/*
 * ccnumber-comparator
 *
 * A trusted component (knows the encryption key), and so can perform
 * operations on encrypted data. Relies on libsodium for encryption.
 *
 * Multi-threaded - creates a thread for each connection.
 */
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>

#include <sodium.h>

/* shouldn't really be hard-coded, but good enough for PoC */
#define SECRET_KEY	"3f91942d47091eac32203d75188125fba55231ca78dc133f8dff6504bef51e2c"

/* decoded secret key (binary, 32B, i.e. 256 bits) */
static unsigned char key[crypto_secretbox_KEYBYTES];

/* reporting of ops/s every second, multiple threads */
pthread_spinlock_t	report_lock;
static double report_time = 0;
static int    report_comparisons = 0;

/* decode hex-encoded string (used for key only) */
static int
hex2bin(const char *str, unsigned char *out)
{
	int bytes;
	int len = strlen(str);
	const char* pos;

	if (len % 2 != 0)
	{
		fprintf(stderr, "incorrect hex length: %d\n", len);
		exit(1);
	}

	pos = str;

	for (bytes = 0; bytes < (len/2); bytes++)
	{
		sscanf(pos, "%2hhx", &out[bytes]);
		pos += 2;
	}

	return bytes;
}

/* handle a client connection, executed by a separate thread */
static void *
handle_connection(void *data)
{
	int				clientfd = *(int *)data;	/* we pass the file descriptor */
	unsigned char	buffer[1024];
	int				ncomparisons = 0;

	while (1)
	{
		int		tmp;
		int		len,		/* total length */
				alen,		/* first value */
				blen;		/* second value */
		int		ret;
		char	retc;

		unsigned char	a_decrypted[128],
						b_decrypted[128];

		/* pointers to individual pieces of the data */
		unsigned char  *a_nonce,
					   *a_ciphertext,
					   *b_nonce,
					   *b_ciphertext,
					   *ptr;

		/* the first bit is the message length */
		tmp = recv(clientfd, &len, 4, MSG_WAITALL);

		/*
		 * This is expected when the client simply closes the connection,
		 * so no error message here.
		 */
		if (tmp == 0)
			break;
		else if (tmp < 4)
		{
			/* incomplete length or message means broken connection */
			perror("incomplete message length (expected 4), closing connection");
			break;
		}

		if (recv(clientfd, buffer, len, MSG_WAITALL) < len)
		{
			perror("incomplete message, closing connection");
			break;
		}

		ptr = buffer;

		/* extract first value from buffer */
		memcpy(&alen, ptr, sizeof(int));
		ptr += sizeof(int);

		a_ciphertext = ptr;
		ptr += alen;

		a_nonce = a_ciphertext;
		a_ciphertext = a_ciphertext + crypto_secretbox_NONCEBYTES;

		/* extract second value from buffer */
		memcpy(&blen, ptr, sizeof(int));
		ptr += sizeof(int);

		b_ciphertext = ptr;
		ptr += blen;

		b_nonce = b_ciphertext;
		b_ciphertext = b_ciphertext + crypto_secretbox_NONCEBYTES;

		alen = alen - crypto_secretbox_NONCEBYTES;
		blen = blen - crypto_secretbox_NONCEBYTES;

		if (crypto_secretbox_open_easy(a_decrypted, a_ciphertext, alen, a_nonce, key) != 0)
		{
			/* something went wrong (corrupted data?), give up and close connection */
			perror("failed to decrypt data, closing connection");
			break;
		}

		if (crypto_secretbox_open_easy(b_decrypted, b_ciphertext, blen, b_nonce, key) != 0)
		{
			/* something went wrong (corrupted data?), give up and close connection */
			perror("failed to decrypt data, closing connection");
			break;
		}

		alen -= crypto_secretbox_MACBYTES;
		blen -= crypto_secretbox_MACBYTES;

		a_decrypted[alen] = '\0';
		b_decrypted[blen] = '\0';

		ret = memcmp(a_decrypted, b_decrypted, ((alen < blen) ? alen : blen));

		if (ret < 0)
			retc = -1;
		else if (ret > 0)
			retc = 1;
		else if (alen == blen)
			retc = 0;
		else if (alen < blen)
			retc = -1;
		else
			retc = 1;

		if (send(clientfd, &retc, 1, 0) < 1)
		{
			perror("failed to send response to client");
			break;
		}

		ncomparisons++;

		/*
		 * Update the global counter, but do that only once in a while (every
		 * 1000 operations) to limit overhead and spinlock contention.
		 */
		if (ncomparisons % 1000 == 0)
		{
			pthread_spin_lock(&report_lock);

			report_comparisons += ncomparisons;
			ncomparisons = 0;

			/*
			 * And then every now and then, see if we need to print data about
			 * progress.  We only want to do that every second or so, to give
			 * nice "per second" values.  But we don't want to do gettimeofday
			 * very often, so we do it every time we add total 10000 ops.
			 */
			if (report_comparisons % 10000 == 0)
			{
				struct	timeval tv;
				double	time;

				if (gettimeofday(&tv, NULL) != 0)
					perror("gettimeofday failed");

				time = ((double)tv.tv_sec + (double) tv.tv_usec / 1000000.0);

				/* Is the last report older than 1 second? */
				if (time >= report_time + 1.0)
				{
					double time_delta = time - report_time;

					printf("%f %d %f %f\n", time, report_comparisons, time_delta,
						   (report_comparisons / time_delta));

					report_time = time;
					report_comparisons = 0;
				}
			}

			pthread_spin_unlock(&report_lock);
		}

	}

	close(clientfd);
	free(data);

	return NULL;
}


int main(int argc, char **argv)
{
	int					fd;
	struct sockaddr_in	serv_addr;
	int					flag = 1;
	int					port = atoi(argv[1]);

	pthread_spin_init(&report_lock, PTHREAD_PROCESS_PRIVATE);

	/* decode the encryption key */
	hex2bin(SECRET_KEY, key);

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
	{
		perror("failed to open a socket");
		exit(2);
	}

	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int)) < 0)
		perror("setsockopt failed");

	memset(&serv_addr, '0', sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(port);

	if (bind(fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
	{
		perror("failed to bind a socket to port");
		exit(3);
	}

	if (listen(fd, 10) < 0)
	{
		perror("failed to listen on a socket");
		exit(4);
	}

	while(1)
	{
		int clientfd = accept(fd, (struct sockaddr*)NULL, NULL);
		pthread_t thread;

		int *data = (int *) malloc(sizeof(int));
		*data = clientfd;

		printf("opened socket %d\n", clientfd);

		if (clientfd < 0)
		{
			perror("failed to accept a connection on a socket");
			continue;
		}

		/* start thread handling connection */
		if (pthread_create(&thread, NULL, handle_connection, data) != 0)
		{
			perror("failed to create connection thread");
			continue;
		}
	}

	close(fd);
}
