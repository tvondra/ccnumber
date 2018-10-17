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
#include <errno.h>

#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <mqueue.h>

#include <sodium.h>

#include "slock.h"

#define		SHMEM_KEY		23110
#define		MAX_QUEUES		32
// #define		QUEUE_SIZE		1024
#define		QUEUE_NAME_LEN	64

typedef struct qname_t
{
	char	name[QUEUE_NAME_LEN];
} qname_t;

typedef struct queues_t
{
	slock_t	lock;					/* spinlock (when acquiring queue) */
	char	used[MAX_QUEUES];		/* number of concurrent queues */
	qname_t	names_in[MAX_QUEUES];	/* input queues (requests) */
	qname_t	names_out[MAX_QUEUES];	/* output queues (responsed) */
} queues_t;

static queues_t *queues = NULL;

static mqd_t queue_descriptors_in[MAX_QUEUES];
static mqd_t queue_descriptors_out[MAX_QUEUES];

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
	int				qid = *(int *)data;
	mqd_t			mqd_in = queue_descriptors_in[qid];
	mqd_t			mqd_out = queue_descriptors_out[qid];
	int				ncomparisons = 0;

	while (1)
	{
		int		len,		/* total length */
				alen,		/* first value */
				blen;		/* second value */
		int		ret;
		char	retc;
		char	buffer[2048];
		int		nbytes;

		unsigned char	a_decrypted[128],
						b_decrypted[128];

		/* pointers to individual pieces of the data */
		unsigned char  *a_nonce,
					   *a_ciphertext,
					   *b_nonce,
					   *b_ciphertext,
					   *ptr;

		/* wait until we get request on on queue */
		nbytes = mq_receive(mqd_in, buffer, 2048, NULL);
		if (nbytes < 0)
		{
			perror("mq_receive failed");
			goto error;
		}

		/* the first bit is the message length */
		memcpy(&len, buffer, sizeof(int));

		/* cross-check message length with queue length */
		if (len + sizeof(int) != nbytes)
		{
			/* incomplete length or message means broken connection */
			fprintf(stderr, "incomplete message length: header=%d queue=%d\n", len, nbytes);
			goto error;
		}

		/* message starts after the length */
		ptr = (unsigned char *) buffer + sizeof(int);

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
			fprintf(stderr, "failed to decrypt data, closing connection\n");
			goto error;
		}

		if (crypto_secretbox_open_easy(b_decrypted, b_ciphertext, blen, b_nonce, key) != 0)
		{
			/* something went wrong (corrupted data?), give up and close connection */
			fprintf(stderr, "failed to decrypt data, closing connection\n");
			goto error;
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

		if (mq_send(mqd_out, &retc, sizeof(retc), 0) != 0)
		{
			fprintf(stderr, "failed to send response\n");
			goto error;
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

		continue;

error:
		/* send response meaning "invalid" */
		retc = 2;
		if (mq_send(mqd_out, &retc, sizeof(retc), 0) != 0)
			fprintf(stderr, "mq_send failed (again)");
	}

	free(data);

	return NULL;
}

static queues_t *
create_queues(void)
{
	int		i;
	int		shmem_id;
	key_t	shmem_key = SHMEM_KEY;

	shmem_id = shmget(shmem_key, sizeof(queues_t), IPC_CREAT | 0666);

	if (shmem_id < 0)
	{
		perror("failed to create shmem segment");
		exit(1);
	}

	queues = shmat(shmem_id, NULL, 0);

	if (queues == (void *) -1)
	{
		perror("failed to attach shmem segment");
		exit(2);
	}

	SpinLockInit(&queues->lock);
	memset(queues->used, 0, sizeof(char) * MAX_QUEUES);

	for (i = 0; i < MAX_QUEUES; i++)
	{
		struct mq_attr	attr;

		attr.mq_flags = 0;
		attr.mq_maxmsg = 10;
		attr.mq_msgsize = 1024;
		attr.mq_curmsgs = 0;

		sprintf(queues->names_in[i].name, "/ccnumber_queue_in_%d", i);
		sprintf(queues->names_out[i].name, "/ccnumber_queue_out_%d", i);

		mq_unlink(queues->names_in[i].name);
		queue_descriptors_in[i] = mq_open(queues->names_in[i].name, O_RDWR | O_CREAT, 0666, &attr);

		if (queue_descriptors_in[i] == (mqd_t) -1)
		{
			perror("failed to create queue");
			exit(3);
		}

		fprintf(stderr, "creating input queue '%s' => %d\n", queues->names_in[i].name, queue_descriptors_in[i]);

		mq_unlink(queues->names_out[i].name);
		queue_descriptors_out[i] = mq_open(queues->names_out[i].name, O_RDWR | O_CREAT, 0666, &attr);

		if (queue_descriptors_out[i] == (mqd_t) -1)
		{
			perror("failed to create queue");
			exit(3);
		}

		fprintf(stderr, "creating output queue '%s' => %d\n", queues->names_out[i].name, queue_descriptors_out[i]);
	}

	return queues;
}

int main(int argc, char **argv)
{
	int					i;
	pthread_t			threads[MAX_QUEUES];

	queues = create_queues();

	pthread_spin_init(&report_lock, PTHREAD_PROCESS_PRIVATE);

	/* decode the encryption key */
	hex2bin(SECRET_KEY, key);

	for (i = 0; i < MAX_QUEUES; i++)
	{
		int *id = (int *) malloc(sizeof(int));
		*id = i;

		printf("starting thread for queues '%s' / '%s' (%d)\n", queues->names_in[i].name, queues->names_out[i].name, i);

		/* start a separate thread for each queue */
		if (pthread_create(&threads[i], NULL, handle_connection, id) != 0)
		{
			perror("failed to create connection thread");
			continue;
		}
	}
	printf("threads started\n");

	for (i = 0; i < MAX_QUEUES; i++)
	{
		pthread_join(threads[i], NULL);
	}

}
