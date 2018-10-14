/*
 * ccnumber
 *
 * A data type representing encrypted credit card number, with operations
 * off-loaded to a separate trusted component, allowing the database to
 * work without knowing the encryption key.
 *
 * Credit card numbers are merely an example - the same principle can be
 * used for various other data types.
 *
 * This is a PoC implementation only - it works, but it's not production
 * ready and/or tested very much.  Only basic comparison operations are
 * supported, which allows building and using encrypted indexes.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "postgres.h"

#include "catalog/pg_collation.h"
#include "commands/explain.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/formatting.h"
#include "utils/varlena.h"

PG_MODULE_MAGIC;

void		_PG_init(void);
void		_PG_fini(void);

/*
 * TCP socket (we also check PID, because we don't want child to use the
 * socket opened by parent process).
 */
static int	comparator_socket = -1;
static int	comparator_pid = -1;

/* where to find the comparator */
static int ccnumber_comparator_port = 9999;
static char *ccnumber_comparator_host = "127.0.0.1";
static bool ccnumber_comparator_optimize = true;

static ExecutorEnd_hook_type prev_ExecutorEnd = NULL;
static void ccnumber_ExecutorEnd(QueryDesc *queryDesc);

/*
 * Make sure we're connected to the comparator. Simply open a TCP socket
 * (unless we already have one for this process).
 */
static void
connect_to_comparator(void)
{
	struct sockaddr_in serv_addr;
	int		flag = 1;

	if ((comparator_socket > 0) && comparator_pid == getpid())
		return;

	comparator_pid = getpid();
	comparator_socket = socket(AF_INET, SOCK_STREAM, 0);

	if (comparator_socket < 0)
		goto error;

	/* XXX: send the data right away, don't wait - important for low latency */
	if (setsockopt(comparator_socket, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int)) < 0)
		goto error;

	memset(&serv_addr, '0', sizeof(serv_addr));
   
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(ccnumber_comparator_port);

	if (inet_pton(AF_INET, ccnumber_comparator_host, &serv_addr.sin_addr) <= 0)
		goto error;

	if (connect(comparator_socket, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
		goto error;

	return;

error:
	comparator_socket = -1;
	elog(ERROR, "connection to comparator failed (socket creation)");
}

/*
 * Module load callback
 */
void
_PG_init(void)
{
	DefineCustomIntVariable("ccnumber.comparator_port",
							"sets the comparator port to connect to",
							NULL,
							&ccnumber_comparator_port,
							9999,
							1, INT_MAX,
							PGC_SUSET,
							0,
							NULL,
							NULL,
							NULL);

	DefineCustomStringVariable("ccnumber.comparator_host",
							   "sets the comparator host to connect to",
							   NULL,
							   &ccnumber_comparator_host,
							   "127.0.0.1",
							   PGC_SUSET,
							   0,
							   NULL,
							   NULL,
							   NULL);

	DefineCustomBoolVariable("ccnumber.optimize_remote_calls",
							 "eliminate remote calls where possible",
							 NULL,
							 &ccnumber_comparator_optimize,
							 true,
							 PGC_SUSET,
							 0,
							 NULL,
							 NULL,
							 NULL);

	prev_ExecutorEnd = ExecutorEnd_hook;
	ExecutorEnd_hook = ccnumber_ExecutorEnd;
}

/*
 * Module unload callback
 */
void
_PG_fini(void)
{
	/* Uninstall hooks. */
	ExecutorEnd_hook = prev_ExecutorEnd;
}

/*
 * ExecutorEnd hook: close the comparator connection (if opened)
 */
static void
ccnumber_ExecutorEnd(QueryDesc *queryDesc)
{
	if (comparator_socket != -1)
	{
		close(comparator_socket);
		comparator_socket = -1;
	}

	if (prev_ExecutorEnd)
		prev_ExecutorEnd(queryDesc);
	else
		standard_ExecutorEnd(queryDesc);
}


/*
 * ccnumber_cmp()
 * Internal comparison function for encrypted CC numbers.
 * Returns int32 negative, zero, or positive.
 */
static int32
ccnumbercmp(bytea *left, bytea *right)
{
	int			len;
	char		response;
	char		buffer[1024];
	char	   *ptr;
	int			lena, lenb;

	if (ccnumber_comparator_optimize)
	{
		char	   *lstr, *rstr;
		int			lhash, rhash;

		lstr = VARDATA_ANY(left);
		rstr = VARDATA_ANY(right);

		memcpy(&lhash, lstr, sizeof(int));
		memcpy(&rhash, rstr, sizeof(int));

		if (lhash < rhash)
			return -1;
		else if (lhash > rhash)
			return 1;
	}

	/* ensure connection to comparator */
	connect_to_comparator();

	len = VARSIZE_ANY_EXHDR(left) + VARSIZE_ANY_EXHDR(right) + 2 * sizeof(int) - 8;

	ptr = buffer;

	memcpy(ptr, &len, sizeof(int));
	ptr += sizeof(int);

	lena = VARSIZE_ANY_EXHDR(left) - 4;
	memcpy(ptr, &lena, sizeof(int));
	ptr += sizeof(int);

	memcpy(ptr, VARDATA_ANY(left) + 4, lena);
	ptr += lena;

	lenb = VARSIZE_ANY_EXHDR(right) - 4;
	memcpy(ptr, &lenb, sizeof(int));
	ptr += sizeof(int);

	memcpy(ptr, VARDATA_ANY(right) + 4, lenb);
	ptr += lenb;

	len += sizeof(int);

	/* send message */
	if (send(comparator_socket, buffer, len, 0) != len)
		goto error;

	/* receive response (single character) */
	if ((len = recv(comparator_socket, &response, 1, MSG_WAITALL)) < 0)
		goto error;

	if ((response >= -1) && (response <= 1))
		return (int)response;

error:
	close(comparator_socket);
	comparator_socket = -1;
	elog(ERROR, "comparator failure");
}

/*
 *		==================
 *		INDEXING FUNCTIONS
 *		==================
 */

PG_FUNCTION_INFO_V1(ccnumber_cmp);

Datum
ccnumber_cmp(PG_FUNCTION_ARGS)
{
	bytea	   *left = PG_GETARG_BYTEA_PP(0);
	bytea	   *right = PG_GETARG_BYTEA_PP(1);
	int32		result;

	result = ccnumbercmp(left, right);

	PG_FREE_IF_COPY(left, 0);
	PG_FREE_IF_COPY(right, 1);

	PG_RETURN_INT32(result);
}

/*
 *		==================
 *		OPERATOR FUNCTIONS
 *		==================
 */

PG_FUNCTION_INFO_V1(ccnumber_eq);

Datum
ccnumber_eq(PG_FUNCTION_ARGS)
{
	bytea	   *left = PG_GETARG_BYTEA_PP(0);
	bytea	   *right = PG_GETARG_BYTEA_PP(1);
	bool		result;

	result = ccnumbercmp(left, right) == 0;

	PG_FREE_IF_COPY(left, 0);
	PG_FREE_IF_COPY(right, 1);

	PG_RETURN_BOOL(result);
}

PG_FUNCTION_INFO_V1(ccnumber_ne);

Datum
ccnumber_ne(PG_FUNCTION_ARGS)
{
	bytea	   *left = PG_GETARG_BYTEA_PP(0);
	bytea	   *right = PG_GETARG_BYTEA_PP(1);
	bool		result;

	result = ccnumbercmp(left, right) != 0;

	PG_FREE_IF_COPY(left, 0);
	PG_FREE_IF_COPY(right, 1);

	PG_RETURN_BOOL(result);
}

PG_FUNCTION_INFO_V1(ccnumber_lt);

Datum
ccnumber_lt(PG_FUNCTION_ARGS)
{
	bytea	   *left = PG_GETARG_BYTEA_PP(0);
	bytea	   *right = PG_GETARG_BYTEA_PP(1);
	bool		result;

	result = ccnumbercmp(left, right) < 0;

	PG_FREE_IF_COPY(left, 0);
	PG_FREE_IF_COPY(right, 1);

	PG_RETURN_BOOL(result);
}

PG_FUNCTION_INFO_V1(ccnumber_le);

Datum
ccnumber_le(PG_FUNCTION_ARGS)
{
	bytea	   *left = PG_GETARG_BYTEA_PP(0);
	bytea	   *right = PG_GETARG_BYTEA_PP(1);
	bool		result;

	result = ccnumbercmp(left, right) <= 0;

	PG_FREE_IF_COPY(left, 0);
	PG_FREE_IF_COPY(right, 1);

	PG_RETURN_BOOL(result);
}

PG_FUNCTION_INFO_V1(ccnumber_gt);

Datum
ccnumber_gt(PG_FUNCTION_ARGS)
{
	bytea	   *left = PG_GETARG_BYTEA_PP(0);
	bytea	   *right = PG_GETARG_BYTEA_PP(1);
	bool		result;

	result = ccnumbercmp(left, right) > 0;

	PG_FREE_IF_COPY(left, 0);
	PG_FREE_IF_COPY(right, 1);

	PG_RETURN_BOOL(result);
}

PG_FUNCTION_INFO_V1(ccnumber_ge);

Datum
ccnumber_ge(PG_FUNCTION_ARGS)
{
	bytea	   *left = PG_GETARG_BYTEA_PP(0);
	bytea	   *right = PG_GETARG_BYTEA_PP(1);
	bool		result;

	result = ccnumbercmp(left, right) >= 0;

	PG_FREE_IF_COPY(left, 0);
	PG_FREE_IF_COPY(right, 1);

	PG_RETURN_BOOL(result);
}


PG_FUNCTION_INFO_V1(ccnumber_hash);

Datum
ccnumber_hash(PG_FUNCTION_ARGS)
{
	bytea	   *val = PG_GETARG_BYTEA_PP(0);
	int			result;

	memcpy(&result, VARDATA_ANY(val), sizeof(int));

	/* Avoid leaking memory for toasted inputs */
	PG_FREE_IF_COPY(val, 0);

	PG_RETURN_DATUM(Int32GetDatum(result));
}


/*
 *		===================
 *		AGGREGATE FUNCTIONS
 *		===================
 */

PG_FUNCTION_INFO_V1(ccnumber_smaller);

Datum
ccnumber_smaller(PG_FUNCTION_ARGS)
{
	bytea	   *left = PG_GETARG_BYTEA_PP(0);
	bytea	   *right = PG_GETARG_BYTEA_PP(1);
	bytea	   *result;

	result = ccnumbercmp(left, right) < 0 ? left : right;

	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(ccnumber_larger);

Datum
ccnumber_larger(PG_FUNCTION_ARGS)
{
	bytea	   *left = PG_GETARG_BYTEA_PP(0);
	bytea	   *right = PG_GETARG_BYTEA_PP(1);
	bytea	   *result;

	result = ccnumbercmp(left, right) > 0 ? left : right;

	PG_RETURN_BYTEA_P(result);
}
