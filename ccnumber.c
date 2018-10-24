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
#include <errno.h>

#include <sys/ipc.h>
#include <sys/shm.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <mqueue.h>

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
static int	comparator_queue = -1;
static int	comparator_pid = -1;

#define		SHMEM_KEY		23110
#define		MAX_QUEUES		32
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

/* where to find the comparator */
static bool ccnumber_comparator_optimize = true;

static ExecutorEnd_hook_type prev_ExecutorEnd = NULL;
static ExecutorFinish_hook_type prev_ExecutorFinish = NULL;
static ExecutorRun_hook_type prev_ExecutorRun = NULL;

static void ccnumber_ExecutorEnd(QueryDesc *queryDesc);
static void ccnumber_ExecutorFinish(QueryDesc *queryDesc);
static void ccnumber_ExecutorRun(QueryDesc *queryDesc,
									   ScanDirection direction,
									   uint64 count,
									   bool execute_once);

static void
attach_queues(void)
{
	int		i;
	int		shmem_id;
	key_t	shmem_key = SHMEM_KEY;

	if (queues)
		return;

	shmem_id = shmget(shmem_key, sizeof(queues_t), 0666);
	if (shmem_id < 0)
	{
		elog(ERROR, "failed to get shmem segment");
		return;
	}

	queues = shmat(shmem_id, NULL, 0);
	if (queues == (void *) -1)
	{
		elog(ERROR, "failed to attach shmem segment");
		return;
	}

	for (i = 0; i < MAX_QUEUES; i++)
	{
		elog(WARNING, "opening queue '%s' / '%s'\n", queues->names_in[i].name, queues->names_out[i].name);

		queue_descriptors_in[i] = mq_open(queues->names_out[i].name, O_RDWR, 0666, NULL);
		if (queue_descriptors_in[i] == (mqd_t) -1)
			elog(ERROR, "failed to open queue");

		queue_descriptors_out[i] = mq_open(queues->names_in[i].name, O_RDWR, 0666, NULL);
		if (queue_descriptors_out[i] == (mqd_t) -1)
			elog(ERROR, "failed to open queue");

		elog(WARNING, "opening queue '%s' / '%s' => %d / %d\n", queues->names_in[i].name, queues->names_out[i].name, queue_descriptors_in[i], queue_descriptors_out[i]);
	}

}

static void
acquire_queue(void)
{
	int			i;

	attach_queues();

	if ((comparator_queue != -1) && (comparator_pid == getpid()))
		return;

	comparator_pid = getpid();

	SpinLockAcquire(&queues->lock);

	for (i = 0; i < MAX_QUEUES; i++)
	{
		if (!queues->used[i])
		{
			queues->used[i] = true;
			comparator_queue = i;
			break;
		}
	}

	SpinLockRelease(&queues->lock);

	if (comparator_queue == -1)
		elog(ERROR, "failed to acquire comparator queue");
}

static void
release_queue(void)
{
	attach_queues();

	if ((comparator_queue == -1) || (comparator_pid != getpid()))
		return;

	SpinLockAcquire(&queues->lock);
	queues->used[comparator_queue] = false;
	SpinLockRelease(&queues->lock);

	elog(WARNING, "%d : released queue %d", getpid(), comparator_queue);

	comparator_queue = -1;
}

/*
 * Module load callback
 */
void
_PG_init(void)
{
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

	prev_ExecutorFinish = ExecutorFinish_hook;
	ExecutorFinish_hook = ccnumber_ExecutorFinish;

	prev_ExecutorRun = ExecutorRun_hook;
	ExecutorRun_hook = ccnumber_ExecutorRun;
}

/*
 * Module unload callback
 */
void
_PG_fini(void)
{
	/* Uninstall hooks. */
	ExecutorEnd_hook = prev_ExecutorEnd;
	ExecutorFinish_hook = prev_ExecutorFinish;
	ExecutorRun_hook = prev_ExecutorRun;
}

/*
 * ExecutorEnd hook: close the comparator connection (if opened)
 */
static void
ccnumber_ExecutorEnd(QueryDesc *queryDesc)
{
	release_queue();

	if (prev_ExecutorEnd)
		prev_ExecutorEnd(queryDesc);
	else
		standard_ExecutorEnd(queryDesc);
}

/*
 * ExecutorEnd hook: close the comparator connection (if opened)
 */
static void
ccnumber_ExecutorFinish(QueryDesc *queryDesc)
{
	release_queue();

	if (prev_ExecutorFinish)
		prev_ExecutorFinish(queryDesc);
	else
		standard_ExecutorFinish(queryDesc);
}

static void
ccnumber_ExecutorRun(QueryDesc *queryDesc,
					 ScanDirection direction,
					 uint64 count,
					 bool execute_once)
{
	release_queue();

	if (prev_ExecutorRun)
		prev_ExecutorRun(queryDesc, direction, count, execute_once);
	else
		standard_ExecutorRun(queryDesc, direction, count, execute_once);
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
	char		buffer[2048];
	char	   *ptr;
	int			lena, lenb;
	mqd_t		mqd_in;
	mqd_t		mqd_out;
	int			nbytes;

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
	acquire_queue();

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

	mqd_in = queue_descriptors_in[comparator_queue];
	mqd_out = queue_descriptors_out[comparator_queue];

	/* send message through the queue */
	if (mq_send(mqd_out, buffer, len, 0) != 0)
		elog(ERROR, "comparator queue failure");

	/* receive response (single character) */
	nbytes = mq_receive(mqd_in, buffer, 2048, NULL);
	if (nbytes != 1)
		elog(ERROR, "mq_receive failed (mqd %d, bytes %d)", mqd_in, nbytes);

	memcpy(&response, buffer, 1);

	if ((response >= -1) && (response <= 1))
		return (int)response;

	elog(WARNING, "%d : queue %d (%d / %d) response = %d (len = %d)", getpid(), comparator_queue, mqd_in, mqd_out, response, nbytes);

	release_queue();
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
