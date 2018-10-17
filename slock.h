typedef unsigned char slock_t;

#define TAS(lock) tas(lock)
#define TAS_SPIN(lock)    (*(lock) ? 1 : TAS(lock))

static __inline__ int
tas(volatile slock_t *lock)
{
	register slock_t _res = 1;

	__asm__ __volatile__(
		"	lock			\n"
		"	xchgb	%0,%1	\n"
:		"+q"(_res), "+m"(*lock)
:		/* no inputs */
:		"memory", "cc");
	return (int) _res;
}

#define SPIN_DELAY() spin_delay()

static __inline__ void
spin_delay(void)
{
	/*
	 * Adding a PAUSE in the spin delay loop is demonstrably a no-op on
	 * Opteron, but it may be of some use on EM64T, so we keep it.
	 */
	__asm__ __volatile__(
		" rep; nop			\n");
}


#define S_LOCK(lock) \
	(TAS(lock) ? s_lock((lock), __FILE__, __LINE__, PG_FUNCNAME_MACRO) : 0)

#define S_LOCK_FREE(lock)	(*(lock) == 0)

#define S_UNLOCK(lock)		s_unlock(lock)

#define S_INIT_LOCK(lock)	S_UNLOCK(lock)

#define DEFAULT_SPINS_PER_DELAY  100

extern void set_spins_per_delay(int shared_spins_per_delay);
extern int	update_spins_per_delay(int shared_spins_per_delay);

/*
 * Support for spin delay which is useful in various places where
 * spinlock-like procedures take place.
 */
typedef struct
{
	int			spins;
	int			delays;
	int			cur_delay;
	const char *file;
	int			line;
	const char *func;
} SpinDelayStatus;

static inline void
init_spin_delay(SpinDelayStatus *status,
				const char *file, int line, const char *func)
{
	status->spins = 0;
	status->delays = 0;
	status->cur_delay = 0;
	status->file = file;
	status->line = line;
	status->func = func;
}

#define init_local_spin_delay(status) init_spin_delay(status, __FILE__, __LINE__, PG_FUNCNAME_MACRO)

int s_lock(volatile slock_t *lock, const char *file, int line, const char *func);
void perform_spin_delay(SpinDelayStatus *status);
void perform_spin_delay(SpinDelayStatus *status);
void finish_spin_delay(SpinDelayStatus *status);
void s_unlock(volatile slock_t *lock);
void s_lock_stuck(const char *file, int line, const char *func);

#define MIN_SPINS_PER_DELAY 10
#define MAX_SPINS_PER_DELAY 1000
#define NUM_DELAYS			1000
#define MIN_DELAY_USEC		1000L
#define MAX_DELAY_USEC		1000000L
#define MAX_RANDOM_VALUE	INT32_MAX

#define Min(x, y)			((x) < (y) ? (x) : (y))
#define Max(x, y)			((x) > (y) ? (x) : (y))

static int	spins_per_delay = DEFAULT_SPINS_PER_DELAY;

int
s_lock(volatile slock_t *lock, const char *file, int line, const char *func)
{
	SpinDelayStatus delayStatus;

	init_spin_delay(&delayStatus, file, line, func);

	while (TAS_SPIN(lock))
	{
		perform_spin_delay(&delayStatus);
	}

	finish_spin_delay(&delayStatus);

	return delayStatus.delays;
}

void
s_unlock(volatile slock_t *lock)
{
	*lock = 0;
}

/*
 * Wait while spinning on a contended spinlock.
 */
void
perform_spin_delay(SpinDelayStatus *status)
{
	/* CPU-specific delay each time through the loop */
	SPIN_DELAY();

	/* Block the process every spins_per_delay tries */
	if (++(status->spins) >= spins_per_delay)
	{
		if (++(status->delays) > NUM_DELAYS)
			s_lock_stuck(status->file, status->line, status->func);

		if (status->cur_delay == 0) /* first time to delay? */
			status->cur_delay = MIN_DELAY_USEC;

		usleep(status->cur_delay);

		/* increase delay by a random fraction between 1X and 2X */
		status->cur_delay += (int) (status->cur_delay *
									((double) random() / (double) MAX_RANDOM_VALUE) + 0.5);
		/* wrap back to minimum delay when max is exceeded */
		if (status->cur_delay > MAX_DELAY_USEC)
			status->cur_delay = MIN_DELAY_USEC;

		status->spins = 0;
	}
}

void
finish_spin_delay(SpinDelayStatus *status)
{
	if (status->cur_delay == 0)
	{
		/* we never had to delay */
		if (spins_per_delay < MAX_SPINS_PER_DELAY)
			spins_per_delay = Min(spins_per_delay + 100, MAX_SPINS_PER_DELAY);
	}
	else
	{
		if (spins_per_delay > MIN_SPINS_PER_DELAY)
			spins_per_delay = Max(spins_per_delay - 1, MIN_SPINS_PER_DELAY);
	}
}

void
s_lock_stuck(const char *file, int line, const char *func)
{
	if (!func)
		func = "(unknown)";
	fprintf(stderr,
			"\nStuck spinlock detected at %s, %s:%d.\n",
			func, file, line);
	exit(1);
}

#define SpinLockInit(lock)	S_INIT_LOCK(lock)

#define SpinLockAcquire(lock) S_LOCK(lock)

#define SpinLockRelease(lock) S_UNLOCK(lock)

#define SpinLockFree(lock)	S_LOCK_FREE(lock)
