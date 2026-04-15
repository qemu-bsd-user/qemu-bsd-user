/*
 * Glue code needed to use a lightly-edited truss + sysdecode library
 */

#ifndef TRUSS_HDR_H
#define TRUSS_HDR_H 1

void record_syscall(TaskState *ts, const os_syscall_args_t *sa);
void record_syscall_ret(TaskState *ts, int num, abi_ulong ret, abi_ulong ret2);

/*
 * System call arguments come in several flavors. These
 * try to enumerate them all.
 */

enum Argtype {
	None = 1,

	Int,
	Ptr,
	Sizet,
	Octal,
	Rusage,
	UInt,
	Msghdr,
	Sockaddr,
	LongHex,
	Itimerval,
	Long,
	Ulong,
	Timeval,
	Stat11,
	Rlimit,
	Pollfd,
	Timespec,
	Sigevent,
	QuadHex,
	Aiocb,
	Siginfo,
	Acltype,
	Kevent11,
	Sigaction,
	Sctpsndrcvinfo,
	Stat,
	StatFs,
	Kevent,
	MAX_ARG_TYPE,
};

#define ARG_MASK	0xff
#define	OUT		0x100
#define	IN		0x200

_Static_assert(ARG_MASK > MAX_ARG_TYPE,
    "ARG_MASK overlaps with Argtype values");

struct syscall_arg {
	enum Argtype type;
	int offset;
};

struct syscall_decode {
	const char *name; /* Name for calling convention lookup. */
	/*
	 * Syscall return type:
	 * 0: no return value (e.g. exit)
	 * 1: normal return value (a single int/long/pointer)
	 * 2: off_t return value (two values for 32-bit ABIs)
	 */
	u_int ret_type;
	u_int nargs;		     /* number of meaningful arguments */
	struct syscall_arg args[10]; /* Hopefully no syscalls with > 10 args */
};

extern const struct syscall_decode decoded_syscalls[];

#endif /* TRUSS_HDR_H */
