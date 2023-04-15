/*
 * Table for truss to decode system calls
 *
 * DO NOT EDIT -- this file is automatically @generated.
 */

#ifndef _SYS_SYSTRUSS_H_
#define _SYS_SYSTRUSS_H_
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

static const struct syscall_decode decoded_syscalls[] = {
#ifdef SYS_exit
	[SYS_exit] = { .name = "exit", .ret_type = 0, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* exit 1 */
#endif
#ifdef SYS_fork
	[SYS_fork] = { .name = "fork", .ret_type = 1, .nargs = 0,
	}, /* fork 2 */
#endif
#ifdef SYS_read
	[SYS_read] = { .name = "read", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { OUT | Ptr, 1 },
		  { Sizet, 2 },
		}
	}, /* read 3 */
#endif
#ifdef SYS_write
	[SYS_write] = { .name = "write", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { Sizet, 2 },
		}
	}, /* write 4 */
#endif
#ifdef SYS_open
	[SYS_open] = { .name = "open", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { Int, 1 },
		  { Octal, 2 },
		}
	}, /* open 5 */
#endif
#ifdef SYS_close
	[SYS_close] = { .name = "close", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* close 6 */
#endif
#ifdef SYS_wait4
	[SYS_wait4] = { .name = "wait4", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { OUT | Ptr, 1 },
		  { Int, 2 },
		  { OUT | Rusage, 3 },
		}
	}, /* wait4 7 */
#endif
#ifdef SYS_link
	[SYS_link] = { .name = "link", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { IN | Ptr, 1 },
		}
	}, /* link 9 */
#endif
#ifdef SYS_unlink
	[SYS_unlink] = { .name = "unlink", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* unlink 10 */
#endif
#ifdef SYS_chdir
	[SYS_chdir] = { .name = "chdir", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* chdir 12 */
#endif
#ifdef SYS_fchdir
	[SYS_fchdir] = { .name = "fchdir", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* fchdir 13 */
#endif
#ifdef SYS_freebsd11_mknod
	[SYS_freebsd11_mknod] = { .name = "freebsd11_mknod", .ret_type = 1, .nargs = 3,
		{ 
		{ Ptr, 0 },
		{ Int, 1 },
		{ UInt, 2 },
		}
	}, /* freebsd11_mknod 14 */
#endif
#ifdef SYS_chmod
	[SYS_chmod] = { .name = "chmod", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { Octal, 1 },
		}
	}, /* chmod 15 */
#endif
#ifdef SYS_chown
	[SYS_chown] = { .name = "chown", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { Int, 1 },
		  { Int, 2 },
		}
	}, /* chown 16 */
#endif
#ifdef SYS_break
	[SYS_break] = { .name = "break", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* break 17 */
#endif
#ifdef SYS_getpid
	[SYS_getpid] = { .name = "getpid", .ret_type = 1, .nargs = 0,
	}, /* getpid 20 */
#endif
#ifdef SYS_mount
	[SYS_mount] = { .name = "mount", .ret_type = 1, .nargs = 4,
		{ 
		  { IN | Ptr, 0 },
		  { IN | Ptr, 1 },
		  { Int, 2 },
		  { IN | Ptr, 3 },
		}
	}, /* mount 21 */
#endif
#ifdef SYS_unmount
	[SYS_unmount] = { .name = "unmount", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { Int, 1 },
		}
	}, /* unmount 22 */
#endif
#ifdef SYS_setuid
	[SYS_setuid] = { .name = "setuid", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* setuid 23 */
#endif
#ifdef SYS_getuid
	[SYS_getuid] = { .name = "getuid", .ret_type = 1, .nargs = 0,
	}, /* getuid 24 */
#endif
#ifdef SYS_geteuid
	[SYS_geteuid] = { .name = "geteuid", .ret_type = 1, .nargs = 0,
	}, /* geteuid 25 */
#endif
#ifdef SYS_ptrace
	[SYS_ptrace] = { .name = "ptrace", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { IN | OUT | Ptr, 2 },
		  { Int, 3 },
		}
	}, /* ptrace 26 */
#endif
#ifdef SYS_recvmsg
	[SYS_recvmsg] = { .name = "recvmsg", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { IN | OUT | Msghdr, 1 },
		  { Int, 2 },
		}
	}, /* recvmsg 27 */
#endif
#ifdef SYS_sendmsg
	[SYS_sendmsg] = { .name = "sendmsg", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { IN | Msghdr, 1 },
		  { Int, 2 },
		}
	}, /* sendmsg 28 */
#endif
#ifdef SYS_recvfrom
	[SYS_recvfrom] = { .name = "recvfrom", .ret_type = 1, .nargs = 6,
		{ 
		  { Int, 0 },
		  { OUT | Ptr, 1 },
		  { Sizet, 2 },
		  { Int, 3 },
		  { OUT | Sockaddr, 4 },
		  { IN | OUT | Ptr, 5 },
		}
	}, /* recvfrom 29 */
#endif
#ifdef SYS_accept
	[SYS_accept] = { .name = "accept", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { OUT | Sockaddr, 1 },
		  { IN | OUT | Ptr, 2 },
		}
	}, /* accept 30 */
#endif
#ifdef SYS_getpeername
	[SYS_getpeername] = { .name = "getpeername", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { OUT | Sockaddr, 1 },
		  { IN | OUT | Ptr, 2 },
		}
	}, /* getpeername 31 */
#endif
#ifdef SYS_getsockname
	[SYS_getsockname] = { .name = "getsockname", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { OUT | Sockaddr, 1 },
		  { IN | OUT | Ptr, 2 },
		}
	}, /* getsockname 32 */
#endif
#ifdef SYS_access
	[SYS_access] = { .name = "access", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { Int, 1 },
		}
	}, /* access 33 */
#endif
#ifdef SYS_chflags
	[SYS_chflags] = { .name = "chflags", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { LongHex, 1 },
		}
	}, /* chflags 34 */
#endif
#ifdef SYS_fchflags
	[SYS_fchflags] = { .name = "fchflags", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { LongHex, 1 },
		}
	}, /* fchflags 35 */
#endif
#ifdef SYS_sync
	[SYS_sync] = { .name = "sync", .ret_type = 1, .nargs = 0,
	}, /* sync 36 */
#endif
#ifdef SYS_kill
	[SYS_kill] = { .name = "kill", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		}
	}, /* kill 37 */
#endif
#ifdef SYS_getppid
	[SYS_getppid] = { .name = "getppid", .ret_type = 1, .nargs = 0,
	}, /* getppid 39 */
#endif
#ifdef SYS_dup
	[SYS_dup] = { .name = "dup", .ret_type = 1, .nargs = 1,
		{ 
		  { UInt, 0 },
		}
	}, /* dup 41 */
#endif
#ifdef SYS_freebsd10_pipe
	[SYS_freebsd10_pipe] = { .name = "freebsd10_pipe", .ret_type = 1, .nargs = 0,
	}, /* freebsd10_pipe 42 */
#endif
#ifdef SYS_getegid
	[SYS_getegid] = { .name = "getegid", .ret_type = 1, .nargs = 0,
	}, /* getegid 43 */
#endif
#ifdef SYS_profil
	[SYS_profil] = { .name = "profil", .ret_type = 1, .nargs = 4,
		{ 
		  { OUT | Ptr, 0 },
		  { Sizet, 1 },
		  { Sizet, 2 },
		  { UInt, 3 },
		}
	}, /* profil 44 */
#endif
#ifdef SYS_ktrace
	[SYS_ktrace] = { .name = "ktrace", .ret_type = 1, .nargs = 4,
		{ 
		  { IN | Ptr, 0 },
		  { Int, 1 },
		  { Int, 2 },
		  { Int, 3 },
		}
	}, /* ktrace 45 */
#endif
#ifdef SYS_getgid
	[SYS_getgid] = { .name = "getgid", .ret_type = 1, .nargs = 0,
	}, /* getgid 47 */
#endif
#ifdef SYS_getlogin
	[SYS_getlogin] = { .name = "getlogin", .ret_type = 1, .nargs = 2,
		{ 
		  { OUT | Ptr, 0 },
		  { UInt, 1 },
		}
	}, /* getlogin 49 */
#endif
#ifdef SYS_setlogin
	[SYS_setlogin] = { .name = "setlogin", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* setlogin 50 */
#endif
#ifdef SYS_acct
	[SYS_acct] = { .name = "acct", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* acct 51 */
#endif
#ifdef SYS_sigaltstack
	[SYS_sigaltstack] = { .name = "sigaltstack", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { OUT | Ptr, 1 },
		}
	}, /* sigaltstack 53 */
#endif
#ifdef SYS_ioctl
	[SYS_ioctl] = { .name = "ioctl", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { LongHex, 1 },
		  { IN | OUT | Ptr, 2 },
		}
	}, /* ioctl 54 */
#endif
#ifdef SYS_reboot
	[SYS_reboot] = { .name = "reboot", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* reboot 55 */
#endif
#ifdef SYS_revoke
	[SYS_revoke] = { .name = "revoke", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* revoke 56 */
#endif
#ifdef SYS_symlink
	[SYS_symlink] = { .name = "symlink", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { IN | Ptr, 1 },
		}
	}, /* symlink 57 */
#endif
#ifdef SYS_readlink
	[SYS_readlink] = { .name = "readlink", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { OUT | Ptr, 1 },
		  { Sizet, 2 },
		}
	}, /* readlink 58 */
#endif
#ifdef SYS_execve
	[SYS_execve] = { .name = "execve", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { IN | Ptr, 1 },
		  { IN | Ptr, 2 },
		}
	}, /* execve 59 */
#endif
#ifdef SYS_umask
	[SYS_umask] = { .name = "umask", .ret_type = 1, .nargs = 1,
		{ 
		  { Octal, 0 },
		}
	}, /* umask 60 */
#endif
#ifdef SYS_chroot
	[SYS_chroot] = { .name = "chroot", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* chroot 61 */
#endif
#ifdef SYS_msync
	[SYS_msync] = { .name = "msync", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { Sizet, 1 },
		  { Int, 2 },
		}
	}, /* msync 65 */
#endif
#ifdef SYS_vfork
	[SYS_vfork] = { .name = "vfork", .ret_type = 1, .nargs = 0,
	}, /* vfork 66 */
#endif
#ifdef SYS_sbrk
	[SYS_sbrk] = { .name = "sbrk", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* sbrk 69 */
#endif
#ifdef SYS_sstk
	[SYS_sstk] = { .name = "sstk", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* sstk 70 */
#endif
#ifdef SYS_freebsd11_vadvise
	[SYS_freebsd11_vadvise] = { .name = "freebsd11_vadvise", .ret_type = 1, .nargs = 1,
		{ 
		{ Int, 0 },
		}
	}, /* freebsd11_vadvise 72 */
#endif
#ifdef SYS_munmap
	[SYS_munmap] = { .name = "munmap", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { Sizet, 1 },
		}
	}, /* munmap 73 */
#endif
#ifdef SYS_mprotect
	[SYS_mprotect] = { .name = "mprotect", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { Sizet, 1 },
		  { Int, 2 },
		}
	}, /* mprotect 74 */
#endif
#ifdef SYS_madvise
	[SYS_madvise] = { .name = "madvise", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { Sizet, 1 },
		  { Int, 2 },
		}
	}, /* madvise 75 */
#endif
#ifdef SYS_mincore
	[SYS_mincore] = { .name = "mincore", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { Sizet, 1 },
		  { OUT | Ptr, 2 },
		}
	}, /* mincore 78 */
#endif
#ifdef SYS_getgroups
	[SYS_getgroups] = { .name = "getgroups", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { OUT | Ptr, 1 },
		}
	}, /* getgroups 79 */
#endif
#ifdef SYS_setgroups
	[SYS_setgroups] = { .name = "setgroups", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		}
	}, /* setgroups 80 */
#endif
#ifdef SYS_getpgrp
	[SYS_getpgrp] = { .name = "getpgrp", .ret_type = 1, .nargs = 0,
	}, /* getpgrp 81 */
#endif
#ifdef SYS_setpgid
	[SYS_setpgid] = { .name = "setpgid", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		}
	}, /* setpgid 82 */
#endif
#ifdef SYS_setitimer
	[SYS_setitimer] = { .name = "setitimer", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { IN | Itimerval, 1 },
		  { OUT | Itimerval, 2 },
		}
	}, /* setitimer 83 */
#endif
#ifdef SYS_swapon
	[SYS_swapon] = { .name = "swapon", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* swapon 85 */
#endif
#ifdef SYS_getitimer
	[SYS_getitimer] = { .name = "getitimer", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { OUT | Itimerval, 1 },
		}
	}, /* getitimer 86 */
#endif
#ifdef SYS_getdtablesize
	[SYS_getdtablesize] = { .name = "getdtablesize", .ret_type = 1, .nargs = 0,
	}, /* getdtablesize 89 */
#endif
#ifdef SYS_dup2
	[SYS_dup2] = { .name = "dup2", .ret_type = 1, .nargs = 2,
		{ 
		  { UInt, 0 },
		  { UInt, 1 },
		}
	}, /* dup2 90 */
#endif
#ifdef SYS_fcntl
	[SYS_fcntl] = { .name = "fcntl", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { Long, 2 },
		}
	}, /* fcntl 92 */
#endif
#ifdef SYS_select
	[SYS_select] = { .name = "select", .ret_type = 1, .nargs = 5,
		{ 
		  { Int, 0 },
		  { IN | OUT | Ptr, 1 },
		  { IN | OUT | Ptr, 2 },
		  { IN | OUT | Ptr, 3 },
		  { IN | Timeval, 4 },
		}
	}, /* select 93 */
#endif
#ifdef SYS_fsync
	[SYS_fsync] = { .name = "fsync", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* fsync 95 */
#endif
#ifdef SYS_setpriority
	[SYS_setpriority] = { .name = "setpriority", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { Int, 2 },
		}
	}, /* setpriority 96 */
#endif
#ifdef SYS_socket
	[SYS_socket] = { .name = "socket", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { Int, 2 },
		}
	}, /* socket 97 */
#endif
#ifdef SYS_connect
	[SYS_connect] = { .name = "connect", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { IN | Sockaddr, 1 },
		  { UInt, 2 },
		}
	}, /* connect 98 */
#endif
#ifdef SYS_getpriority
	[SYS_getpriority] = { .name = "getpriority", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		}
	}, /* getpriority 100 */
#endif
#ifdef SYS_bind
	[SYS_bind] = { .name = "bind", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { IN | Sockaddr, 1 },
		  { UInt, 2 },
		}
	}, /* bind 104 */
#endif
#ifdef SYS_setsockopt
	[SYS_setsockopt] = { .name = "setsockopt", .ret_type = 1, .nargs = 5,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { Int, 2 },
		  { IN | Ptr, 3 },
		  { UInt, 4 },
		}
	}, /* setsockopt 105 */
#endif
#ifdef SYS_listen
	[SYS_listen] = { .name = "listen", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		}
	}, /* listen 106 */
#endif
#ifdef SYS_gettimeofday
	[SYS_gettimeofday] = { .name = "gettimeofday", .ret_type = 1, .nargs = 2,
		{ 
		  { OUT | Timeval, 0 },
		  { OUT | Ptr, 1 },
		}
	}, /* gettimeofday 116 */
#endif
#ifdef SYS_getrusage
	[SYS_getrusage] = { .name = "getrusage", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { OUT | Rusage, 1 },
		}
	}, /* getrusage 117 */
#endif
#ifdef SYS_getsockopt
	[SYS_getsockopt] = { .name = "getsockopt", .ret_type = 1, .nargs = 5,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { Int, 2 },
		  { OUT | Ptr, 3 },
		  { IN | OUT | Ptr, 4 },
		}
	}, /* getsockopt 118 */
#endif
#ifdef SYS_readv
	[SYS_readv] = { .name = "readv", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { IN | OUT | Ptr, 1 },
		  { UInt, 2 },
		}
	}, /* readv 120 */
#endif
#ifdef SYS_writev
	[SYS_writev] = { .name = "writev", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { UInt, 2 },
		}
	}, /* writev 121 */
#endif
#ifdef SYS_settimeofday
	[SYS_settimeofday] = { .name = "settimeofday", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Timeval, 0 },
		  { IN | Ptr, 1 },
		}
	}, /* settimeofday 122 */
#endif
#ifdef SYS_fchown
	[SYS_fchown] = { .name = "fchown", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { Int, 2 },
		}
	}, /* fchown 123 */
#endif
#ifdef SYS_fchmod
	[SYS_fchmod] = { .name = "fchmod", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { Octal, 1 },
		}
	}, /* fchmod 124 */
#endif
#ifdef SYS_setreuid
	[SYS_setreuid] = { .name = "setreuid", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		}
	}, /* setreuid 126 */
#endif
#ifdef SYS_setregid
	[SYS_setregid] = { .name = "setregid", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		}
	}, /* setregid 127 */
#endif
#ifdef SYS_rename
	[SYS_rename] = { .name = "rename", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { IN | Ptr, 1 },
		}
	}, /* rename 128 */
#endif
#ifdef SYS_flock
	[SYS_flock] = { .name = "flock", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		}
	}, /* flock 131 */
#endif
#ifdef SYS_mkfifo
	[SYS_mkfifo] = { .name = "mkfifo", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { Octal, 1 },
		}
	}, /* mkfifo 132 */
#endif
#ifdef SYS_sendto
	[SYS_sendto] = { .name = "sendto", .ret_type = 1, .nargs = 6,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { Sizet, 2 },
		  { Int, 3 },
		  { IN | Sockaddr, 4 },
		  { UInt, 5 },
		}
	}, /* sendto 133 */
#endif
#ifdef SYS_shutdown
	[SYS_shutdown] = { .name = "shutdown", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		}
	}, /* shutdown 134 */
#endif
#ifdef SYS_socketpair
	[SYS_socketpair] = { .name = "socketpair", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { Int, 2 },
		  { OUT | Ptr, 3 },
		}
	}, /* socketpair 135 */
#endif
#ifdef SYS_mkdir
	[SYS_mkdir] = { .name = "mkdir", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { Octal, 1 },
		}
	}, /* mkdir 136 */
#endif
#ifdef SYS_rmdir
	[SYS_rmdir] = { .name = "rmdir", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* rmdir 137 */
#endif
#ifdef SYS_utimes
	[SYS_utimes] = { .name = "utimes", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { IN | Timeval, 1 },
		}
	}, /* utimes 138 */
#endif
#ifdef SYS_adjtime
	[SYS_adjtime] = { .name = "adjtime", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Timeval, 0 },
		  { OUT | Timeval, 1 },
		}
	}, /* adjtime 140 */
#endif
#ifdef SYS_setsid
	[SYS_setsid] = { .name = "setsid", .ret_type = 1, .nargs = 0,
	}, /* setsid 147 */
#endif
#ifdef SYS_quotactl
	[SYS_quotactl] = { .name = "quotactl", .ret_type = 1, .nargs = 4,
		{ 
		  { IN | Ptr, 0 },
		  { Int, 1 },
		  { Int, 2 },
		  { IN | Ptr, 3 },
		}
	}, /* quotactl 148 */
#endif
#ifdef SYS_nlm_syscall
	[SYS_nlm_syscall] = { .name = "nlm_syscall", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { Int, 2 },
		  { IN | Ptr, 3 },
		}
	}, /* nlm_syscall 154 */
#endif
#ifdef SYS_nfssvc
	[SYS_nfssvc] = { .name = "nfssvc", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		}
	}, /* nfssvc 155 */
#endif
#ifdef SYS_lgetfh
	[SYS_lgetfh] = { .name = "lgetfh", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { OUT | Ptr, 1 },
		}
	}, /* lgetfh 160 */
#endif
#ifdef SYS_getfh
	[SYS_getfh] = { .name = "getfh", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { OUT | Ptr, 1 },
		}
	}, /* getfh 161 */
#endif
#ifdef SYS_sysarch
	[SYS_sysarch] = { .name = "sysarch", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		}
	}, /* sysarch 165 */
#endif
#ifdef SYS_rtprio
	[SYS_rtprio] = { .name = "rtprio", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { IN | OUT | Ptr, 2 },
		}
	}, /* rtprio 166 */
#endif
#ifdef SYS_semsys
	[SYS_semsys] = { .name = "semsys", .ret_type = 1, .nargs = 5,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { Int, 2 },
		  { Int, 3 },
		  { Int, 4 },
		}
	}, /* semsys 169 */
#endif
#ifdef SYS_msgsys
	[SYS_msgsys] = { .name = "msgsys", .ret_type = 1, .nargs = 6,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { Int, 2 },
		  { Int, 3 },
		  { Int, 4 },
		  { Int, 5 },
		}
	}, /* msgsys 170 */
#endif
#ifdef SYS_shmsys
	[SYS_shmsys] = { .name = "shmsys", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { Int, 2 },
		  { Int, 3 },
		}
	}, /* shmsys 171 */
#endif
#ifdef SYS_setfib
	[SYS_setfib] = { .name = "setfib", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* setfib 175 */
#endif
#ifdef SYS_ntp_adjtime
	[SYS_ntp_adjtime] = { .name = "ntp_adjtime", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | OUT | Ptr, 0 },
		}
	}, /* ntp_adjtime 176 */
#endif
#ifdef SYS_setgid
	[SYS_setgid] = { .name = "setgid", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* setgid 181 */
#endif
#ifdef SYS_setegid
	[SYS_setegid] = { .name = "setegid", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* setegid 182 */
#endif
#ifdef SYS_seteuid
	[SYS_seteuid] = { .name = "seteuid", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* seteuid 183 */
#endif
#ifdef SYS_freebsd11_stat
	[SYS_freebsd11_stat] = { .name = "freebsd11_stat", .ret_type = 1, .nargs = 2,
		{ 
		{ Ptr, 0 },
		{ Stat11, 1 },
		}
	}, /* freebsd11_stat 188 */
#endif
#ifdef SYS_freebsd11_fstat
	[SYS_freebsd11_fstat] = { .name = "freebsd11_fstat", .ret_type = 1, .nargs = 2,
		{ 
		{ Int, 0 },
		{ Stat11, 1 },
		}
	}, /* freebsd11_fstat 189 */
#endif
#ifdef SYS_freebsd11_lstat
	[SYS_freebsd11_lstat] = { .name = "freebsd11_lstat", .ret_type = 1, .nargs = 2,
		{ 
		{ Ptr, 0 },
		{ Stat11, 1 },
		}
	}, /* freebsd11_lstat 190 */
#endif
#ifdef SYS_pathconf
	[SYS_pathconf] = { .name = "pathconf", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { Int, 1 },
		}
	}, /* pathconf 191 */
#endif
#ifdef SYS_fpathconf
	[SYS_fpathconf] = { .name = "fpathconf", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		}
	}, /* fpathconf 192 */
#endif
#ifdef SYS_getrlimit
	[SYS_getrlimit] = { .name = "getrlimit", .ret_type = 1, .nargs = 2,
		{ 
		  { UInt, 0 },
		  { OUT | Rlimit, 1 },
		}
	}, /* getrlimit 194 */
#endif
#ifdef SYS_setrlimit
	[SYS_setrlimit] = { .name = "setrlimit", .ret_type = 1, .nargs = 2,
		{ 
		  { UInt, 0 },
		  { IN | Rlimit, 1 },
		}
	}, /* setrlimit 195 */
#endif
#ifdef SYS_freebsd11_getdirentries
	[SYS_freebsd11_getdirentries] = { .name = "freebsd11_getdirentries", .ret_type = 1, .nargs = 4,
		{ 
		{ Int, 0 },
		{ Ptr, 1 },
		{ UInt, 2 },
		{ Ptr, 3 },
		}
	}, /* freebsd11_getdirentries 196 */
#endif
#ifdef SYS___sysctl
	[SYS___sysctl] = { .name = "__sysctl", .ret_type = 1, .nargs = 6,
		{ 
		  { IN | Ptr, 0 },
		  { UInt, 1 },
		  { OUT | Ptr, 2 },
		  { IN | OUT | Ptr, 3 },
		  { IN | Ptr, 4 },
		  { Sizet, 5 },
		}
	}, /* __sysctl 202 */
#endif
#ifdef SYS_mlock
	[SYS_mlock] = { .name = "mlock", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { Sizet, 1 },
		}
	}, /* mlock 203 */
#endif
#ifdef SYS_munlock
	[SYS_munlock] = { .name = "munlock", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { Sizet, 1 },
		}
	}, /* munlock 204 */
#endif
#ifdef SYS_undelete
	[SYS_undelete] = { .name = "undelete", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* undelete 205 */
#endif
#ifdef SYS_futimes
	[SYS_futimes] = { .name = "futimes", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { IN | Timeval, 1 },
		}
	}, /* futimes 206 */
#endif
#ifdef SYS_getpgid
	[SYS_getpgid] = { .name = "getpgid", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* getpgid 207 */
#endif
#ifdef SYS_poll
	[SYS_poll] = { .name = "poll", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | OUT | Pollfd, 0 },
		  { UInt, 1 },
		  { Int, 2 },
		}
	}, /* poll 209 */
#endif
#ifdef SYS_freebsd7___semctl
	[SYS_freebsd7___semctl] = { .name = "freebsd7___semctl", .ret_type = 1, .nargs = 4,
		{ 
		{ Int, 0 },
		{ Int, 1 },
		{ Int, 2 },
		{ Ptr, 3 },
		}
	}, /* freebsd7___semctl 220 */
#endif
#ifdef SYS_semget
	[SYS_semget] = { .name = "semget", .ret_type = 1, .nargs = 3,
		{ 
		  { LongHex, 0 },
		  { Int, 1 },
		  { Int, 2 },
		}
	}, /* semget 221 */
#endif
#ifdef SYS_semop
	[SYS_semop] = { .name = "semop", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { Sizet, 2 },
		}
	}, /* semop 222 */
#endif
#ifdef SYS_freebsd7_msgctl
	[SYS_freebsd7_msgctl] = { .name = "freebsd7_msgctl", .ret_type = 1, .nargs = 3,
		{ 
		{ Int, 0 },
		{ Int, 1 },
		{ Ptr, 2 },
		}
	}, /* freebsd7_msgctl 224 */
#endif
#ifdef SYS_msgget
	[SYS_msgget] = { .name = "msgget", .ret_type = 1, .nargs = 2,
		{ 
		  { LongHex, 0 },
		  { Int, 1 },
		}
	}, /* msgget 225 */
#endif
#ifdef SYS_msgsnd
	[SYS_msgsnd] = { .name = "msgsnd", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { Sizet, 2 },
		  { Int, 3 },
		}
	}, /* msgsnd 226 */
#endif
#ifdef SYS_msgrcv
	[SYS_msgrcv] = { .name = "msgrcv", .ret_type = 1, .nargs = 5,
		{ 
		  { Int, 0 },
		  { OUT | Ptr, 1 },
		  { Sizet, 2 },
		  { Long, 3 },
		  { Int, 4 },
		}
	}, /* msgrcv 227 */
#endif
#ifdef SYS_shmat
	[SYS_shmat] = { .name = "shmat", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { Int, 2 },
		}
	}, /* shmat 228 */
#endif
#ifdef SYS_freebsd7_shmctl
	[SYS_freebsd7_shmctl] = { .name = "freebsd7_shmctl", .ret_type = 1, .nargs = 3,
		{ 
		{ Int, 0 },
		{ Int, 1 },
		{ Ptr, 2 },
		}
	}, /* freebsd7_shmctl 229 */
#endif
#ifdef SYS_shmdt
	[SYS_shmdt] = { .name = "shmdt", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* shmdt 230 */
#endif
#ifdef SYS_shmget
	[SYS_shmget] = { .name = "shmget", .ret_type = 1, .nargs = 3,
		{ 
		  { LongHex, 0 },
		  { Sizet, 1 },
		  { Int, 2 },
		}
	}, /* shmget 231 */
#endif
#ifdef SYS_clock_gettime
	[SYS_clock_gettime] = { .name = "clock_gettime", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { OUT | Timespec, 1 },
		}
	}, /* clock_gettime 232 */
#endif
#ifdef SYS_clock_settime
	[SYS_clock_settime] = { .name = "clock_settime", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { IN | Timespec, 1 },
		}
	}, /* clock_settime 233 */
#endif
#ifdef SYS_clock_getres
	[SYS_clock_getres] = { .name = "clock_getres", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { OUT | Timespec, 1 },
		}
	}, /* clock_getres 234 */
#endif
#ifdef SYS_ktimer_create
	[SYS_ktimer_create] = { .name = "ktimer_create", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { IN | Sigevent, 1 },
		  { OUT | Ptr, 2 },
		}
	}, /* ktimer_create 235 */
#endif
#ifdef SYS_ktimer_delete
	[SYS_ktimer_delete] = { .name = "ktimer_delete", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* ktimer_delete 236 */
#endif
#ifdef SYS_ktimer_settime
	[SYS_ktimer_settime] = { .name = "ktimer_settime", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { IN | Ptr, 2 },
		  { OUT | Ptr, 3 },
		}
	}, /* ktimer_settime 237 */
#endif
#ifdef SYS_ktimer_gettime
	[SYS_ktimer_gettime] = { .name = "ktimer_gettime", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { OUT | Ptr, 1 },
		}
	}, /* ktimer_gettime 238 */
#endif
#ifdef SYS_ktimer_getoverrun
	[SYS_ktimer_getoverrun] = { .name = "ktimer_getoverrun", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* ktimer_getoverrun 239 */
#endif
#ifdef SYS_nanosleep
	[SYS_nanosleep] = { .name = "nanosleep", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Timespec, 0 },
		  { OUT | Timespec, 1 },
		}
	}, /* nanosleep 240 */
#endif
#ifdef SYS_ffclock_getcounter
	[SYS_ffclock_getcounter] = { .name = "ffclock_getcounter", .ret_type = 1, .nargs = 1,
		{ 
		  { OUT | Ptr, 0 },
		}
	}, /* ffclock_getcounter 241 */
#endif
#ifdef SYS_ffclock_setestimate
	[SYS_ffclock_setestimate] = { .name = "ffclock_setestimate", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* ffclock_setestimate 242 */
#endif
#ifdef SYS_ffclock_getestimate
	[SYS_ffclock_getestimate] = { .name = "ffclock_getestimate", .ret_type = 1, .nargs = 1,
		{ 
		  { OUT | Ptr, 0 },
		}
	}, /* ffclock_getestimate 243 */
#endif
#ifdef SYS_clock_nanosleep
	[SYS_clock_nanosleep] = { .name = "clock_nanosleep", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { IN | Timespec, 2 },
		  { OUT | Timespec, 3 },
		}
	}, /* clock_nanosleep 244 */
#endif
#ifdef SYS_clock_getcpuclockid2
	[SYS_clock_getcpuclockid2] = { .name = "clock_getcpuclockid2", .ret_type = 1, .nargs = 3,
		{ 
		  { QuadHex, 0 },
		  { Int, 1 },
		  { OUT | Ptr, 2 },
		}
	}, /* clock_getcpuclockid2 247 */
#endif
#ifdef SYS_ntp_gettime
	[SYS_ntp_gettime] = { .name = "ntp_gettime", .ret_type = 1, .nargs = 1,
		{ 
		  { OUT | Ptr, 0 },
		}
	}, /* ntp_gettime 248 */
#endif
#ifdef SYS_minherit
	[SYS_minherit] = { .name = "minherit", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { Sizet, 1 },
		  { Int, 2 },
		}
	}, /* minherit 250 */
#endif
#ifdef SYS_rfork
	[SYS_rfork] = { .name = "rfork", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* rfork 251 */
#endif
#ifdef SYS_issetugid
	[SYS_issetugid] = { .name = "issetugid", .ret_type = 1, .nargs = 0,
	}, /* issetugid 253 */
#endif
#ifdef SYS_lchown
	[SYS_lchown] = { .name = "lchown", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { Int, 1 },
		  { Int, 2 },
		}
	}, /* lchown 254 */
#endif
#ifdef SYS_aio_read
	[SYS_aio_read] = { .name = "aio_read", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | OUT | Aiocb, 0 },
		}
	}, /* aio_read 255 */
#endif
#ifdef SYS_aio_write
	[SYS_aio_write] = { .name = "aio_write", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | OUT | Aiocb, 0 },
		}
	}, /* aio_write 256 */
#endif
#ifdef SYS_lio_listio
	[SYS_lio_listio] = { .name = "lio_listio", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { IN | OUT | Ptr, 1 },
		  { Int, 2 },
		  { IN | Sigevent, 3 },
		}
	}, /* lio_listio 257 */
#endif
#ifdef SYS_freebsd11_getdents
	[SYS_freebsd11_getdents] = { .name = "freebsd11_getdents", .ret_type = 1, .nargs = 3,
		{ 
		{ Int, 0 },
		{ Ptr, 1 },
		{ Sizet, 2 },
		}
	}, /* freebsd11_getdents 272 */
#endif
#ifdef SYS_lchmod
	[SYS_lchmod] = { .name = "lchmod", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { Octal, 1 },
		}
	}, /* lchmod 274 */
#endif
#ifdef SYS_lutimes
	[SYS_lutimes] = { .name = "lutimes", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { IN | Timeval, 1 },
		}
	}, /* lutimes 276 */
#endif
#ifdef SYS_freebsd11_nstat
	[SYS_freebsd11_nstat] = { .name = "freebsd11_nstat", .ret_type = 1, .nargs = 2,
		{ 
		{ Ptr, 0 },
		{ Ptr, 1 },
		}
	}, /* freebsd11_nstat 278 */
#endif
#ifdef SYS_freebsd11_nfstat
	[SYS_freebsd11_nfstat] = { .name = "freebsd11_nfstat", .ret_type = 1, .nargs = 2,
		{ 
		{ Int, 0 },
		{ Ptr, 1 },
		}
	}, /* freebsd11_nfstat 279 */
#endif
#ifdef SYS_freebsd11_nlstat
	[SYS_freebsd11_nlstat] = { .name = "freebsd11_nlstat", .ret_type = 1, .nargs = 2,
		{ 
		{ Ptr, 0 },
		{ Ptr, 1 },
		}
	}, /* freebsd11_nlstat 280 */
#endif
#ifdef SYS_preadv
	[SYS_preadv] = { .name = "preadv", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { UInt, 2 },
		  { QuadHex, 3 },
		}
	}, /* preadv 289 */
#endif
#ifdef SYS_pwritev
	[SYS_pwritev] = { .name = "pwritev", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { UInt, 2 },
		  { QuadHex, 3 },
		}
	}, /* pwritev 290 */
#endif
#ifdef SYS_fhopen
	[SYS_fhopen] = { .name = "fhopen", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { Int, 1 },
		}
	}, /* fhopen 298 */
#endif
#ifdef SYS_freebsd11_fhstat
	[SYS_freebsd11_fhstat] = { .name = "freebsd11_fhstat", .ret_type = 1, .nargs = 2,
		{ 
		{ Ptr, 0 },
		{ Stat11, 1 },
		}
	}, /* freebsd11_fhstat 299 */
#endif
#ifdef SYS_modnext
	[SYS_modnext] = { .name = "modnext", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* modnext 300 */
#endif
#ifdef SYS_modstat
	[SYS_modstat] = { .name = "modstat", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { OUT | Ptr, 1 },
		}
	}, /* modstat 301 */
#endif
#ifdef SYS_modfnext
	[SYS_modfnext] = { .name = "modfnext", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* modfnext 302 */
#endif
#ifdef SYS_modfind
	[SYS_modfind] = { .name = "modfind", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* modfind 303 */
#endif
#ifdef SYS_kldload
	[SYS_kldload] = { .name = "kldload", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* kldload 304 */
#endif
#ifdef SYS_kldunload
	[SYS_kldunload] = { .name = "kldunload", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* kldunload 305 */
#endif
#ifdef SYS_kldfind
	[SYS_kldfind] = { .name = "kldfind", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* kldfind 306 */
#endif
#ifdef SYS_kldnext
	[SYS_kldnext] = { .name = "kldnext", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* kldnext 307 */
#endif
#ifdef SYS_kldstat
	[SYS_kldstat] = { .name = "kldstat", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { OUT | Ptr, 1 },
		}
	}, /* kldstat 308 */
#endif
#ifdef SYS_kldfirstmod
	[SYS_kldfirstmod] = { .name = "kldfirstmod", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* kldfirstmod 309 */
#endif
#ifdef SYS_getsid
	[SYS_getsid] = { .name = "getsid", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* getsid 310 */
#endif
#ifdef SYS_setresuid
	[SYS_setresuid] = { .name = "setresuid", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { Int, 2 },
		}
	}, /* setresuid 311 */
#endif
#ifdef SYS_setresgid
	[SYS_setresgid] = { .name = "setresgid", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { Int, 2 },
		}
	}, /* setresgid 312 */
#endif
#ifdef SYS_aio_return
	[SYS_aio_return] = { .name = "aio_return", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | OUT | Aiocb, 0 },
		}
	}, /* aio_return 314 */
#endif
#ifdef SYS_aio_suspend
	[SYS_aio_suspend] = { .name = "aio_suspend", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | OUT | Ptr, 0 },
		  { Int, 1 },
		  { IN | Timespec, 2 },
		}
	}, /* aio_suspend 315 */
#endif
#ifdef SYS_aio_cancel
	[SYS_aio_cancel] = { .name = "aio_cancel", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { IN | Aiocb, 1 },
		}
	}, /* aio_cancel 316 */
#endif
#ifdef SYS_aio_error
	[SYS_aio_error] = { .name = "aio_error", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Aiocb, 0 },
		}
	}, /* aio_error 317 */
#endif
#ifdef SYS_yield
	[SYS_yield] = { .name = "yield", .ret_type = 1, .nargs = 0,
	}, /* yield 321 */
#endif
#ifdef SYS_mlockall
	[SYS_mlockall] = { .name = "mlockall", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* mlockall 324 */
#endif
#ifdef SYS_munlockall
	[SYS_munlockall] = { .name = "munlockall", .ret_type = 1, .nargs = 0,
	}, /* munlockall 325 */
#endif
#ifdef SYS___getcwd
	[SYS___getcwd] = { .name = "__getcwd", .ret_type = 1, .nargs = 2,
		{ 
		  { OUT | Ptr, 0 },
		  { Sizet, 1 },
		}
	}, /* __getcwd 326 */
#endif
#ifdef SYS_sched_setparam
	[SYS_sched_setparam] = { .name = "sched_setparam", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		}
	}, /* sched_setparam 327 */
#endif
#ifdef SYS_sched_getparam
	[SYS_sched_getparam] = { .name = "sched_getparam", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { OUT | Ptr, 1 },
		}
	}, /* sched_getparam 328 */
#endif
#ifdef SYS_sched_setscheduler
	[SYS_sched_setscheduler] = { .name = "sched_setscheduler", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { IN | Ptr, 2 },
		}
	}, /* sched_setscheduler 329 */
#endif
#ifdef SYS_sched_getscheduler
	[SYS_sched_getscheduler] = { .name = "sched_getscheduler", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* sched_getscheduler 330 */
#endif
#ifdef SYS_sched_yield
	[SYS_sched_yield] = { .name = "sched_yield", .ret_type = 1, .nargs = 0,
	}, /* sched_yield 331 */
#endif
#ifdef SYS_sched_get_priority_max
	[SYS_sched_get_priority_max] = { .name = "sched_get_priority_max", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* sched_get_priority_max 332 */
#endif
#ifdef SYS_sched_get_priority_min
	[SYS_sched_get_priority_min] = { .name = "sched_get_priority_min", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* sched_get_priority_min 333 */
#endif
#ifdef SYS_sched_rr_get_interval
	[SYS_sched_rr_get_interval] = { .name = "sched_rr_get_interval", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { OUT | Timespec, 1 },
		}
	}, /* sched_rr_get_interval 334 */
#endif
#ifdef SYS_utrace
	[SYS_utrace] = { .name = "utrace", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { Sizet, 1 },
		}
	}, /* utrace 335 */
#endif
#ifdef SYS_kldsym
	[SYS_kldsym] = { .name = "kldsym", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { IN | Ptr, 2 },
		}
	}, /* kldsym 337 */
#endif
#ifdef SYS_jail
	[SYS_jail] = { .name = "jail", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* jail 338 */
#endif
#ifdef SYS_nnpfs_syscall
	[SYS_nnpfs_syscall] = { .name = "nnpfs_syscall", .ret_type = 1, .nargs = 5,
		{ 
		  { Int, 0 },
		  { Ptr, 1 },
		  { Int, 2 },
		  { Ptr, 3 },
		  { Int, 4 },
		}
	}, /* nnpfs_syscall 339 */
#endif
#ifdef SYS_sigprocmask
	[SYS_sigprocmask] = { .name = "sigprocmask", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { OUT | Ptr, 2 },
		}
	}, /* sigprocmask 340 */
#endif
#ifdef SYS_sigsuspend
	[SYS_sigsuspend] = { .name = "sigsuspend", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* sigsuspend 341 */
#endif
#ifdef SYS_sigpending
	[SYS_sigpending] = { .name = "sigpending", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* sigpending 343 */
#endif
#ifdef SYS_sigtimedwait
	[SYS_sigtimedwait] = { .name = "sigtimedwait", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { OUT | Siginfo, 1 },
		  { IN | Timespec, 2 },
		}
	}, /* sigtimedwait 345 */
#endif
#ifdef SYS_sigwaitinfo
	[SYS_sigwaitinfo] = { .name = "sigwaitinfo", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { OUT | Siginfo, 1 },
		}
	}, /* sigwaitinfo 346 */
#endif
#ifdef SYS___acl_get_file
	[SYS___acl_get_file] = { .name = "__acl_get_file", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { Acltype, 1 },
		  { OUT | Ptr, 2 },
		}
	}, /* __acl_get_file 347 */
#endif
#ifdef SYS___acl_set_file
	[SYS___acl_set_file] = { .name = "__acl_set_file", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { Acltype, 1 },
		  { IN | Ptr, 2 },
		}
	}, /* __acl_set_file 348 */
#endif
#ifdef SYS___acl_get_fd
	[SYS___acl_get_fd] = { .name = "__acl_get_fd", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { Acltype, 1 },
		  { OUT | Ptr, 2 },
		}
	}, /* __acl_get_fd 349 */
#endif
#ifdef SYS___acl_set_fd
	[SYS___acl_set_fd] = { .name = "__acl_set_fd", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { Acltype, 1 },
		  { IN | Ptr, 2 },
		}
	}, /* __acl_set_fd 350 */
#endif
#ifdef SYS___acl_delete_file
	[SYS___acl_delete_file] = { .name = "__acl_delete_file", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { Acltype, 1 },
		}
	}, /* __acl_delete_file 351 */
#endif
#ifdef SYS___acl_delete_fd
	[SYS___acl_delete_fd] = { .name = "__acl_delete_fd", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { Acltype, 1 },
		}
	}, /* __acl_delete_fd 352 */
#endif
#ifdef SYS___acl_aclcheck_file
	[SYS___acl_aclcheck_file] = { .name = "__acl_aclcheck_file", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { Acltype, 1 },
		  { IN | Ptr, 2 },
		}
	}, /* __acl_aclcheck_file 353 */
#endif
#ifdef SYS___acl_aclcheck_fd
	[SYS___acl_aclcheck_fd] = { .name = "__acl_aclcheck_fd", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { Acltype, 1 },
		  { IN | Ptr, 2 },
		}
	}, /* __acl_aclcheck_fd 354 */
#endif
#ifdef SYS_extattrctl
	[SYS_extattrctl] = { .name = "extattrctl", .ret_type = 1, .nargs = 5,
		{ 
		  { IN | Ptr, 0 },
		  { Int, 1 },
		  { IN | Ptr, 2 },
		  { Int, 3 },
		  { IN | Ptr, 4 },
		}
	}, /* extattrctl 355 */
#endif
#ifdef SYS_extattr_set_file
	[SYS_extattr_set_file] = { .name = "extattr_set_file", .ret_type = 1, .nargs = 5,
		{ 
		  { IN | Ptr, 0 },
		  { Int, 1 },
		  { IN | Ptr, 2 },
		  { IN | Ptr, 3 },
		  { Sizet, 4 },
		}
	}, /* extattr_set_file 356 */
#endif
#ifdef SYS_extattr_get_file
	[SYS_extattr_get_file] = { .name = "extattr_get_file", .ret_type = 1, .nargs = 5,
		{ 
		  { IN | Ptr, 0 },
		  { Int, 1 },
		  { IN | Ptr, 2 },
		  { OUT | Ptr, 3 },
		  { Sizet, 4 },
		}
	}, /* extattr_get_file 357 */
#endif
#ifdef SYS_extattr_delete_file
	[SYS_extattr_delete_file] = { .name = "extattr_delete_file", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { Int, 1 },
		  { IN | Ptr, 2 },
		}
	}, /* extattr_delete_file 358 */
#endif
#ifdef SYS_aio_waitcomplete
	[SYS_aio_waitcomplete] = { .name = "aio_waitcomplete", .ret_type = 1, .nargs = 2,
		{ 
		  { Ptr, 0 },
		  { IN | Timespec, 1 },
		}
	}, /* aio_waitcomplete 359 */
#endif
#ifdef SYS_getresuid
	[SYS_getresuid] = { .name = "getresuid", .ret_type = 1, .nargs = 3,
		{ 
		  { OUT | Ptr, 0 },
		  { OUT | Ptr, 1 },
		  { OUT | Ptr, 2 },
		}
	}, /* getresuid 360 */
#endif
#ifdef SYS_getresgid
	[SYS_getresgid] = { .name = "getresgid", .ret_type = 1, .nargs = 3,
		{ 
		  { OUT | Ptr, 0 },
		  { OUT | Ptr, 1 },
		  { OUT | Ptr, 2 },
		}
	}, /* getresgid 361 */
#endif
#ifdef SYS_kqueue
	[SYS_kqueue] = { .name = "kqueue", .ret_type = 1, .nargs = 0,
	}, /* kqueue 362 */
#endif
#ifdef SYS_freebsd11_kevent
	[SYS_freebsd11_kevent] = { .name = "freebsd11_kevent", .ret_type = 1, .nargs = 6,
		{ 
		{ Int, 0 },
		{ Kevent11, 1 },
		{ Int, 2 },
		{ Kevent11, 3 },
		{ Int, 4 },
		{ Timespec, 5 },
		}
	}, /* freebsd11_kevent 363 */
#endif
#ifdef SYS_extattr_set_fd
	[SYS_extattr_set_fd] = { .name = "extattr_set_fd", .ret_type = 1, .nargs = 5,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { IN | Ptr, 2 },
		  { IN | Ptr, 3 },
		  { Sizet, 4 },
		}
	}, /* extattr_set_fd 371 */
#endif
#ifdef SYS_extattr_get_fd
	[SYS_extattr_get_fd] = { .name = "extattr_get_fd", .ret_type = 1, .nargs = 5,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { IN | Ptr, 2 },
		  { OUT | Ptr, 3 },
		  { Sizet, 4 },
		}
	}, /* extattr_get_fd 372 */
#endif
#ifdef SYS_extattr_delete_fd
	[SYS_extattr_delete_fd] = { .name = "extattr_delete_fd", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { IN | Ptr, 2 },
		}
	}, /* extattr_delete_fd 373 */
#endif
#ifdef SYS___setugid
	[SYS___setugid] = { .name = "__setugid", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* __setugid 374 */
#endif
#ifdef SYS_eaccess
	[SYS_eaccess] = { .name = "eaccess", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { Int, 1 },
		}
	}, /* eaccess 376 */
#endif
#ifdef SYS_afs3_syscall
	[SYS_afs3_syscall] = { .name = "afs3_syscall", .ret_type = 1, .nargs = 7,
		{ 
		  { Long, 0 },
		  { Long, 1 },
		  { Long, 2 },
		  { Long, 3 },
		  { Long, 4 },
		  { Long, 5 },
		  { Long, 6 },
		}
	}, /* afs3_syscall 377 */
#endif
#ifdef SYS_nmount
	[SYS_nmount] = { .name = "nmount", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { UInt, 1 },
		  { Int, 2 },
		}
	}, /* nmount 378 */
#endif
#ifdef SYS___mac_get_proc
	[SYS___mac_get_proc] = { .name = "__mac_get_proc", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* __mac_get_proc 384 */
#endif
#ifdef SYS___mac_set_proc
	[SYS___mac_set_proc] = { .name = "__mac_set_proc", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* __mac_set_proc 385 */
#endif
#ifdef SYS___mac_get_fd
	[SYS___mac_get_fd] = { .name = "__mac_get_fd", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		}
	}, /* __mac_get_fd 386 */
#endif
#ifdef SYS___mac_get_file
	[SYS___mac_get_file] = { .name = "__mac_get_file", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { IN | Ptr, 1 },
		}
	}, /* __mac_get_file 387 */
#endif
#ifdef SYS___mac_set_fd
	[SYS___mac_set_fd] = { .name = "__mac_set_fd", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		}
	}, /* __mac_set_fd 388 */
#endif
#ifdef SYS___mac_set_file
	[SYS___mac_set_file] = { .name = "__mac_set_file", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { IN | Ptr, 1 },
		}
	}, /* __mac_set_file 389 */
#endif
#ifdef SYS_kenv
	[SYS_kenv] = { .name = "kenv", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { IN | OUT | Ptr, 2 },
		  { Int, 3 },
		}
	}, /* kenv 390 */
#endif
#ifdef SYS_lchflags
	[SYS_lchflags] = { .name = "lchflags", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { LongHex, 1 },
		}
	}, /* lchflags 391 */
#endif
#ifdef SYS_uuidgen
	[SYS_uuidgen] = { .name = "uuidgen", .ret_type = 1, .nargs = 2,
		{ 
		  { OUT | Ptr, 0 },
		  { Int, 1 },
		}
	}, /* uuidgen 392 */
#endif
#ifdef SYS_sendfile
	[SYS_sendfile] = { .name = "sendfile", .ret_type = 1, .nargs = 7,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { QuadHex, 2 },
		  { Sizet, 3 },
		  { IN | Ptr, 4 },
		  { OUT | Ptr, 5 },
		  { Int, 6 },
		}
	}, /* sendfile 393 */
#endif
#ifdef SYS_mac_syscall
	[SYS_mac_syscall] = { .name = "mac_syscall", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { Int, 1 },
		  { IN | Ptr, 2 },
		}
	}, /* mac_syscall 394 */
#endif
#ifdef SYS_freebsd11_getfsstat
	[SYS_freebsd11_getfsstat] = { .name = "freebsd11_getfsstat", .ret_type = 1, .nargs = 3,
		{ 
		{ Ptr, 0 },
		{ Long, 1 },
		{ Int, 2 },
		}
	}, /* freebsd11_getfsstat 395 */
#endif
#ifdef SYS_freebsd11_statfs
	[SYS_freebsd11_statfs] = { .name = "freebsd11_statfs", .ret_type = 1, .nargs = 2,
		{ 
		{ Ptr, 0 },
		{ Ptr, 1 },
		}
	}, /* freebsd11_statfs 396 */
#endif
#ifdef SYS_freebsd11_fstatfs
	[SYS_freebsd11_fstatfs] = { .name = "freebsd11_fstatfs", .ret_type = 1, .nargs = 2,
		{ 
		{ Int, 0 },
		{ Ptr, 1 },
		}
	}, /* freebsd11_fstatfs 397 */
#endif
#ifdef SYS_freebsd11_fhstatfs
	[SYS_freebsd11_fhstatfs] = { .name = "freebsd11_fhstatfs", .ret_type = 1, .nargs = 2,
		{ 
		{ Ptr, 0 },
		{ Ptr, 1 },
		}
	}, /* freebsd11_fhstatfs 398 */
#endif
#ifdef SYS_ksem_close
	[SYS_ksem_close] = { .name = "ksem_close", .ret_type = 1, .nargs = 1,
		{ 
		  { LongHex, 0 },
		}
	}, /* ksem_close 400 */
#endif
#ifdef SYS_ksem_post
	[SYS_ksem_post] = { .name = "ksem_post", .ret_type = 1, .nargs = 1,
		{ 
		  { LongHex, 0 },
		}
	}, /* ksem_post 401 */
#endif
#ifdef SYS_ksem_wait
	[SYS_ksem_wait] = { .name = "ksem_wait", .ret_type = 1, .nargs = 1,
		{ 
		  { LongHex, 0 },
		}
	}, /* ksem_wait 402 */
#endif
#ifdef SYS_ksem_trywait
	[SYS_ksem_trywait] = { .name = "ksem_trywait", .ret_type = 1, .nargs = 1,
		{ 
		  { LongHex, 0 },
		}
	}, /* ksem_trywait 403 */
#endif
#ifdef SYS_ksem_init
	[SYS_ksem_init] = { .name = "ksem_init", .ret_type = 1, .nargs = 2,
		{ 
		  { OUT | Ptr, 0 },
		  { UInt, 1 },
		}
	}, /* ksem_init 404 */
#endif
#ifdef SYS_ksem_open
	[SYS_ksem_open] = { .name = "ksem_open", .ret_type = 1, .nargs = 5,
		{ 
		  { OUT | Ptr, 0 },
		  { IN | Ptr, 1 },
		  { Int, 2 },
		  { Octal, 3 },
		  { UInt, 4 },
		}
	}, /* ksem_open 405 */
#endif
#ifdef SYS_ksem_unlink
	[SYS_ksem_unlink] = { .name = "ksem_unlink", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* ksem_unlink 406 */
#endif
#ifdef SYS_ksem_getvalue
	[SYS_ksem_getvalue] = { .name = "ksem_getvalue", .ret_type = 1, .nargs = 2,
		{ 
		  { LongHex, 0 },
		  { OUT | Ptr, 1 },
		}
	}, /* ksem_getvalue 407 */
#endif
#ifdef SYS_ksem_destroy
	[SYS_ksem_destroy] = { .name = "ksem_destroy", .ret_type = 1, .nargs = 1,
		{ 
		  { LongHex, 0 },
		}
	}, /* ksem_destroy 408 */
#endif
#ifdef SYS___mac_get_pid
	[SYS___mac_get_pid] = { .name = "__mac_get_pid", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		}
	}, /* __mac_get_pid 409 */
#endif
#ifdef SYS___mac_get_link
	[SYS___mac_get_link] = { .name = "__mac_get_link", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { IN | Ptr, 1 },
		}
	}, /* __mac_get_link 410 */
#endif
#ifdef SYS___mac_set_link
	[SYS___mac_set_link] = { .name = "__mac_set_link", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { IN | Ptr, 1 },
		}
	}, /* __mac_set_link 411 */
#endif
#ifdef SYS_extattr_set_link
	[SYS_extattr_set_link] = { .name = "extattr_set_link", .ret_type = 1, .nargs = 5,
		{ 
		  { IN | Ptr, 0 },
		  { Int, 1 },
		  { IN | Ptr, 2 },
		  { IN | Ptr, 3 },
		  { Sizet, 4 },
		}
	}, /* extattr_set_link 412 */
#endif
#ifdef SYS_extattr_get_link
	[SYS_extattr_get_link] = { .name = "extattr_get_link", .ret_type = 1, .nargs = 5,
		{ 
		  { IN | Ptr, 0 },
		  { Int, 1 },
		  { IN | Ptr, 2 },
		  { OUT | Ptr, 3 },
		  { Sizet, 4 },
		}
	}, /* extattr_get_link 413 */
#endif
#ifdef SYS_extattr_delete_link
	[SYS_extattr_delete_link] = { .name = "extattr_delete_link", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { Int, 1 },
		  { IN | Ptr, 2 },
		}
	}, /* extattr_delete_link 414 */
#endif
#ifdef SYS___mac_execve
	[SYS___mac_execve] = { .name = "__mac_execve", .ret_type = 1, .nargs = 4,
		{ 
		  { IN | Ptr, 0 },
		  { IN | Ptr, 1 },
		  { IN | Ptr, 2 },
		  { IN | Ptr, 3 },
		}
	}, /* __mac_execve 415 */
#endif
#ifdef SYS_sigaction
	[SYS_sigaction] = { .name = "sigaction", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { IN | Sigaction, 1 },
		  { OUT | Sigaction, 2 },
		}
	}, /* sigaction 416 */
#endif
#ifdef SYS_sigreturn
	[SYS_sigreturn] = { .name = "sigreturn", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* sigreturn 417 */
#endif
#ifdef SYS_getcontext
	[SYS_getcontext] = { .name = "getcontext", .ret_type = 1, .nargs = 1,
		{ 
		  { OUT | Ptr, 0 },
		}
	}, /* getcontext 421 */
#endif
#ifdef SYS_setcontext
	[SYS_setcontext] = { .name = "setcontext", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* setcontext 422 */
#endif
#ifdef SYS_swapcontext
	[SYS_swapcontext] = { .name = "swapcontext", .ret_type = 1, .nargs = 2,
		{ 
		  { OUT | Ptr, 0 },
		  { IN | Ptr, 1 },
		}
	}, /* swapcontext 423 */
#endif
#ifdef SYS_freebsd13_swapoff
	[SYS_freebsd13_swapoff] = { .name = "freebsd13_swapoff", .ret_type = 1, .nargs = 1,
		{ 
		{ Ptr, 0 },
		}
	}, /* freebsd13_swapoff 424 */
#endif
#ifdef SYS___acl_get_link
	[SYS___acl_get_link] = { .name = "__acl_get_link", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { Acltype, 1 },
		  { OUT | Ptr, 2 },
		}
	}, /* __acl_get_link 425 */
#endif
#ifdef SYS___acl_set_link
	[SYS___acl_set_link] = { .name = "__acl_set_link", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { Acltype, 1 },
		  { IN | Ptr, 2 },
		}
	}, /* __acl_set_link 426 */
#endif
#ifdef SYS___acl_delete_link
	[SYS___acl_delete_link] = { .name = "__acl_delete_link", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { Acltype, 1 },
		}
	}, /* __acl_delete_link 427 */
#endif
#ifdef SYS___acl_aclcheck_link
	[SYS___acl_aclcheck_link] = { .name = "__acl_aclcheck_link", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { Acltype, 1 },
		  { IN | Ptr, 2 },
		}
	}, /* __acl_aclcheck_link 428 */
#endif
#ifdef SYS_sigwait
	[SYS_sigwait] = { .name = "sigwait", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { OUT | Ptr, 1 },
		}
	}, /* sigwait 429 */
#endif
#ifdef SYS_thr_create
	[SYS_thr_create] = { .name = "thr_create", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { OUT | Ptr, 1 },
		  { Int, 2 },
		}
	}, /* thr_create 430 */
#endif
#ifdef SYS_thr_exit
	[SYS_thr_exit] = { .name = "thr_exit", .ret_type = 1, .nargs = 1,
		{ 
		  { OUT | Ptr, 0 },
		}
	}, /* thr_exit 431 */
#endif
#ifdef SYS_thr_self
	[SYS_thr_self] = { .name = "thr_self", .ret_type = 1, .nargs = 1,
		{ 
		  { OUT | Ptr, 0 },
		}
	}, /* thr_self 432 */
#endif
#ifdef SYS_thr_kill
	[SYS_thr_kill] = { .name = "thr_kill", .ret_type = 1, .nargs = 2,
		{ 
		  { Long, 0 },
		  { Int, 1 },
		}
	}, /* thr_kill 433 */
#endif
#ifdef SYS_freebsd10__umtx_lock
	[SYS_freebsd10__umtx_lock] = { .name = "freebsd10__umtx_lock", .ret_type = 1, .nargs = 1,
		{ 
		{ Ptr, 0 },
		}
	}, /* freebsd10__umtx_lock 434 */
#endif
#ifdef SYS_freebsd10__umtx_unlock
	[SYS_freebsd10__umtx_unlock] = { .name = "freebsd10__umtx_unlock", .ret_type = 1, .nargs = 1,
		{ 
		{ Ptr, 0 },
		}
	}, /* freebsd10__umtx_unlock 435 */
#endif
#ifdef SYS_jail_attach
	[SYS_jail_attach] = { .name = "jail_attach", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* jail_attach 436 */
#endif
#ifdef SYS_extattr_list_fd
	[SYS_extattr_list_fd] = { .name = "extattr_list_fd", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { OUT | Ptr, 2 },
		  { Sizet, 3 },
		}
	}, /* extattr_list_fd 437 */
#endif
#ifdef SYS_extattr_list_file
	[SYS_extattr_list_file] = { .name = "extattr_list_file", .ret_type = 1, .nargs = 4,
		{ 
		  { IN | Ptr, 0 },
		  { Int, 1 },
		  { OUT | Ptr, 2 },
		  { Sizet, 3 },
		}
	}, /* extattr_list_file 438 */
#endif
#ifdef SYS_extattr_list_link
	[SYS_extattr_list_link] = { .name = "extattr_list_link", .ret_type = 1, .nargs = 4,
		{ 
		  { IN | Ptr, 0 },
		  { Int, 1 },
		  { OUT | Ptr, 2 },
		  { Sizet, 3 },
		}
	}, /* extattr_list_link 439 */
#endif
#ifdef SYS_ksem_timedwait
	[SYS_ksem_timedwait] = { .name = "ksem_timedwait", .ret_type = 1, .nargs = 2,
		{ 
		  { LongHex, 0 },
		  { IN | Timespec, 1 },
		}
	}, /* ksem_timedwait 441 */
#endif
#ifdef SYS_thr_suspend
	[SYS_thr_suspend] = { .name = "thr_suspend", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Timespec, 0 },
		}
	}, /* thr_suspend 442 */
#endif
#ifdef SYS_thr_wake
	[SYS_thr_wake] = { .name = "thr_wake", .ret_type = 1, .nargs = 1,
		{ 
		  { Long, 0 },
		}
	}, /* thr_wake 443 */
#endif
#ifdef SYS_kldunloadf
	[SYS_kldunloadf] = { .name = "kldunloadf", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		}
	}, /* kldunloadf 444 */
#endif
#ifdef SYS_audit
	[SYS_audit] = { .name = "audit", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { UInt, 1 },
		}
	}, /* audit 445 */
#endif
#ifdef SYS_auditon
	[SYS_auditon] = { .name = "auditon", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { UInt, 2 },
		}
	}, /* auditon 446 */
#endif
#ifdef SYS_getauid
	[SYS_getauid] = { .name = "getauid", .ret_type = 1, .nargs = 1,
		{ 
		  { OUT | Ptr, 0 },
		}
	}, /* getauid 447 */
#endif
#ifdef SYS_setauid
	[SYS_setauid] = { .name = "setauid", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* setauid 448 */
#endif
#ifdef SYS_getaudit
	[SYS_getaudit] = { .name = "getaudit", .ret_type = 1, .nargs = 1,
		{ 
		  { OUT | Ptr, 0 },
		}
	}, /* getaudit 449 */
#endif
#ifdef SYS_setaudit
	[SYS_setaudit] = { .name = "setaudit", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* setaudit 450 */
#endif
#ifdef SYS_getaudit_addr
	[SYS_getaudit_addr] = { .name = "getaudit_addr", .ret_type = 1, .nargs = 2,
		{ 
		  { OUT | Ptr, 0 },
		  { UInt, 1 },
		}
	}, /* getaudit_addr 451 */
#endif
#ifdef SYS_setaudit_addr
	[SYS_setaudit_addr] = { .name = "setaudit_addr", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { UInt, 1 },
		}
	}, /* setaudit_addr 452 */
#endif
#ifdef SYS_auditctl
	[SYS_auditctl] = { .name = "auditctl", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* auditctl 453 */
#endif
#ifdef SYS__umtx_op
	[SYS__umtx_op] = { .name = "_umtx_op", .ret_type = 1, .nargs = 5,
		{ 
		  { IN | OUT | Ptr, 0 },
		  { Int, 1 },
		  { LongHex, 2 },
		  { IN | Ptr, 3 },
		  { IN | Ptr, 4 },
		}
	}, /* _umtx_op 454 */
#endif
#ifdef SYS_thr_new
	[SYS_thr_new] = { .name = "thr_new", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { Int, 1 },
		}
	}, /* thr_new 455 */
#endif
#ifdef SYS_sigqueue
	[SYS_sigqueue] = { .name = "sigqueue", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { IN | Ptr, 2 },
		}
	}, /* sigqueue 456 */
#endif
#ifdef SYS_kmq_open
	[SYS_kmq_open] = { .name = "kmq_open", .ret_type = 1, .nargs = 4,
		{ 
		  { IN | Ptr, 0 },
		  { Int, 1 },
		  { Octal, 2 },
		  { IN | Ptr, 3 },
		}
	}, /* kmq_open 457 */
#endif
#ifdef SYS_kmq_setattr
	[SYS_kmq_setattr] = { .name = "kmq_setattr", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { OUT | Ptr, 2 },
		}
	}, /* kmq_setattr 458 */
#endif
#ifdef SYS_kmq_timedreceive
	[SYS_kmq_timedreceive] = { .name = "kmq_timedreceive", .ret_type = 1, .nargs = 5,
		{ 
		  { Int, 0 },
		  { OUT | Ptr, 1 },
		  { Sizet, 2 },
		  { OUT | Ptr, 3 },
		  { IN | Timespec, 4 },
		}
	}, /* kmq_timedreceive 459 */
#endif
#ifdef SYS_kmq_timedsend
	[SYS_kmq_timedsend] = { .name = "kmq_timedsend", .ret_type = 1, .nargs = 5,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { Sizet, 2 },
		  { UInt, 3 },
		  { IN | Timespec, 4 },
		}
	}, /* kmq_timedsend 460 */
#endif
#ifdef SYS_kmq_notify
	[SYS_kmq_notify] = { .name = "kmq_notify", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { IN | Sigevent, 1 },
		}
	}, /* kmq_notify 461 */
#endif
#ifdef SYS_kmq_unlink
	[SYS_kmq_unlink] = { .name = "kmq_unlink", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* kmq_unlink 462 */
#endif
#ifdef SYS_abort2
	[SYS_abort2] = { .name = "abort2", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { Int, 1 },
		  { IN | Ptr, 2 },
		}
	}, /* abort2 463 */
#endif
#ifdef SYS_thr_set_name
	[SYS_thr_set_name] = { .name = "thr_set_name", .ret_type = 1, .nargs = 2,
		{ 
		  { Long, 0 },
		  { IN | Ptr, 1 },
		}
	}, /* thr_set_name 464 */
#endif
#ifdef SYS_aio_fsync
	[SYS_aio_fsync] = { .name = "aio_fsync", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { IN | Aiocb, 1 },
		}
	}, /* aio_fsync 465 */
#endif
#ifdef SYS_rtprio_thread
	[SYS_rtprio_thread] = { .name = "rtprio_thread", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { IN | OUT | Ptr, 2 },
		}
	}, /* rtprio_thread 466 */
#endif
#ifdef SYS_sctp_peeloff
	[SYS_sctp_peeloff] = { .name = "sctp_peeloff", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { UInt, 1 },
		}
	}, /* sctp_peeloff 471 */
#endif
#ifdef SYS_sctp_generic_sendmsg
	[SYS_sctp_generic_sendmsg] = { .name = "sctp_generic_sendmsg", .ret_type = 1, .nargs = 7,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { Int, 2 },
		  { IN | Sockaddr, 3 },
		  { UInt, 4 },
		  { IN | Sctpsndrcvinfo, 5 },
		  { Int, 6 },
		}
	}, /* sctp_generic_sendmsg 472 */
#endif
#ifdef SYS_sctp_generic_sendmsg_iov
	[SYS_sctp_generic_sendmsg_iov] = { .name = "sctp_generic_sendmsg_iov", .ret_type = 1, .nargs = 7,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { Int, 2 },
		  { IN | Sockaddr, 3 },
		  { UInt, 4 },
		  { IN | Sctpsndrcvinfo, 5 },
		  { Int, 6 },
		}
	}, /* sctp_generic_sendmsg_iov 473 */
#endif
#ifdef SYS_sctp_generic_recvmsg
	[SYS_sctp_generic_recvmsg] = { .name = "sctp_generic_recvmsg", .ret_type = 1, .nargs = 7,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { Int, 2 },
		  { OUT | Sockaddr, 3 },
		  { OUT | Ptr, 4 },
		  { IN | Sctpsndrcvinfo, 5 },
		  { OUT | Ptr, 6 },
		}
	}, /* sctp_generic_recvmsg 474 */
#endif
#ifdef SYS_pread
	[SYS_pread] = { .name = "pread", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { OUT | Ptr, 1 },
		  { Sizet, 2 },
		  { QuadHex, 3 },
		}
	}, /* pread 475 */
#endif
#ifdef SYS_pwrite
	[SYS_pwrite] = { .name = "pwrite", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { Sizet, 2 },
		  { QuadHex, 3 },
		}
	}, /* pwrite 476 */
#endif
#ifdef SYS_mmap
	[SYS_mmap] = { .name = "mmap", .ret_type = 1, .nargs = 6,
		{ 
		  { IN | Ptr, 0 },
		  { Sizet, 1 },
		  { Int, 2 },
		  { Int, 3 },
		  { Int, 4 },
		  { QuadHex, 5 },
		}
	}, /* mmap 477 */
#endif
#ifdef SYS_lseek
	[SYS_lseek] = { .name = "lseek", .ret_type = 2, .nargs = 3,
		{ 
		  { Int, 0 },
		  { QuadHex, 1 },
		  { Int, 2 },
		}
	}, /* lseek 478 */
#endif
#ifdef SYS_truncate
	[SYS_truncate] = { .name = "truncate", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { QuadHex, 1 },
		}
	}, /* truncate 479 */
#endif
#ifdef SYS_ftruncate
	[SYS_ftruncate] = { .name = "ftruncate", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { QuadHex, 1 },
		}
	}, /* ftruncate 480 */
#endif
#ifdef SYS_thr_kill2
	[SYS_thr_kill2] = { .name = "thr_kill2", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { Long, 1 },
		  { Int, 2 },
		}
	}, /* thr_kill2 481 */
#endif
#ifdef SYS_freebsd12_shm_open
	[SYS_freebsd12_shm_open] = { .name = "freebsd12_shm_open", .ret_type = 1, .nargs = 3,
		{ 
		{ Ptr, 0 },
		{ Int, 1 },
		{ Octal, 2 },
		}
	}, /* freebsd12_shm_open 482 */
#endif
#ifdef SYS_shm_unlink
	[SYS_shm_unlink] = { .name = "shm_unlink", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* shm_unlink 483 */
#endif
#ifdef SYS_cpuset
	[SYS_cpuset] = { .name = "cpuset", .ret_type = 1, .nargs = 1,
		{ 
		  { OUT | Ptr, 0 },
		}
	}, /* cpuset 484 */
#endif
#ifdef SYS_cpuset_setid
	[SYS_cpuset_setid] = { .name = "cpuset_setid", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { QuadHex, 1 },
		  { Int, 2 },
		}
	}, /* cpuset_setid 485 */
#endif
#ifdef SYS_cpuset_getid
	[SYS_cpuset_getid] = { .name = "cpuset_getid", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { QuadHex, 2 },
		  { OUT | Ptr, 3 },
		}
	}, /* cpuset_getid 486 */
#endif
#ifdef SYS_cpuset_getaffinity
	[SYS_cpuset_getaffinity] = { .name = "cpuset_getaffinity", .ret_type = 1, .nargs = 5,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { QuadHex, 2 },
		  { Sizet, 3 },
		  { OUT | Ptr, 4 },
		}
	}, /* cpuset_getaffinity 487 */
#endif
#ifdef SYS_cpuset_setaffinity
	[SYS_cpuset_setaffinity] = { .name = "cpuset_setaffinity", .ret_type = 1, .nargs = 5,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { QuadHex, 2 },
		  { Sizet, 3 },
		  { OUT | Ptr, 4 },
		}
	}, /* cpuset_setaffinity 488 */
#endif
#ifdef SYS_faccessat
	[SYS_faccessat] = { .name = "faccessat", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { Int, 2 },
		  { Int, 3 },
		}
	}, /* faccessat 489 */
#endif
#ifdef SYS_fchmodat
	[SYS_fchmodat] = { .name = "fchmodat", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { Octal, 2 },
		  { Int, 3 },
		}
	}, /* fchmodat 490 */
#endif
#ifdef SYS_fchownat
	[SYS_fchownat] = { .name = "fchownat", .ret_type = 1, .nargs = 5,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { Int, 2 },
		  { Int, 3 },
		  { Int, 4 },
		}
	}, /* fchownat 491 */
#endif
#ifdef SYS_fexecve
	[SYS_fexecve] = { .name = "fexecve", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { IN | Ptr, 2 },
		}
	}, /* fexecve 492 */
#endif
#ifdef SYS_freebsd11_fstatat
	[SYS_freebsd11_fstatat] = { .name = "freebsd11_fstatat", .ret_type = 1, .nargs = 4,
		{ 
		{ Int, 0 },
		{ Ptr, 1 },
		{ Stat11, 2 },
		{ Int, 3 },
		}
	}, /* freebsd11_fstatat 493 */
#endif
#ifdef SYS_futimesat
	[SYS_futimesat] = { .name = "futimesat", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { IN | Timeval, 2 },
		}
	}, /* futimesat 494 */
#endif
#ifdef SYS_linkat
	[SYS_linkat] = { .name = "linkat", .ret_type = 1, .nargs = 5,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { Int, 2 },
		  { IN | Ptr, 3 },
		  { Int, 4 },
		}
	}, /* linkat 495 */
#endif
#ifdef SYS_mkdirat
	[SYS_mkdirat] = { .name = "mkdirat", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { Octal, 2 },
		}
	}, /* mkdirat 496 */
#endif
#ifdef SYS_mkfifoat
	[SYS_mkfifoat] = { .name = "mkfifoat", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { Octal, 2 },
		}
	}, /* mkfifoat 497 */
#endif
#ifdef SYS_freebsd11_mknodat
	[SYS_freebsd11_mknodat] = { .name = "freebsd11_mknodat", .ret_type = 1, .nargs = 4,
		{ 
		{ Int, 0 },
		{ Ptr, 1 },
		{ Octal, 2 },
		{ UInt, 3 },
		}
	}, /* freebsd11_mknodat 498 */
#endif
#ifdef SYS_openat
	[SYS_openat] = { .name = "openat", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { Int, 2 },
		  { Octal, 3 },
		}
	}, /* openat 499 */
#endif
#ifdef SYS_readlinkat
	[SYS_readlinkat] = { .name = "readlinkat", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { OUT | Ptr, 2 },
		  { Sizet, 3 },
		}
	}, /* readlinkat 500 */
#endif
#ifdef SYS_renameat
	[SYS_renameat] = { .name = "renameat", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { Int, 2 },
		  { IN | Ptr, 3 },
		}
	}, /* renameat 501 */
#endif
#ifdef SYS_symlinkat
	[SYS_symlinkat] = { .name = "symlinkat", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { Int, 1 },
		  { IN | Ptr, 2 },
		}
	}, /* symlinkat 502 */
#endif
#ifdef SYS_unlinkat
	[SYS_unlinkat] = { .name = "unlinkat", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { Int, 2 },
		}
	}, /* unlinkat 503 */
#endif
#ifdef SYS_posix_openpt
	[SYS_posix_openpt] = { .name = "posix_openpt", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* posix_openpt 504 */
#endif
#ifdef SYS_gssd_syscall
	[SYS_gssd_syscall] = { .name = "gssd_syscall", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* gssd_syscall 505 */
#endif
#ifdef SYS_jail_get
	[SYS_jail_get] = { .name = "jail_get", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { UInt, 1 },
		  { Int, 2 },
		}
	}, /* jail_get 506 */
#endif
#ifdef SYS_jail_set
	[SYS_jail_set] = { .name = "jail_set", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { UInt, 1 },
		  { Int, 2 },
		}
	}, /* jail_set 507 */
#endif
#ifdef SYS_jail_remove
	[SYS_jail_remove] = { .name = "jail_remove", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* jail_remove 508 */
#endif
#ifdef SYS_freebsd12_closefrom
	[SYS_freebsd12_closefrom] = { .name = "freebsd12_closefrom", .ret_type = 1, .nargs = 1,
		{ 
		{ Int, 0 },
		}
	}, /* freebsd12_closefrom 509 */
#endif
#ifdef SYS___semctl
	[SYS___semctl] = { .name = "__semctl", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { Int, 2 },
		  { IN | OUT | Ptr, 3 },
		}
	}, /* __semctl 510 */
#endif
#ifdef SYS_msgctl
	[SYS_msgctl] = { .name = "msgctl", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { IN | OUT | Ptr, 2 },
		}
	}, /* msgctl 511 */
#endif
#ifdef SYS_shmctl
	[SYS_shmctl] = { .name = "shmctl", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { IN | OUT | Ptr, 2 },
		}
	}, /* shmctl 512 */
#endif
#ifdef SYS_lpathconf
	[SYS_lpathconf] = { .name = "lpathconf", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { Int, 1 },
		}
	}, /* lpathconf 513 */
#endif
#ifdef SYS___cap_rights_get
	[SYS___cap_rights_get] = { .name = "__cap_rights_get", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { OUT | Ptr, 2 },
		}
	}, /* __cap_rights_get 515 */
#endif
#ifdef SYS_cap_enter
	[SYS_cap_enter] = { .name = "cap_enter", .ret_type = 1, .nargs = 0,
	}, /* cap_enter 516 */
#endif
#ifdef SYS_cap_getmode
	[SYS_cap_getmode] = { .name = "cap_getmode", .ret_type = 1, .nargs = 1,
		{ 
		  { OUT | Ptr, 0 },
		}
	}, /* cap_getmode 517 */
#endif
#ifdef SYS_pdfork
	[SYS_pdfork] = { .name = "pdfork", .ret_type = 1, .nargs = 2,
		{ 
		  { OUT | Ptr, 0 },
		  { Int, 1 },
		}
	}, /* pdfork 518 */
#endif
#ifdef SYS_pdkill
	[SYS_pdkill] = { .name = "pdkill", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		}
	}, /* pdkill 519 */
#endif
#ifdef SYS_pdgetpid
	[SYS_pdgetpid] = { .name = "pdgetpid", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { OUT | Ptr, 1 },
		}
	}, /* pdgetpid 520 */
#endif
#ifdef SYS_pselect
	[SYS_pselect] = { .name = "pselect", .ret_type = 1, .nargs = 6,
		{ 
		  { Int, 0 },
		  { IN | OUT | Ptr, 1 },
		  { IN | OUT | Ptr, 2 },
		  { IN | OUT | Ptr, 3 },
		  { IN | Timespec, 4 },
		  { IN | Ptr, 5 },
		}
	}, /* pselect 522 */
#endif
#ifdef SYS_getloginclass
	[SYS_getloginclass] = { .name = "getloginclass", .ret_type = 1, .nargs = 2,
		{ 
		  { OUT | Ptr, 0 },
		  { Sizet, 1 },
		}
	}, /* getloginclass 523 */
#endif
#ifdef SYS_setloginclass
	[SYS_setloginclass] = { .name = "setloginclass", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Ptr, 0 },
		}
	}, /* setloginclass 524 */
#endif
#ifdef SYS_rctl_get_racct
	[SYS_rctl_get_racct] = { .name = "rctl_get_racct", .ret_type = 1, .nargs = 4,
		{ 
		  { IN | Ptr, 0 },
		  { Sizet, 1 },
		  { OUT | Ptr, 2 },
		  { Sizet, 3 },
		}
	}, /* rctl_get_racct 525 */
#endif
#ifdef SYS_rctl_get_rules
	[SYS_rctl_get_rules] = { .name = "rctl_get_rules", .ret_type = 1, .nargs = 4,
		{ 
		  { IN | Ptr, 0 },
		  { Sizet, 1 },
		  { OUT | Ptr, 2 },
		  { Sizet, 3 },
		}
	}, /* rctl_get_rules 526 */
#endif
#ifdef SYS_rctl_get_limits
	[SYS_rctl_get_limits] = { .name = "rctl_get_limits", .ret_type = 1, .nargs = 4,
		{ 
		  { IN | Ptr, 0 },
		  { Sizet, 1 },
		  { OUT | Ptr, 2 },
		  { Sizet, 3 },
		}
	}, /* rctl_get_limits 527 */
#endif
#ifdef SYS_rctl_add_rule
	[SYS_rctl_add_rule] = { .name = "rctl_add_rule", .ret_type = 1, .nargs = 4,
		{ 
		  { IN | Ptr, 0 },
		  { Sizet, 1 },
		  { OUT | Ptr, 2 },
		  { Sizet, 3 },
		}
	}, /* rctl_add_rule 528 */
#endif
#ifdef SYS_rctl_remove_rule
	[SYS_rctl_remove_rule] = { .name = "rctl_remove_rule", .ret_type = 1, .nargs = 4,
		{ 
		  { IN | Ptr, 0 },
		  { Sizet, 1 },
		  { OUT | Ptr, 2 },
		  { Sizet, 3 },
		}
	}, /* rctl_remove_rule 529 */
#endif
#ifdef SYS_posix_fallocate
	[SYS_posix_fallocate] = { .name = "posix_fallocate", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { QuadHex, 1 },
		  { QuadHex, 2 },
		}
	}, /* posix_fallocate 530 */
#endif
#ifdef SYS_posix_fadvise
	[SYS_posix_fadvise] = { .name = "posix_fadvise", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { QuadHex, 1 },
		  { QuadHex, 2 },
		  { Int, 3 },
		}
	}, /* posix_fadvise 531 */
#endif
#ifdef SYS_wait6
	[SYS_wait6] = { .name = "wait6", .ret_type = 1, .nargs = 6,
		{ 
		  { QuadHex, 0 },
		  { QuadHex, 1 },
		  { OUT | Ptr, 2 },
		  { Int, 3 },
		  { OUT | Ptr, 4 },
		  { OUT | Siginfo, 5 },
		}
	}, /* wait6 532 */
#endif
#ifdef SYS_cap_rights_limit
	[SYS_cap_rights_limit] = { .name = "cap_rights_limit", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		}
	}, /* cap_rights_limit 533 */
#endif
#ifdef SYS_cap_ioctls_limit
	[SYS_cap_ioctls_limit] = { .name = "cap_ioctls_limit", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { Sizet, 2 },
		}
	}, /* cap_ioctls_limit 534 */
#endif
#ifdef SYS_cap_ioctls_get
	[SYS_cap_ioctls_get] = { .name = "cap_ioctls_get", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { OUT | Ptr, 1 },
		  { Sizet, 2 },
		}
	}, /* cap_ioctls_get 535 */
#endif
#ifdef SYS_cap_fcntls_limit
	[SYS_cap_fcntls_limit] = { .name = "cap_fcntls_limit", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { UInt, 1 },
		}
	}, /* cap_fcntls_limit 536 */
#endif
#ifdef SYS_cap_fcntls_get
	[SYS_cap_fcntls_get] = { .name = "cap_fcntls_get", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { OUT | Ptr, 1 },
		}
	}, /* cap_fcntls_get 537 */
#endif
#ifdef SYS_bindat
	[SYS_bindat] = { .name = "bindat", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { IN | Sockaddr, 2 },
		  { UInt, 3 },
		}
	}, /* bindat 538 */
#endif
#ifdef SYS_connectat
	[SYS_connectat] = { .name = "connectat", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { IN | Sockaddr, 2 },
		  { UInt, 3 },
		}
	}, /* connectat 539 */
#endif
#ifdef SYS_chflagsat
	[SYS_chflagsat] = { .name = "chflagsat", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { LongHex, 2 },
		  { Int, 3 },
		}
	}, /* chflagsat 540 */
#endif
#ifdef SYS_accept4
	[SYS_accept4] = { .name = "accept4", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { OUT | Sockaddr, 1 },
		  { IN | OUT | Ptr, 2 },
		  { Int, 3 },
		}
	}, /* accept4 541 */
#endif
#ifdef SYS_pipe2
	[SYS_pipe2] = { .name = "pipe2", .ret_type = 1, .nargs = 2,
		{ 
		  { OUT | Ptr, 0 },
		  { Int, 1 },
		}
	}, /* pipe2 542 */
#endif
#ifdef SYS_aio_mlock
	[SYS_aio_mlock] = { .name = "aio_mlock", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | Aiocb, 0 },
		}
	}, /* aio_mlock 543 */
#endif
#ifdef SYS_procctl
	[SYS_procctl] = { .name = "procctl", .ret_type = 1, .nargs = 4,
		{ 
		  { QuadHex, 0 },
		  { QuadHex, 1 },
		  { Int, 2 },
		  { IN | Ptr, 3 },
		}
	}, /* procctl 544 */
#endif
#ifdef SYS_ppoll
	[SYS_ppoll] = { .name = "ppoll", .ret_type = 1, .nargs = 4,
		{ 
		  { IN | OUT | Pollfd, 0 },
		  { UInt, 1 },
		  { IN | Timespec, 2 },
		  { IN | Ptr, 3 },
		}
	}, /* ppoll 545 */
#endif
#ifdef SYS_futimens
	[SYS_futimens] = { .name = "futimens", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { IN | Timespec, 1 },
		}
	}, /* futimens 546 */
#endif
#ifdef SYS_utimensat
	[SYS_utimensat] = { .name = "utimensat", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { IN | Timespec, 2 },
		  { Int, 3 },
		}
	}, /* utimensat 547 */
#endif
#ifdef SYS_fdatasync
	[SYS_fdatasync] = { .name = "fdatasync", .ret_type = 1, .nargs = 1,
		{ 
		  { Int, 0 },
		}
	}, /* fdatasync 550 */
#endif
#ifdef SYS_fstat
	[SYS_fstat] = { .name = "fstat", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { OUT | Stat, 1 },
		}
	}, /* fstat 551 */
#endif
#ifdef SYS_fstatat
	[SYS_fstatat] = { .name = "fstatat", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { OUT | Stat, 2 },
		  { Int, 3 },
		}
	}, /* fstatat 552 */
#endif
#ifdef SYS_fhstat
	[SYS_fhstat] = { .name = "fhstat", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { OUT | Stat, 1 },
		}
	}, /* fhstat 553 */
#endif
#ifdef SYS_getdirentries
	[SYS_getdirentries] = { .name = "getdirentries", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { OUT | Ptr, 1 },
		  { Sizet, 2 },
		  { OUT | Ptr, 3 },
		}
	}, /* getdirentries 554 */
#endif
#ifdef SYS_statfs
	[SYS_statfs] = { .name = "statfs", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { OUT | StatFs, 1 },
		}
	}, /* statfs 555 */
#endif
#ifdef SYS_fstatfs
	[SYS_fstatfs] = { .name = "fstatfs", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { OUT | StatFs, 1 },
		}
	}, /* fstatfs 556 */
#endif
#ifdef SYS_getfsstat
	[SYS_getfsstat] = { .name = "getfsstat", .ret_type = 1, .nargs = 3,
		{ 
		  { OUT | StatFs, 0 },
		  { Long, 1 },
		  { Int, 2 },
		}
	}, /* getfsstat 557 */
#endif
#ifdef SYS_fhstatfs
	[SYS_fhstatfs] = { .name = "fhstatfs", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { OUT | StatFs, 1 },
		}
	}, /* fhstatfs 558 */
#endif
#ifdef SYS_mknodat
	[SYS_mknodat] = { .name = "mknodat", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { Octal, 2 },
		  { QuadHex, 3 },
		}
	}, /* mknodat 559 */
#endif
#ifdef SYS_kevent
	[SYS_kevent] = { .name = "kevent", .ret_type = 1, .nargs = 6,
		{ 
		  { Int, 0 },
		  { IN | Kevent, 1 },
		  { Int, 2 },
		  { OUT | Kevent, 3 },
		  { Int, 4 },
		  { IN | Timespec, 5 },
		}
	}, /* kevent 560 */
#endif
#ifdef SYS_cpuset_getdomain
	[SYS_cpuset_getdomain] = { .name = "cpuset_getdomain", .ret_type = 1, .nargs = 6,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { QuadHex, 2 },
		  { Sizet, 3 },
		  { OUT | Ptr, 4 },
		  { OUT | Ptr, 5 },
		}
	}, /* cpuset_getdomain 561 */
#endif
#ifdef SYS_cpuset_setdomain
	[SYS_cpuset_setdomain] = { .name = "cpuset_setdomain", .ret_type = 1, .nargs = 6,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { QuadHex, 2 },
		  { Sizet, 3 },
		  { IN | Ptr, 4 },
		  { Int, 5 },
		}
	}, /* cpuset_setdomain 562 */
#endif
#ifdef SYS_getrandom
	[SYS_getrandom] = { .name = "getrandom", .ret_type = 1, .nargs = 3,
		{ 
		  { OUT | Ptr, 0 },
		  { Sizet, 1 },
		  { UInt, 2 },
		}
	}, /* getrandom 563 */
#endif
#ifdef SYS_getfhat
	[SYS_getfhat] = { .name = "getfhat", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { OUT | Ptr, 2 },
		  { Int, 3 },
		}
	}, /* getfhat 564 */
#endif
#ifdef SYS_fhlink
	[SYS_fhlink] = { .name = "fhlink", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { IN | Ptr, 1 },
		}
	}, /* fhlink 565 */
#endif
#ifdef SYS_fhlinkat
	[SYS_fhlinkat] = { .name = "fhlinkat", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { Int, 1 },
		  { IN | Ptr, 2 },
		}
	}, /* fhlinkat 566 */
#endif
#ifdef SYS_fhreadlink
	[SYS_fhreadlink] = { .name = "fhreadlink", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { OUT | Ptr, 1 },
		  { Sizet, 2 },
		}
	}, /* fhreadlink 567 */
#endif
#ifdef SYS_funlinkat
	[SYS_funlinkat] = { .name = "funlinkat", .ret_type = 1, .nargs = 4,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { Int, 2 },
		  { Int, 3 },
		}
	}, /* funlinkat 568 */
#endif
#ifdef SYS_copy_file_range
	[SYS_copy_file_range] = { .name = "copy_file_range", .ret_type = 1, .nargs = 6,
		{ 
		  { Int, 0 },
		  { IN | OUT | Ptr, 1 },
		  { Int, 2 },
		  { IN | OUT | Ptr, 3 },
		  { Sizet, 4 },
		  { UInt, 5 },
		}
	}, /* copy_file_range 569 */
#endif
#ifdef SYS___sysctlbyname
	[SYS___sysctlbyname] = { .name = "__sysctlbyname", .ret_type = 1, .nargs = 6,
		{ 
		  { IN | Ptr, 0 },
		  { Sizet, 1 },
		  { OUT | Ptr, 2 },
		  { IN | OUT | Ptr, 3 },
		  { IN | Ptr, 4 },
		  { Sizet, 5 },
		}
	}, /* __sysctlbyname 570 */
#endif
#ifdef SYS_shm_open2
	[SYS_shm_open2] = { .name = "shm_open2", .ret_type = 1, .nargs = 5,
		{ 
		  { IN | Ptr, 0 },
		  { Int, 1 },
		  { Octal, 2 },
		  { Int, 3 },
		  { IN | Ptr, 4 },
		}
	}, /* shm_open2 571 */
#endif
#ifdef SYS_shm_rename
	[SYS_shm_rename] = { .name = "shm_rename", .ret_type = 1, .nargs = 3,
		{ 
		  { IN | Ptr, 0 },
		  { IN | Ptr, 1 },
		  { Int, 2 },
		}
	}, /* shm_rename 572 */
#endif
#ifdef SYS_sigfastblock
	[SYS_sigfastblock] = { .name = "sigfastblock", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { IN | OUT | Ptr, 1 },
		}
	}, /* sigfastblock 573 */
#endif
#ifdef SYS___realpathat
	[SYS___realpathat] = { .name = "__realpathat", .ret_type = 1, .nargs = 5,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { OUT | Ptr, 2 },
		  { Sizet, 3 },
		  { Int, 4 },
		}
	}, /* __realpathat 574 */
#endif
#ifdef SYS_close_range
	[SYS_close_range] = { .name = "close_range", .ret_type = 1, .nargs = 3,
		{ 
		  { UInt, 0 },
		  { UInt, 1 },
		  { Int, 2 },
		}
	}, /* close_range 575 */
#endif
#ifdef SYS_rpctls_syscall
	[SYS_rpctls_syscall] = { .name = "rpctls_syscall", .ret_type = 1, .nargs = 2,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		}
	}, /* rpctls_syscall 576 */
#endif
#ifdef SYS___specialfd
	[SYS___specialfd] = { .name = "__specialfd", .ret_type = 1, .nargs = 3,
		{ 
		  { Int, 0 },
		  { IN | Ptr, 1 },
		  { Sizet, 2 },
		}
	}, /* __specialfd 577 */
#endif
#ifdef SYS_aio_writev
	[SYS_aio_writev] = { .name = "aio_writev", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | OUT | Aiocb, 0 },
		}
	}, /* aio_writev 578 */
#endif
#ifdef SYS_aio_readv
	[SYS_aio_readv] = { .name = "aio_readv", .ret_type = 1, .nargs = 1,
		{ 
		  { IN | OUT | Aiocb, 0 },
		}
	}, /* aio_readv 579 */
#endif
#ifdef SYS_fspacectl
	[SYS_fspacectl] = { .name = "fspacectl", .ret_type = 1, .nargs = 5,
		{ 
		  { Int, 0 },
		  { Int, 1 },
		  { IN | Ptr, 2 },
		  { Int, 3 },
		  { OUT | Ptr, 4 },
		}
	}, /* fspacectl 580 */
#endif
#ifdef SYS_sched_getcpu
	[SYS_sched_getcpu] = { .name = "sched_getcpu", .ret_type = 1, .nargs = 0,
	}, /* sched_getcpu 581 */
#endif
#ifdef SYS_swapoff
	[SYS_swapoff] = { .name = "swapoff", .ret_type = 1, .nargs = 2,
		{ 
		  { IN | Ptr, 0 },
		  { UInt, 1 },
		}
	}, /* swapoff 582 */
#endif
#ifdef SYS_kqueue1
	[SYS_kqueue1] = { .name = "kqueue1", .ret_type = 1, .nargs = 1,
		{ 
		  { UInt, 0 },
		}
	}, /* kqueue1 583 */
#endif
};

#endif /* _SYS_SYSTRUSS_H_ */
