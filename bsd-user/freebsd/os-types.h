/*
 * Copyright (c) 2026 Warner Losh <imp@bsdimp.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Target types for system calls
 */

/* Long list of types from sys/_types.h XXX generate long term */
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
typedef int32_t target_time_t;
#else
typedef int64_t target_time_t;
#endif
typedef abi_long target_intptr_t;
typedef abi_ulong target_uintptr_t;
typedef abi_long target_caddr_t;
typedef abi_long target_semid_t;
typedef abi_int target_idtype_t;	/* really enum, yikes! */
typedef	abi_ulong target_size_t;
typedef	abi_long target_ssize_t;
typedef	int32_t target_blksize_t;	/* file block size */
typedef	int64_t target_blkcnt_t;	/* file block count */
typedef	int32_t target_clockid_t;	/* clock_gettime()... */
typedef	uint32_t target_fflags_t;	/* file flags */
typedef	uint64_t target_fsblkcnt_t;
typedef	uint64_t target_fsfilcnt_t;
typedef	uint32_t target_gid_t;
typedef	int64_t target_id_t;		/* can hold a gid_t, pid_t, or uid_t */
typedef	uint64_t target_ino_t;	/* inode number */
typedef	abi_long target_key_t;	/* IPC key (for Sys V IPC) */
typedef	int32_t	target_lwpid_t;	/* Thread ID (a.k.a. LWP) */
typedef	uint16_t target_mode_t;	/* permissions */
typedef	abi_int target_accmode_t;	/* access permissions */
typedef	abi_int target_nl_item;
typedef	uint64_t target_nlink_t;	/* link count */
typedef	int64_t	target_off_t;	/* file offset */
typedef	int64_t	target_off64_t;	/* file offset (alias) */
typedef	int32_t	target_pid_t;	/* process [group] */
typedef	int64_t	target_sbintime_t;
typedef	int64_t	target_rlim_t;	/* resource limit - intentionally */
					/* signed, because of legacy code */
					/* that uses -1 for RLIM_INFINITY */
typedef	uint8_t target_sa_family_t;
typedef	uint32_t target_socklen_t;
typedef	uint32_t target___socklen_t;
typedef	abi_long target_suseconds_t;	/* microseconds (signed) */
typedef	abi_long target_timer_t;	/* timer_gettime()... */
typedef	abi_long target_mqd_t;	/* mq_open()... */
typedef	uint32_t target_uid_t;
typedef	abi_ulong target_useconds_t;	/* microseconds (unsigned) */
typedef	abi_int target_cpuwhich_t;	/* which parameter for cpuset. */
typedef	abi_int target_cpulevel_t;	/* level parameter for cpuset. */
typedef abi_int target_cpusetid_t;	/* cpuset identifier. */
typedef int64_t target_daddr_t;	/* bwrite(3), FIOBMAP2, etc */
/* Types for sys/acl.h */
typedef uint32_t target___acl_tag_t;
typedef uint32_t target___acl_perm_t;
typedef uint16_t target___acl_entry_type_t;
typedef uint16_t target___acl_flag_t;
typedef uint32_t target___acl_type_t;
typedef abi_long target___acl_permset_t;
typedef abi_long target___acl_flagset_t;

typedef	uint64_t target_dev_t;	/* device number */

typedef	uint32_t target_fixpt_t;	/* fixed point number */
