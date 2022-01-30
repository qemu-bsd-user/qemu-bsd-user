/*
 *  BSD syscalls
 *
 *  Copyright (c) 2003 - 2008 Fabrice Bellard
 *  Copyright (c) 2013-14 Stacey D. Son
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "qemu/path.h"
#include <sys/syscall.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <utime.h>

#include "qemu.h"
#include "qemu-common.h"
#include "signal-common.h"
#include "user/syscall-trace.h"

#define target_to_host_bitmask(x, tbl) (x)

/* BSD independent syscall shims */
#include "bsd-file.h"
#include "bsd-ioctl.h"
#include "bsd-mem.h"
#include "bsd-misc.h"
#include "bsd-proc.h"
#include "bsd-signal.h"
#include "bsd-socket.h"

/* *BSD dependent syscall shims */
#include "os-extattr.h"
#include "os-file.h"
#include "os-time.h"
#include "os-misc.h"
#include "os-proc.h"
#include "os-signal.h"
#include "os-socket.h"
#include "os-stat.h"
#include "os-thread.h"

/* #define DEBUG */
/* Used in os-thread */
safe_syscall1(int, thr_suspend, struct timespec *, timeout);
safe_syscall5(int, _umtx_op, void *, obj, int, op, unsigned long, val, void *,
    uaddr, void *, uaddr2);

/* used in os-time */
safe_syscall2(int, nanosleep, const struct timespec *, rqtp, struct timespec *,
    rmtp);
safe_syscall4(int, clock_nanosleep, clockid_t, clock_id, int, flags,
    const struct timespec *, rqtp, struct timespec *, rmtp);

safe_syscall6(int, kevent, int, kq, const struct kevent *, changelist,
    int, nchanges, struct kevent *, eventlist, int, nevents,
    const struct timespec *, timeout);

/* used in os-proc */
safe_syscall4(pid_t, wait4, pid_t, wpid, int *, status, int, options,
    struct rusage *, rusage);
safe_syscall6(pid_t, wait6, idtype_t, idtype, id_t, id, int *, status, int,
    options, struct __wrusage *, wrusage, siginfo_t *, infop);

/* I/O */
safe_syscall3(int, open, const char *, path, int, flags, mode_t, mode);
safe_syscall4(int, openat, int, fd, const char *, path, int, flags, mode_t,
    mode);

safe_syscall3(ssize_t, read, int, fd, void *, buf, size_t, nbytes);
safe_syscall4(ssize_t, pread, int, fd, void *, buf, size_t, nbytes, off_t,
    offset);
safe_syscall3(ssize_t, readv, int, fd, const struct iovec *, iov, int, iovcnt);
safe_syscall4(ssize_t, preadv, int, fd, const struct iovec *, iov, int, iovcnt,
    off_t, offset);

safe_syscall3(ssize_t, write, int, fd, void *, buf, size_t, nbytes);
safe_syscall4(ssize_t, pwrite, int, fd, void *, buf, size_t, nbytes, off_t,
    offset);
safe_syscall3(ssize_t, writev, int, fd, const struct iovec *, iov, int, iovcnt);
safe_syscall4(ssize_t, pwritev, int, fd, const struct iovec *, iov, int, iovcnt,
    off_t, offset);

safe_syscall5(int, select, int, nfds, fd_set *, readfs, fd_set *, writefds,
    fd_set *, exceptfds, struct timeval *, timeout);
safe_syscall6(int, pselect, int, nfds, fd_set * restrict, readfs,
    fd_set * restrict, writefds, fd_set * restrict, exceptfds,
    const struct timespec * restrict, timeout,
    const sigset_t * restrict, newsigmask);

safe_syscall6(ssize_t, recvfrom, int, fd, void *, buf, size_t, len, int, flags,
    struct sockaddr * restrict, from, socklen_t * restrict, fromlen);
safe_syscall6(ssize_t, sendto, int, fd, const void *, buf, size_t, len, int,
    flags, const struct sockaddr *, to, socklen_t, tolen);
safe_syscall3(ssize_t, recvmsg, int, s, struct msghdr *, msg, int, flags);
safe_syscall3(ssize_t, sendmsg, int, s, const struct msghdr *, msg, int, flags);

#if defined(__FreeBSD_version) && __FreeBSD_version >= 1300133
safe_syscall6(ssize_t, copy_file_range, int, infd, off_t *, inoffp, int, outfd,
    off_t *, outoffp, size_t, len, unsigned int, flags);
#endif

int g_posix_timers[32] = { 0, } ;

/*
 * errno conversion.
 */
abi_long get_errno(abi_long ret)
{

    if (ret == -1) {
        /* XXX need to translate host -> target errnos here */
        return -host_to_target_errno(errno);
    } else {
        return ret;
    }
}

int host_to_target_errno(int err)
{
    /* XXX need to translate host errnos here */
    return err;
}

bool is_error(abi_long ret)
{

    return (abi_ulong)ret >= (abi_ulong)(-4096);
}

struct iovec *lock_iovec(int type, abi_ulong target_addr,
        int count, int copy)
{
    struct target_iovec *target_vec;
    struct iovec *vec;
    abi_ulong total_len, max_len;
    int i;
    int err = 0;
    bool bad_address = false;

    if (count == 0) {
        errno = 0;
        return NULL;
    }
    if (count < 0 || count > IOV_MAX) {
        errno = EINVAL;
        return NULL;
    }

    vec = calloc(count, sizeof(struct iovec));
    if (vec == NULL) {
        errno = ENOMEM;
        return NULL;
    }

    target_vec = lock_user(VERIFY_READ, target_addr,
                           count * sizeof(struct target_iovec), 1);
    if (target_vec == NULL) {
        err = EFAULT;
        goto fail2;
    }

    /* ??? If host page size > target page size, this will result in a
       value larger than what we can actually support.  */
    max_len = 0x7fffffff & TARGET_PAGE_MASK;
    total_len = 0;

    for (i = 0; i < count; i++) {
        abi_ulong base = tswapal(target_vec[i].iov_base);
        abi_long len = tswapal(target_vec[i].iov_len);

        if (len < 0) {
            err = EINVAL;
            goto fail;
        } else if (len == 0) {
            /* Zero length pointer is ignored.  */
            vec[i].iov_base = 0;
        } else {
            vec[i].iov_base = lock_user(type, base, len, copy);
            /* If the first buffer pointer is bad, this is a fault.  But
             * subsequent bad buffers will result in a partial write; this
             * is realized by filling the vector with null pointers and
             * zero lengths. */
            if (!vec[i].iov_base) {
                if (i == 0) {
                    err = EFAULT;
                    goto fail;
                } else {
                    bad_address = true;
                }
            }
            if (bad_address) {
                len = 0;
            }
            if (len > max_len - total_len) {
                len = max_len - total_len;
            }
        }
        vec[i].iov_len = len;
        total_len += len;
    }

    unlock_user(target_vec, target_addr, 0);
    return vec;

 fail:
    while (--i >= 0) {
        if (tswapal(target_vec[i].iov_len) > 0) {
            unlock_user(vec[i].iov_base, tswapal(target_vec[i].iov_base), 0);
        }
    }
    unlock_user(target_vec, target_addr, 0);
 fail2:
    free(vec);
    errno = err;
    return NULL;
}

void unlock_iovec(struct iovec *vec, abi_ulong target_addr,
        int count, int copy)
{
    struct target_iovec *target_vec;
    int i;

    target_vec = lock_user(VERIFY_READ, target_addr,
                           count * sizeof(struct target_iovec), 1);
    if (target_vec) {
        for (i = 0; i < count; i++) {
            abi_ulong base = tswapal(target_vec[i].iov_base);
            abi_long len = tswapal(target_vec[i].iov_len);
            if (len < 0) {
                break;
            }
            unlock_user(vec[i].iov_base, base, copy ? vec[i].iov_len : 0);
        }
        unlock_user(target_vec, target_addr, 0);
    }

    free(vec);
}


/* stub for arm semihosting support */
abi_long do_brk(abi_ulong new_brk)
{
    return do_obreak(new_brk);
}

abi_long do_openbsd_syscall(void *cpu_env, int num, abi_long arg1,
                            abi_long arg2, abi_long arg3, abi_long arg4,
                            abi_long arg5, abi_long arg6)
{
    CPUState *cpu = env_cpu(cpu_env);
    abi_long ret;

#ifdef DEBUG
    gemu_log("openbsd syscall %d\n", num);
#endif
    trace_guest_user_syscall(cpu, num, arg1, arg2, arg3, arg4, arg5, arg6, 0, 0);
    if (do_strace) {
        print_openbsd_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6);
    }

    switch (num) {
    case TARGET_OPENBSD_NR_exit:
        ret = do_bsd_exit(cpu_env, arg1);
        break;

    case TARGET_OPENBSD_NR_read:
        ret = do_bsd_read(arg1, arg2, arg3);
        break;
    case TARGET_OPENBSD_NR_write:
        ret = do_bsd_write(arg1, arg2, arg3);
        break;
    case TARGET_OPENBSD_NR_open:
        ret = do_bsd_open(arg1, arg2, arg3);
        break;

    case TARGET_OPENBSD_NR_mmap:
        ret = do_bsd_mmap(cpu_env, arg1, arg2, arg3, arg4, arg5, arg6, 0, 0);
        break;
    case TARGET_OPENBSD_NR_mprotect:
        ret = do_bsd_mprotect(arg1, arg2, arg3);
        break;

    case TARGET_OPENBSD_NR_syscall:
    case TARGET_OPENBSD_NR___syscall:
        ret = do_openbsd_syscall(cpu_env,arg1 & 0xffff,arg2,arg3,arg4,arg5,arg6,0);
        break;
    default:
        ret = syscall(num, arg1, arg2, arg3, arg4, arg5, arg6);
        break;
    }
#ifdef DEBUG
    gemu_log(" = %ld\n", ret);
#endif
    if (do_strace)
        print_openbsd_syscall_ret(num, ret);
    trace_guest_user_syscall_ret(cpu, num, ret);
    return ret;
}

void syscall_init(void)
{

    init_bsd_ioctl();
}
