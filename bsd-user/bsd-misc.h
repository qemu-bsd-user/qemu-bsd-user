/*
 *  miscellaneous BSD system call shims
 *
 *  Copyright (c) 2013 Stacey D. Son
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

#ifndef BSD_MISC_H
#define BSD_MISC_H

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/uuid.h>

#include "qemu-bsd.h"

#ifdef MSGMAX
static int bsd_msgmax = MSGMAX;
#else
static int bsd_msgmax;
#endif

/* quotactl(2) */
static inline abi_long do_bsd_quotactl(abi_ulong path, abi_long cmd,
        __unused abi_ulong target_addr)
{
    qemu_log("qemu: Unsupported syscall quotactl()\n");
    return -TARGET_ENOSYS;
}

/* reboot(2) */
static inline abi_long do_bsd_reboot(abi_long how)
{
    qemu_log("qemu: Unsupported syscall reboot()\n");
    return -TARGET_ENOSYS;
}

/* uuidgen(2) */
static inline abi_long do_bsd_uuidgen(abi_ulong target_addr, int count)
{
    int i;
    abi_long ret;
    g_autofree struct uuid *host_uuid;
    struct target_uuid *target_uuid;

    if (count < 1 || count > 2048) {
        return -TARGET_EINVAL;
    }

    WITH_LOCK (target_uuid, VERIFY_WRITE, target_addr,
               count * sizeof(struct target_uuid)) {
        if (target_uuid == NULL) {
            return -TARGET_EFAULT;
        }

        host_uuid = g_try_new(struct uuid, count);
        if (host_uuid == NULL) {
            UNLOCK(target_uuid);
            return -TARGET_ENOMEM;
        }

        ret = get_errno(uuidgen(host_uuid, count));
        if (!ret) {
            for (i = 0; i < count; i++) {
                host_to_target_uuid(&target_uuid[i], &host_uuid[i]);
            }
        }
    }

    return ret;
}


/*
 * System V Semaphores
 */

/* semget(2) */
static inline abi_long do_bsd_semget(abi_long key, int nsems,
        int target_flags)
{
    return get_errno(semget(key, nsems,
                target_to_host_bitmask(target_flags, ipc_flags_tbl)));
}

/* semop(2) */
static inline abi_long do_bsd_semop(int semid, abi_long ptr, unsigned nsops)
{
    g_autofree struct sembuf *sops;
    struct target_sembuf *target_sembuf;
    abi_long ret;
    int i;

    sops = g_try_new(struct sembuf, nsops);

    WITH_LOCK (target_sembuf, VERIFY_READ, ptr,
               nsops * sizeof(struct target_sembuf)) {
        if (target_sembuf == NULL) {
            return -TARGET_EFAULT;
        }
        for (i = 0; i < nsops; i++) {
            __get_user(sops[i].sem_num, &target_sembuf[i].sem_num);
            __get_user(sops[i].sem_op, &target_sembuf[i].sem_op);
            __get_user(sops[i].sem_flg, &target_sembuf[i].sem_flg);
        }
        ret = get_errno(semop(semid, sops, nsops));
    }
    return ret;
}

/* __semctl(2) */
static inline abi_long do_bsd___semctl(int semid, int semnum, int cmd,
                                       union target_semun target_su)
{
    union semun arg;
    struct semid_ds dsarg;
    struct target_semid_ds *target_sd;
    g_autofree unsigned short *host_array = NULL;
    unsigned short *target_array = NULL;
    int nsems;
    abi_long ret = 0;

    switch (cmd) {
    case GETALL:
        nsems = semarray_length(semid);
        if (nsems == -1) {
            return get_errno(nsems);
        }
        WITH_LOCK(target_array, VERIFY_WRITE, target_su.array,
                  nsems * sizeof(unsigned short)) {
            if (target_array == NULL) {
                return -TARGET_EFAULT;
            }
            host_array = g_try_new(unsigned short, nsems);
            arg.array = host_array;

            ret = get_errno(semctl(semid, semnum, cmd, arg));
            host_to_target_semarray(target_array, host_array, nsems);
        }
        break;

    case SETALL:
        nsems = semarray_length(semid);
        if (nsems == -1) {
            return get_errno(nsems);
        }
        WITH_LOCK (target_array, VERIFY_READ, target_su.array,
                   nsems * sizeof(unsigned short)) {
            if (target_array == NULL) {
                return -TARGET_EFAULT;
            }
            host_array = g_try_new(unsigned short, nsems);
            arg.array = host_array;

            target_to_host_semarray(host_array, target_array, nsems);
            ret = get_errno(semctl(semid, semnum, cmd, arg));
        }
        break;

    case IPC_STAT:
        WITH_LOCK (target_sd, VERIFY_WRITE, target_su.buf) {
            if (target_sd == NULL) {
                return -TARGET_EFAULT;
            }
            arg.buf = &dsarg;

            ret = get_errno(semctl(semid, semnum, cmd, arg));
            host_to_target_semid_ds(target_sd, &dsarg);
        }
        break;

    case IPC_SET:
        WITH_LOCK (target_sd, VERIFY_READ, target_su.buf) {
            if (target_sd == NULL) {
                return -TARGET_EFAULT;
            }
            arg.buf = &dsarg;

            target_to_host_semid_ds(&dsarg, target_sd);
            ret = get_errno(semctl(semid, semnum, cmd, arg));
        }
        break;

    case SETVAL:
        __get_user(arg.val, &target_su.val);
        ret = get_errno(semctl(semid, semnum, cmd, arg));
        break;

    case IPC_RMID:
    case GETVAL:
    case GETPID:
    case GETNCNT:
    case GETZCNT:
        ret = get_errno(semctl(semid, semnum, cmd, NULL));
        break;

    default:
        ret = -TARGET_EINVAL;
        break;
    }
    return ret;
}

/* msgctl(2) */
static inline abi_long do_bsd_msgctl(int msgid, int cmd, abi_long ptr)
{
    struct msqid_ds dsarg;
    struct target_msqid_ds *target_md;
    abi_long ret = -TARGET_EINVAL;

    switch (cmd) {
    case IPC_STAT:
        WITH_LOCK (target_md, VERIFY_WRITE, ptr) {
            if (target_md == NULL) {
                return -TARGET_EFAULT;
            }

            ret = get_errno(msgctl(msgid, cmd, &dsarg));
            host_to_target_msqid_ds(target_md, &dsarg);
        }
        break;

    case IPC_SET:
        WITH_LOCK (target_md, VERIFY_READ, ptr) {
            if (target_md == NULL) {
                return -TARGET_EFAULT;
            }

            target_to_host_msqid_ds(&dsarg, target_md);
            ret = get_errno(msgctl(msgid, cmd, &dsarg));
        }
        break;

    case IPC_RMID:
        ret = get_errno(msgctl(msgid, cmd, NULL));
        break;

    default:
        ret = -TARGET_EINVAL;
        break;
    }
    return ret;
}

struct kern_mymsg {
    long mtype;
    char mtext[1];
};

static inline abi_long bsd_validate_msgsz(abi_ulong msgsz)
{
    /* Fetch msgmax the first time we need it. */
    if (bsd_msgmax == 0) {
        size_t len = sizeof(bsd_msgmax);

        if (sysctlbyname("kern.ipc.msgmax", &bsd_msgmax, &len, NULL, 0) == -1) {
            return -TARGET_EINVAL;
        }
    }

    if (msgsz > bsd_msgmax) {
        return -TARGET_EINVAL;
    }
    return 0;
}

/* msgsnd(2) */
static inline abi_long do_bsd_msgsnd(int msqid, abi_long msgp,
        abi_ulong msgsz, int msgflg)
{
    struct target_msgbuf *target_mb;
    g_autofree struct kern_mymsg *host_mb;
    abi_long ret;

    ret = bsd_validate_msgsz(msgsz);
    if (is_error(ret)) {
        return ret;
    }
    WITH_LOCK (target_mb, VERIFY_READ, msgp) {
        if (target_mb) {
            return -TARGET_EFAULT;
        }
        host_mb = (struct kern_mymsg *) g_try_new(char, msgsz + sizeof(long));

        __get_user(host_mb->mtype, &target_mb->mtype);
        memcpy(host_mb->mtext, target_mb->mtext, msgsz);

        ret = get_errno(msgsnd(msqid, host_mb, msgsz, msgflg));
    }
    return ret;
}

/* msgget(2) */
static inline abi_long do_bsd_msgget(abi_long key, abi_long msgflag)
{
    abi_long ret;

    ret = get_errno(msgget(key, msgflag));
    return ret;
}

/* msgrcv(2) */
static inline abi_long do_bsd_msgrcv(int msqid, abi_long msgp,
        abi_ulong msgsz, abi_long msgtyp, int msgflg)
{
    struct target_msgbuf *target_mb = NULL;
    char *target_mtext;
    g_autofree struct kern_mymsg *host_mb;
    abi_long ret = 0;

    ret = bsd_validate_msgsz(msgsz);
    if (is_error(ret)) {
        return ret;
    }

    WITH_LOCK (target_mb, VERIFY_WRITE, msgp) {
        if (target_mb == NULL) {
            return -TARGET_EFAULT;
        }
        host_mb = (struct kern_mymsg *) g_try_new(char, msgsz + sizeof(long));

        ret = get_errno(msgrcv(msqid, host_mb, msgsz, tswapal(msgtyp), msgflg));
        if (!is_error(ret)) {
            target_mb->mtype = tswapal(host_mb->mtype);
        }
        if (ret > 0) {
            WITH_LOCK(target_mtext, VERIFY_WRITE, msgp + sizeof(abi_ulong),
                      ret) {
                if (target_mtext == NULL) {
                    UNLOCK(target_mb);
                    return -TARGET_EFAULT;
                }
                memcpy(target_mb->mtext, host_mb->mtext, ret);
            }
        }
    }

    return ret;
}

/* getdtablesize(2) */
static inline abi_long do_bsd_getdtablesize(void)
{
    return get_errno(getdtablesize());
}

#endif /* BSD_MISC_H */
