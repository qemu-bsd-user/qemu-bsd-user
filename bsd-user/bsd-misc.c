/*
 *  BSD misc system call conversions routines
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
#include "qemu/osdep.h"

#define _WANT_SEMUN
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/uuid.h>

#include "qemu.h"
#include "qemu-bsd.h"

/*
 * BSD uuidgen(2) struct uuid conversion
 */
void host_to_target_uuid(struct target_uuid *target_uuid,
                         struct uuid *host_uuid)
{
    __put_user(host_uuid->time_low, &target_uuid->time_low);
    __put_user(host_uuid->time_mid, &target_uuid->time_mid);
    __put_user(host_uuid->time_hi_and_version,
               &target_uuid->time_hi_and_version);
    host_uuid->clock_seq_hi_and_reserved =
        target_uuid->clock_seq_hi_and_reserved;
    host_uuid->clock_seq_low = target_uuid->clock_seq_low;
    memcpy(host_uuid->node, target_uuid->node, TARGET_UUID_NODE_LEN);
}

void target_to_host_semarray(unsigned short *host_array,
                             unsigned short *target_array,
                             int nsems)
{
    for (int i = 0; i < nsems; i++) {
        __get_user(host_array[i], &target_array[i]);
    }
}

void host_to_target_semarray(unsigned short *target_array,
                             unsigned short *host_array,
                             int nsems)
{
    for (int i = 0; i < nsems; i++) {
        __put_user(host_array[i], &target_array[i]);
    }
}

void target_to_host_semid_ds(struct semid_ds *host_sd,
                             struct target_semid_ds *target_sd)
{
    target_to_host_ipc_perm(&host_sd->sem_perm, &target_sd->sem_perm);
    /* sem_base is not used by kernel for IPC_STAT/IPC_SET */
    /* host_sd->sem_base  = g2h_untagged(target_sd->sem_base); */
    __get_user(host_sd->sem_nsems, &target_sd->sem_nsems);
    __get_user(host_sd->sem_otime, &target_sd->sem_otime);
    __get_user(host_sd->sem_ctime, &target_sd->sem_ctime);
}

void host_to_target_semid_ds(struct target_semid_ds *target_sd,
                             struct semid_ds *host_sd)
{
    host_to_target_ipc_perm(&target_sd->sem_perm, &host_sd->sem_perm);
    /* sem_base is not used by kernel for IPC_STAT/IPC_SET */
    /* target_sd->sem_base = h2g((void *)host_sd->sem_base); */
    __put_user(host_sd->sem_nsems, &target_sd->sem_nsems);
    __put_user(host_sd->sem_otime, &target_sd->sem_otime);
    __put_user(host_sd->sem_ctime, &target_sd->sem_ctime);
}

void target_to_host_msqid_ds(struct msqid_ds *host_md,
                             struct target_msqid_ds *target_md)
{
    memset(host_md, 0, sizeof(struct msqid_ds));
    target_to_host_ipc_perm(&host_md->msg_perm, &target_md->msg_perm);
    /* msg_first and msg_last are not used by IPC_SET/IPC_STAT in kernel. */
    __get_user(host_md->msg_cbytes, &target_md->msg_cbytes);
    __get_user(host_md->msg_qnum,   &target_md->msg_qnum);
    __get_user(host_md->msg_qbytes, &target_md->msg_qbytes);
    __get_user(host_md->msg_lspid,  &target_md->msg_lspid);
    __get_user(host_md->msg_lrpid,  &target_md->msg_lrpid);
    __get_user(host_md->msg_stime,  &target_md->msg_stime);
    __get_user(host_md->msg_rtime,  &target_md->msg_rtime);
    __get_user(host_md->msg_ctime,  &target_md->msg_ctime);
}

void host_to_target_msqid_ds(struct target_msqid_ds *target_md,
                             struct msqid_ds *host_md)
{
    memset(target_md, 0, sizeof(struct target_msqid_ds));
    host_to_target_ipc_perm(&target_md->msg_perm, &host_md->msg_perm);
    /* msg_first and msg_last are not used by IPC_SET/IPC_STAT in kernel. */
    __put_user(host_md->msg_cbytes, &target_md->msg_cbytes);
    __put_user(host_md->msg_qnum,   &target_md->msg_qnum);
    __put_user(host_md->msg_qbytes, &target_md->msg_qbytes);
    __put_user(host_md->msg_lspid,  &target_md->msg_lspid);
    __put_user(host_md->msg_lrpid,  &target_md->msg_lrpid);
    __put_user(host_md->msg_stime,  &target_md->msg_stime);
    __put_user(host_md->msg_rtime,  &target_md->msg_rtime);
    __put_user(host_md->msg_ctime,  &target_md->msg_ctime);
}

int semarray_length(int semid) {
    int err;
    union semun semun;
    struct semid_ds semid_ds;

    semun.buf = &semid_ds;
    err = semctl(semid, 0, IPC_STAT, semun);
    if (!err) {
        return semid_ds.sem_nsems;
    }
    return -1;
}

