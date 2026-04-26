/*
 * process related system call shims and definitions
 *
 * Copyright (c) 2013-2014 Stacey D. Son
 * Copyright (c) 2026 Warner Losh <imp@bsdimp.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu.h"
#include "gdbstub/syscalls.h"
#include "qemu/plugin.h"

#include "special-syscall.h"

#include "os-types.h"
#include "os-sysproto.h"

/* exit(2) */
abi_long do_custom__exit(const os_syscall_args_t *sa)
{
    struct target__exit_args *uap = (struct target__exit_args *)sa->args;

    gdb_exit(uap->rval);
    qemu_plugin_user_exit();
    _exit(uap->rval);

    return 0;
}

abi_long do_custom_break(const os_syscall_args_t *sa)
{
    return -ENOSYS;
}

abi_long do_custom_execve(const os_syscall_args_t *sa)
{
    return -ENOSYS;
}

abi_long do_custom_fexecve(const os_syscall_args_t *sa)
{
    return -ENOSYS;
}

abi_long do_custom___mac_execve(const os_syscall_args_t *sa)
{
    return -ENOSYS;
}

abi_long do_custom_vfork(const os_syscall_args_t *sa)
{
    return -ENOSYS;
}
