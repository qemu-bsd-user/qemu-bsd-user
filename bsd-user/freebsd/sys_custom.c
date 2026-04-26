/*
 * process related system call shims and definitions
 *
 * Copyright (c) 2026 Warner Losh <imp@bsdimp.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu.h"

#include "special-syscall.h"

abi_long do_custom__exit(const os_syscall_args_t *sa)
{
    return -ENOSYS;
}

abi_long do_custom_fork(const os_syscall_args_t *sa)
{
    return -ENOSYS;
}

abi_long do_custom_vfork(const os_syscall_args_t *sa)
{
    return -ENOSYS;
}
