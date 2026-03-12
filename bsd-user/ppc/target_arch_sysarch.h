/*
 *  powerpc cpu init and loop
 *
 * Copyright (c) 2014 Justin Hibbits
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TARGET_ARCH_SYSARCH_H
#define TARGET_ARCH_SYSARCH_H

static inline abi_long do_freebsd_arch_sysarch(CPUPPCState *env, int op,
        abi_ulong parms)
{
    int ret = -TARGET_EINVAL;

    return ret;
}

static inline void do_freebsd_arch_print_sysarch(
        const struct syscallname *name, abi_long arg1, abi_long arg2,
        abi_long arg3, abi_long arg4, abi_long arg5, abi_long arg6)
{
	gemu_log("UNKNOWN OP: %d, " TARGET_ABI_FMT_lx ")", (int)arg1, arg2);
}
#endif
