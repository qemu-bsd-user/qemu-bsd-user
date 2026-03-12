/*
 * powerpc VM parameters definitions
 *
 * Copyright (c) 2014 Justin Hibbits
 * Copyright (c) 2021-2022 Warner Losh
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TARGET_ARCH_VMPARAM_H
#define TARGET_ARCH_VMPARAM_H

#include "cpu.h"

/* compare to sys/powerpc/include/vmparam.h */
#define TARGET_MAXTSIZ      (64 * MiB)          /* max text size */
#define TARGET_DFLDSIZ      (128 * MiB)         /* initial data size limit */
#define TARGET_MAXDSIZ      (1 * GiB)           /* max data size */
#define TARGET_DFLSSIZ      (8 * MiB)           /* initial stack size limit */
#define TARGET_MAXSSIZ      (64 * MiB)          /* max stack size */
#define TARGET_SGROWSIZ     (128 * KiB)         /* amount to grow stack */

#ifndef TARGET_PPC64
#define TARGET_RESERVED_VA  0xfffff000
#endif

                /* KERNBASE - 512 MB */
#if defined(TARGET_PPC64) && !defined(TARGET_ABI32)
#define TARGET_VM_MAXUSER_ADDRESS	0x00007fffff000000ULL
#else
#define TARGET_VM_MAXUSER_ADDRESS   0xfffff000UL
#endif
#define TARGET_USRSTACK             (TARGET_VM_MAXUSER_ADDRESS - TARGET_PAGE_SIZE * 0x10)

static inline abi_ulong get_sp_from_cpustate(CPUPPCState *state)
{
    return state->gpr[1]; /* sp */
}

static inline void set_second_rval(CPUPPCState *state, abi_ulong retval2)
{
    state->gpr[4] = retval2;
}

static inline abi_ulong get_second_rval(CPUPPCState *state)
{
    return state->gpr[4];
}

#endif /* TARGET_ARCH_VMPARAM_H */
