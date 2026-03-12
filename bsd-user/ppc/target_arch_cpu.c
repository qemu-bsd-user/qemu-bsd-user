/*
 * powerpc cpu related code
 *
 * Copyright (c) 2014 Justin Hibbits
 * Copyright (c) 2019 Brandon Bergren
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"

#include "target_arch.h"

static inline uint64_t cpu_ppc_get_tb(CPUPPCState *env)
{
    /* TO FIX */
    return 0;
}

uint64_t cpu_ppc_load_tbl(CPUPPCState *env)
{
    return cpu_ppc_get_tb(env);
}

uint32_t cpu_ppc_load_tbu(CPUPPCState *env)
{
    return cpu_ppc_get_tb(env) >> 32;
}

uint64_t cpu_ppc_load_atbl(CPUPPCState *env)
{
    return cpu_ppc_get_tb(env);
}

uint32_t cpu_ppc_load_atbu(CPUPPCState *env)
{
    return cpu_ppc_get_tb(env) >> 32;
}

uint64_t cpu_ppc_load_vtb(CPUPPCState *env)
{
    return cpu_ppc_get_tb(env);
}

uint32_t cpu_ppc601_load_rtcu(CPUPPCState *env)
__attribute__ (( alias ("cpu_ppc_load_tbu") ));

#if 0
static uint32_t cpu_ppc601_load_rtcl(CPUPPCState *env)
{
    return cpu_ppc_load_tbl(env) & 0x3FFFFF80;
}
#endif

/* XXX: to be fixed */
int ppc_dcr_read (ppc_dcr_t *dcr_env, int dcrn, uint32_t *valp)
{
    return -1;
}

int ppc_dcr_write (ppc_dcr_t *dcr_env, int dcrn, uint32_t val)
{
    return -1;
}

bool bsd_ppc_is_elfv1(CPUPPCState *env)
{
#if defined(TARGET_PPC64)
    CPUState *cpu = env_cpu(env);
    struct TaskState *ts = (struct TaskState *)cpu->opaque;
    struct image_info *infop = ts->info;

    return ((infop->elf_flags & 0x3) < 2);
#else
    return 0;
#endif
}
