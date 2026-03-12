/*
 * FreeBSD ppc register structures
 *
 * Copyright (c) 2015 Stacey D. Son
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TARGET_ARCH_REG_H
#define TARGET_ARCH_REG_H

/* See sys/powerpc/include/reg.h */
typedef struct target_reg {
    abi_ulong       fixreg[32];
    abi_ulong       lr;
    abi_ulong       cr;
    abi_ulong       xer;
    abi_ulong       ctr;
    abi_ulong       pc;
} target_reg_t;

typedef struct target_fpreg {
    double fpreg[32];
    double fpscr;
} target_fpreg_t;

#define tswapreg(ptr)   tswapal(ptr)

static inline void target_copy_regs(target_reg_t *regs, const CPUPPCState *env)
{
    int i;
    target_ulong ccr = 0;

    for (i = 0; i < 32; i++)
        regs->fixreg[i] = tswapreg(env->gpr[i]);
    regs->lr = tswapreg(env->lr);
    for(i = 0; i < ARRAY_SIZE(env->crf); i++) {
        ccr |= env->crf[i] << (32 - ((i + 1) * 4));
    }
    regs->cr = tswapreg(ccr);
    regs->xer = tswapreg(env->xer);
    regs->ctr = tswapreg(env->ctr);
    regs->pc = tswapreg(env->nip);
    /* env->msr XXX ? */
}

#undef tswapreg

#endif /* TARGET_ARCH_REG_H */
