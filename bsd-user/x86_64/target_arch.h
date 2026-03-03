/*
 * Intel x86_64 specific prototypes for bsd-user
 *
 * Copyright (c) 2013 Stacey D. Son
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TARGET_ARCH_H
#define TARGET_ARCH_H

/* target_arch_cpu.c */
void bsd_x86_64_write_dt(void *ptr, unsigned long addr, unsigned long limit,
                int flags);
void bsd_x86_64_set_idt(int n, unsigned int dpl);
void bsd_x86_64_set_idt_base(uint64_t base);

static inline void
target_cpu_set_tls(CPUX86State *env, target_ulong newtls)
{
    env->segs[R_FS].base = newtls;
}


#endif /* TARGET_ARCH_H */
