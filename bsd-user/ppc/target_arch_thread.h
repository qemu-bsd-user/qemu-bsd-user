/*
 *  powerpc thread support
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
#ifndef _TARGET_ARCH_THREAD_H_
#define _TARGET_ARCH_THREAD_H_

#if defined(TARGET_PPC64) && !defined(TARGET_ABI32)
#define STACK_ALIGN 8
#else
#define STACK_ALIGN 4
#endif

/* Compare to powerpc/powerpc/exec_machdep.c cpu_set_upcall_kse() */
static inline void target_thread_set_upcall(CPUPPCState *regs, abi_ulong entry,
    abi_ulong arg, abi_ulong stack_base, abi_ulong stack_size)
{
    abi_ulong sp;

    /*
     * Make sure the stack is properly aligned.
     * powerpc/include/param.h (STACKLIGN() macro)
     */
#if defined(TARGET_PPC64) && !defined(TARGET_ABI32)
    sp = ((u_int)(stack_base + stack_size) - 48) & ~0x1f;
#else
    sp = ((u_int)(stack_base + stack_size) - 8) & ~0x1f;
#endif

    /* r1 = stack base */
    regs->gpr[1] = sp;
    /* r3 = arg */
    regs->gpr[3] = arg;
    /* srr0 = start function entry */
    regs->spr[SPR_SRR0] = entry;

    /* TODO:ppc64 target_thread_set_upcall */
}

static inline void target_thread_init(struct target_pt_regs *regs,
        struct image_info *infop)
{
    memset(regs, 0, sizeof(*regs));
    regs->nip = infop->entry;
    regs->gpr[1] = infop->start_stack;
    if (bsd_type == target_freebsd) {
        regs->lr = infop->entry;
    }
}

#endif /* !_TARGET_ARCH_THREAD_H_ */
