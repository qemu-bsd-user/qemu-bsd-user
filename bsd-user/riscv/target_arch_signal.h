/*
 *  RISC-V signal definitions
 *
 *  Copyright (c) 2019 Mark Corbin
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

#ifndef _TARGET_ARCH_SIGNAL_H_
#define _TARGET_ARCH_SIGNAL_H_

#include "cpu.h"


#define TARGET_INSN_SIZE     4  /* riscv instruction size */

/* Size of the signal trampoline code placed on the stack. */
#define TARGET_SZSIGCODE    ((abi_ulong)(7 * TARGET_INSN_SIZE))

/* Compare with riscv/include/_limits.h */
#define TARGET_MINSIGSTKSZ  (1024 * 4)
#define TARGET_SIGSTKSZ     (TARGET_MINSIGSTKSZ + 32768)

struct target_sigcontext {
    int32_t     _dummy;
};

struct target_gpregs {
    uint64_t    gp_ra;
    uint64_t    gp_sp;
    uint64_t    gp_gp;
    uint64_t    gp_tp;
    uint64_t    gp_t[7];
    uint64_t    gp_s[12];
    uint64_t    gp_a[8];
    uint64_t    gp_sepc;
    uint64_t    gp_sstatus;
};

struct target_fpregs {
    uint64_t        fp_x[32][2];
    uint64_t        fp_fcsr;
    uint32_t        fp_flags;
    uint32_t        pad;
};


typedef struct target_mcontext {
    struct target_gpregs   mc_gpregs;
    struct target_fpregs   mc_fpregs;
    uint32_t               mc_flags;
#define TARGET_MC_FP_VALID 0x01
    uint32_t               mc_pad;
    uint64_t               mc_spare[8];
} target_mcontext_t;

typedef struct target_ucontext {
    target_sigset_t   uc_sigmask;
    target_mcontext_t uc_mcontext;
    abi_ulong         uc_link;
    target_stack_t    uc_stack;
    int32_t           uc_flags;
    int32_t         __spare__[4];
} target_ucontext_t;

struct target_sigframe {
    target_ucontext_t   sf_uc; /* = *sf_uncontext */
    target_siginfo_t    sf_si; /* = *sf_siginfo (SA_SIGINFO case)*/
};

struct target_trapframe {
    uint64_t tf_ra;
    uint64_t tf_sp;
    uint64_t tf_gp;
    uint64_t tf_tp;
    uint64_t tf_t[7];
    uint64_t tf_s[12];
    uint64_t tf_a[8];
    uint64_t tf_sepc;
    uint64_t tf_sstatus;
    uint64_t tf_stval;
    uint64_t tf_scause;
};

#endif /* !_TARGET_ARCH_SIGNAL_H_ */
