/*
 *  x86_64 signal definitions
 *
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

/* Size of the signal trampolin code placed on the stack. */
#define TARGET_SZSIGCODE    0

/* compare to  x86/include/_limits.h */
#define TARGET_MINSIGSTKSZ  (512 * 4)               /* min sig stack size */
#define TARGET_SIGSTKSZ     (MINSIGSTKSZ + 32768)   /* recommended size */

typedef struct target_mcontext {
} target_mcontext_t;

#include "target_os_ucontext.h"

struct target_sigframe {
    abi_ulong   sf_signum;
    abi_ulong   sf_siginfo;    /* code or pointer to sf_si */
    abi_ulong   sf_ucontext;   /* points to sf_uc */
    abi_ulong   sf_addr;       /* undocumented 4th arg */
    target_ucontext_t   sf_uc; /* = *sf_uncontext */
    target_siginfo_t    sf_si; /* = *sf_siginfo (SA_SIGINFO case)*/
    uint32_t    __spare__[2];
};

abi_long set_sigtramp_args(CPUX86State *env, int sig,
                           struct target_sigframe *frame,
                           abi_ulong frame_addr,
                           struct target_sigaction *ka);
abi_long get_mcontext(CPUX86State *regs, target_mcontext_t *mcp, int flags);
abi_long set_mcontext(CPUX86State *regs, target_mcontext_t *mcp, int srflag);
abi_long get_ucontext_sigreturn(CPUX86State *regs, abi_ulong target_sf,
                                abi_ulong *target_uc);

#endif /* !TARGET_ARCH_SIGNAL_H_ */
