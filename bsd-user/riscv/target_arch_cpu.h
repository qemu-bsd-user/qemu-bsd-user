/*
 *  RISC-V CPU init and loop
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

#ifndef _TARGET_ARCH_CPU_H_
#define _TARGET_ARCH_CPU_H_

#include "target_arch.h"

#define TARGET_DEFAULT_CPU_MODEL "any"

static inline void target_cpu_init(CPURISCVState *env,
        struct target_pt_regs *regs)
{
    int i;

    for (i = 0; i < 32; i++) {
        env->gpr[i] = regs->regs[i];
    }

    env->pc = regs->sepc;
}

static inline void target_cpu_loop(CPURISCVState *env)
{
    CPUState *cs = env_cpu(env);
    int trapnr;
    target_siginfo_t info;

    for (;;) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        process_queued_cpu_work(cs);

        info.si_signo = 0;
        info.si_errno = 0;
        info.si_addr = 0;

        switch (trapnr) {
        default:
            fprintf(stderr, "qemu: unhandled CPU exception "
                "0x%x - aborting\n", trapnr);
            cpu_dump_state(cs, stderr, 0);
            abort();
        }

        if (info.si_signo) {
            queue_signal(env, info.si_signo, &info);
        }

        process_pending_signals(env);
    }
}

static inline void target_cpu_clone_regs(CPURISCVState *env, target_ulong newsp)
{
    if (newsp) {
        env->gpr[xSP] = newsp;
    }

    env->gpr[xA0] = 0; /* a0 */
    env->gpr[5] = 0;   /* t0 */
}

static inline void target_cpu_reset(CPUArchState *cpu)
{
}

#endif /* ! _TARGET_ARCH_CPU_H_ */
