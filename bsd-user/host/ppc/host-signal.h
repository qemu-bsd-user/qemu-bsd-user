/*
 * host-signal.h: signal info dependent on the host architecture
 *
 * Copyright (c) 2021 Warner Losh
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PPC_HOST_SIGNAL_H
#define PPC_HOST_SIGNAL_H

#include <machine/trap.h>
#include <machine/spr.h>

static inline uintptr_t host_signal_pc(ucontext_t *uc)
{
    return uc->uc_mcontext.mc_ssr0;
}

static inline void host_signal_set_pc(ucontext_t *uc, uintptr_t pc)
{
    uc->uc_mcontext.mc_ssr0 = pc;
}

static inline bool host_signal_write(siginfo_t *info, ucontext_t *uc)
{
    /*
     * Compare with start of trap_pfault() in sys/powerpc/trap.c
     */
    return uc->uc_mcontext.mc_exc != EXC_ISI &&
        (uc->uc_mcontext.mc_dsisr & DSISR_STORE);
}

#endif
