/*
 * Emulation of BSD signals
 *
 * Copyright (c) 2013 Stacey Son
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SIGNAL_COMMON_H
#define SIGNAL_COMMON_H

void force_sig_fault(int sig, int code, abi_ulong addr);
void queue_signal(CPUArchState *env, int sig, int si_type, target_siginfo_t *info);

/*
 * Within QEMU the top 16 bits of si_code indicate which of the parts of the
 * union in target_siginfo is valid. This only applies between
 * host_to_target_siginfo_noswap() and tswap_siginfo(); it does not appear
 * either within host siginfo_t or in target_siginfo structures which we get
 * from the guest userspace program. The BSD kernels don't do this, but its a
 * useful abstraction.
 */
#define QEMU_SI_KILL 0
#define QEMU_SI_TIMER 1
#define QEMU_SI_POLL 2
#define QEMU_SI_FAULT 3
#define QEMU_SI_CHLD 4

#endif
