/*
 * PowerPC specific prototypes for bsd-user
 *
 * Copyright (c) 2015 Justin Hibbits
 * Copyright (c) 2021 Brandon Bergren
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TARGET_ARCH_H
#define TARGET_ARCH_H

#include "qemu.h"

/* target_arch_cpu.c */
extern bool bsd_ppc_is_elfv1(CPUPPCState *env);

#endif /* TARGET_ARCH_H */
