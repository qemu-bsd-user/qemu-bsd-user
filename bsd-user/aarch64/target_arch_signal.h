/*
 * ARM AArch64 specific signal definitions for bsd-user
 *
 * Copyright (c) 2015 Stacey D. Son <sson at FreeBSD>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _TARGET_ARCH_SIGNAL_H_
#define _TARGET_ARCH_SIGNAL_H_

#include "cpu.h"

#define TARGET_REG_X0   0
#define TARGET_REG_X30  30
#define TARGET_REG_X31  31
#define TARGET_REG_LR   TARGET_REG_X30
#define TARGET_REG_SP   TARGET_REG_X31

#define TARGET_INSN_SIZE    4       /* arm64 instruction size */

/* Size of the signal trampolin code. See _sigtramp(). */
#define TARGET_SZSIGCODE    ((abi_ulong)(9 * TARGET_INSN_SIZE))

/* compare to sys/arm64/include/_limits.h */
#define TARGET_MINSIGSTKSZ  (1024 * 4)                  /* min sig stack size */
#define TARGET_SIGSTKSZ     (TARGET_MINSIGSTKSZ + 32768)  /* recommended size */

#endif /* !_TARGET_ARCH_SIGNAL_H_ */
