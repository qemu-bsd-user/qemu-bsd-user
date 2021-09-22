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

#endif /* !_TARGET_ARCH_SIGNAL_H_ */
