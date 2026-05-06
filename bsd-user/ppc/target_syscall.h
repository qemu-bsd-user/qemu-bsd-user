/*
 * powerpc system call definitions
 *
 * Copyright (c) 2014 Justin Hibbits
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef BSD_USER_PPC_TARGET_SYSCALL_H
#define BSD_USER_PPC_TARGET_SYSCALL_H

/*
 * struct target_pt_regs defines the way the registers are stored on the stack
 * during a system call.
 */

struct target_pt_regs {
        abi_ulong gpr[32];
        abi_ulong lr;
        abi_ulong cr;
        abi_ulong xer;
        abi_ulong ctr;
        abi_ulong nip;
        abi_ulong srr1;
        abi_ulong exc;
        union {
                struct {
                        abi_ulong dar;          /* Fault registers */
                        abi_ulong dsisr;
                } aim;
                struct {
                        abi_ulong dear;
                        abi_ulong esr;
                        abi_ulong dbcr0;
                } booke;
        } cpu;
};


#define UNAME_MACHINE                   "powerpc"
#define TARGET_HW_MACHINE       "powerpc"
#if defined(TARGET_PPC64) && !defined(TARGET_ABI32)
#define TARGET_HW_MACHINE_ARCH  UNAME_MACHINE"64"
#else
#define TARGET_HW_MACHINE_ARCH  UNAME_MACHINE
#endif

#endif /* BSD_USER_PPC_TARGET_SYSCALL_H */
