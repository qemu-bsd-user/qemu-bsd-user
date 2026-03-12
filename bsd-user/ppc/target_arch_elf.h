/*
 * powerpc ELF definitions
 *
 * Copyright (c) 2014 Justin Hibbits
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TARGET_ARCH_ELF_H
#define TARGET_ARCH_ELF_H

#define ELF_START_MMAP 0x80000000
#define ELF_ET_DYN_LOAD_ADDR    0x01010000

#if defined(TARGET_PPC64) && !defined(TARGET_ABI32)

#define ELF_CLASS       ELFCLASS64
#define ELF_ARCH        EM_PPC64

#else

#define ELF_CLASS       ELFCLASS32
#define ELF_ARCH        EM_PPC

#endif

#define elf_check_arch(x) ( (x) == ELF_ARCH )
#ifdef TARGET_BIG_ENDIAN
#define ELF_DATA        ELFDATA2MSB
#else
#define ELF_DATA        ELFDATA2LSB
#endif

#define USE_ELF_CORE_DUMP
#define ELF_EXEC_PAGESIZE       4096

enum
{
	PPC_FEATURE_64		= 0x40000000,	/* Defined on a 64-bit CPU */
	PPC_FEATURE_HAS_ALTIVEC	= 0x10000000,
	PPC_FEATURE_HAS_FPU	= 0x08000000,
};

#define ELF_HWCAP target_get_elf_hwcap()

static inline uint32_t target_get_elf_hwcap(void)
{
    PowerPCCPU *cpu = POWERPC_CPU(thread_cpu);
    uint32_t features = 0;

    /* We don't have to be terribly complete here; the high points are
       Altivec/FP/SPE support.  Anything else is just a bonus.  */
#define GET_FEATURE(flag, feature)                                      \
    do { if (cpu->env.insns_flags & flag) { features |= feature; } } while (0)
    GET_FEATURE(PPC_64B, PPC_FEATURE_64);
    GET_FEATURE(PPC_FLOAT, PPC_FEATURE_HAS_FPU);
    GET_FEATURE(PPC_ALTIVEC, PPC_FEATURE_HAS_ALTIVEC);
#undef GET_FEATURE

    return features;
}

#endif /* TARGET_ARCH_ELF_H */
