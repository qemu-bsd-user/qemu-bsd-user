/*
 *  powerpc ELF definitions
 *
 *  Copyright (c) 2013 Stacey D. Son
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
#ifndef _TARGET_ARCH_ELF_H_
#define _TARGET_ARCH_ELF_H_

#define ELF_START_MMAP 0x80000000

#if defined(TARGET_PPC64) && !defined(TARGET_ABI32)

#define elf_check_arch(x) ( (x) == EM_PPC64 )
#define ELF_CLASS       ELFCLASS64

#else

#define elf_check_arch(x) ( (x) == EM_PPC )
#define ELF_CLASS       ELFCLASS32

#endif

#define ELF_ARCH        EM_PPC

#ifdef TARGET_WORDS_BIGENDIAN
#define ELF_DATA        ELFDATA2MSB
#else
#define ELF_DATA        ELFDATA2LSB
#endif
#define ELF_ARCH        EM_PPC

#define USE_ELF_CORE_DUMP
#define ELF_EXEC_PAGESIZE       4096

enum
{
	PPC_FEATURE_32		= 0x80000000,	/* Always true */
	PPC_FEATURE_64		= 0x40000000,	/* Defined on a 64-bit CPU */
	PPC_FEATURE_HAS_ALTIVEC	= 0x10000000,
	PPC_FEATURE_HAS_FPU	= 0x08000000,
	PPC_FEATURE_HAS_MMU	= 0x04000000,
	PPC_FEATURE_UNIFIED_CACHE = 0x01000000
};

#define TARET_ELF_HWCAP	(PPC_FEATURE_32 | PPC_FEATURE_HAS_ALTIVEC | \
	PPC_FEATURE_HAS_FPU | PPC_HAS_FEATURE_MMU | PPC_FEATURE_UNIFIED_CACHE)
#if defined(TARGET_PPC64) && !defined(TARGET_ABI32)
#define ELF_HWCAP (TARGET_ELF_HWCAP | PPC_FEATURE_64)
#else
#define ELF_HWCAP TARGET_ELF_HWCAP
#endif

#endif /* _TARGET_ARCH_ELF_H_ */
