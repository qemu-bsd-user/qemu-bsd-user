/*
 * ARM AArch64 ELF definitions for bsd-user
 *
 * Copyright (c) 2015 Stacey D. Son
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
#ifndef _TARGET_ARCH_ELF_H_
#define _TARGET_ARCH_ELF_H_

#define ELF_START_MMAP 0x80000000
#define ELF_ET_DYN_LOAD_ADDR    0x100000

#define elf_check_arch(x) ((x) == EM_AARCH64)

#define ELF_CLASS       ELFCLASS64
#define ELF_DATA        ELFDATA2LSB
#define ELF_ARCH        EM_AARCH64

#define USE_ELF_CORE_DUMP
#define ELF_EXEC_PAGESIZE       4096

#define ELF_HWCAP   0

#endif /* _TARGET_ARCH_ELF_H_ */
