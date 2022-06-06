/*
 * Intel i386  sigcode for bsd-user
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

#ifndef TARGET_ARCH_SIGTRAMP_H
#define TARGET_ARCH_SIGTRAMP_H

static inline abi_long setup_sigtramp(abi_ulong offset, unsigned sigf_uc,
        unsigned sys_sigreturn)
{
    static uint8_t sigtramp_code[] = {
                                /* sigcode: */
        /*  0 */ 0xff, 0x54, 0x24, 0x10,
                                /* call   *0x10(%esp) */
        /*  4 */ 0x8d, 0x44, 0x24, 0x20,
                                /* lea    0x20(%esp),%eax */
        /*  8 */ 0x50,          /* push   %eax */
        /*  9 */ 0xf7, 0x40, 0x54, 0x00, 0x00, 0x02, 0x00,
                                /* testl  $0x20000,0x54(%eax) */
        /* 10 */ 0x75, 0x03,
                                /* jne    15 <sigcode+0x15> */
        /* 12 */ 0x8e, 0x68, 0x14,
                                /* mov    0x14(%eax),%gs */
        /* 15 */ 0xb8, 0xa1, 0x01, 0x00, 0x00,
                                /* mov    $0x1a1,%eax */
        /* 1a */ 0x50,          /* push   %eax */
        /* 1b */ 0xcd, 0x80,    /* int    $0x80 */
        /* 1d */ 0xeb, 0xfe,    /* jmp    1d <sigcode+0x1d> */
        /* 1f */ 0x90,          /* nop */
    };

    G_STATIC_ASSERT(sizeof(sigtramp_code) == TARGET_SZSIGCODE);

    return memcpy_to_target(offset, sigtramp_code, sizeof(sigtramp_code));
}
#endif /* TARGET_ARCH_SIGTRAMP_H */
