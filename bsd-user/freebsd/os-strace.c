/*
 *  System call tracing and debugging
 *
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

#include "qemu/osdep.h"
#include <sys/select.h>
#include <sys/syscall.h>
#include <sys/ioccom.h>

/*
 * An array of all of the syscalls we know about
 */
static const struct syscallname freebsd_scnames[] = {
#include "freebsd/strace.list"
};

/*
 * The public interface to this module.
 */
void print_freebsd_syscall(int num, abi_long arg1, abi_long arg2, abi_long arg3,
        abi_long arg4, abi_long arg5, abi_long arg6)
{

    print_syscall(num, freebsd_scnames, ARRAY_SIZE(freebsd_scnames), arg1, arg2,
            arg3, arg4, arg5, arg6);
}

void print_freebsd_syscall_ret(int num, abi_long ret)
{

    print_syscall_ret(num, ret, freebsd_scnames, ARRAY_SIZE(freebsd_scnames));
}

