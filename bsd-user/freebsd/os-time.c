/*
 *  FreeBSD time related system call helpers
 *
 *  Copyright (c) 2013-15 Stacey D. Son
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

#include "qemu.h"
#include "qemu-os.h"

int host_to_target_timerid(int timerid)
{
    int k;

    for (k = 0; k < ARRAY_SIZE(g_posix_timers); k++) {
        if (g_posix_timers[k] == timerid)
            return TIMER_MAGIC | k;
    }

    return -1;
}
