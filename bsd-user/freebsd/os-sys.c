/*
 *  FreeBSD sysctl() and sysarch() system call emulation
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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <string.h>

#include "qemu.h"

#include "target_arch_sysarch.h"
#include "target_os_vmparam.h"

/*
 * XXX this uses the undocumented oidfmt interface to find the kind of
 * a requested sysctl, see /sys/kern/kern_sysctl.c:sysctl_sysctl_oidfmt()
 * (compare to src/sbin/sysctl/sysctl.c)
 */
static int
oidfmt(int *oid, int len, char *fmt, uint32_t *kind)
{
    int qoid[CTL_MAXNAME+2];
    uint8_t buf[BUFSIZ];
    int i;
    size_t j;

    qoid[0] = 0;
    qoid[1] = 4;
    memcpy(qoid + 2, oid, len * sizeof(int));

    j = sizeof(buf);
    i = sysctl(qoid, len + 2, buf, &j, 0, 0);
    if (i) {
        return i;
    }

    if (kind) {
        *kind = *(uint32_t *)buf;
    }

    if (fmt) {
        strcpy(fmt, (char *)(buf + sizeof(uint32_t)));
    }
    return 0;
}

/*
 * try and convert sysctl return data for the target.
 * XXX doesn't handle CTLTYPE_OPAQUE and CTLTYPE_STRUCT.
 */
static int sysctl_oldcvt(void *holdp, size_t holdlen, uint32_t kind)
{
    switch (kind & CTLTYPE) {
    case CTLTYPE_INT:
    case CTLTYPE_UINT:
        *(uint32_t *)holdp = tswap32(*(uint32_t *)holdp);
        break;

#ifdef TARGET_ABI32
    case CTLTYPE_LONG:
    case CTLTYPE_ULONG:
        *(uint32_t *)holdp = tswap32(*(long *)holdp);
        break;
#else
    case CTLTYPE_LONG:
        *(uint64_t *)holdp = tswap64(*(long *)holdp);
    case CTLTYPE_ULONG:
        *(uint64_t *)holdp = tswap64(*(unsigned long *)holdp);
        break;
#endif
#if !defined(__FreeBSD_version) || __FreeBSD_version < 900031
    case CTLTYPE_QUAD:
#else
    case CTLTYPE_U64:
    case CTLTYPE_S64:
#endif
        *(uint64_t *)holdp = tswap64(*(uint64_t *)holdp);
        break;

    case CTLTYPE_STRING:
        break;

    default:
        /* XXX unhandled */
        return -1;
    }
    return 0;
}

/*
 * Convert the undocmented name2oid sysctl data for the target.
 */
static inline void sysctl_name2oid(uint32_t *holdp, size_t holdlen)
{
    size_t i;

    for (i = 0; i < holdlen; i++) {
        holdp[i] = tswap32(holdp[i]);
    }
}

static inline void sysctl_oidfmt(uint32_t *holdp)
{
    /* byte swap the kind */
    holdp[0] = tswap32(holdp[0]);
}

abi_long do_freebsd_sysctl(CPUArchState *env, abi_ulong namep, int32_t namelen,
        abi_ulong oldp, abi_ulong oldlenp, abi_ulong newp, abi_ulong newlen)
{
    abi_long ret;
    void *hnamep, *holdp = NULL, *hnewp = NULL;
    size_t holdlen;
    abi_ulong oldlen = 0;
    int32_t *snamep = g_malloc(sizeof(int32_t) * namelen), *p, *q, i;
    uint32_t kind = 0;
    TaskState *ts = (TaskState *)env->opaque;

    if (oldlenp) {
        if (get_user_ual(oldlen, oldlenp)) {
            return -TARGET_EFAULT;
        }
    }
    hnamep = lock_user(VERIFY_READ, namep, namelen, 1);
    if (hnamep == NULL) {
        return -TARGET_EFAULT;
    }
    if (newp) {
        hnewp = lock_user(VERIFY_READ, newp, newlen, 1);
        if (hnewp == NULL) {
            return -TARGET_EFAULT;
        }
    }
    if (oldp) {
        holdp = lock_user(VERIFY_WRITE, oldp, oldlen, 0);
        if (holdp == NULL) {
            return -TARGET_EFAULT;
        }
    }
    holdlen = oldlen;
    for (p = hnamep, q = snamep, i = 0; i < namelen; p++, i++) {
        *q++ = tswap32(*p);
    }
    oidfmt(snamep, namelen, NULL, &kind);

    /* Handle some arch/emulator dependent sysctl()'s here. */
    switch (snamep[0]) {
    case CTL_KERN:
        switch (snamep[1]) {
        case KERN_USRSTACK:
#if TARGET_USRSTACK != 0
            (*(abi_ulong *)holdp) = tswapal(TARGET_USRSTACK);
            holdlen = sizeof(abi_ulong);
            ret = 0;
#else
            ret = -TARGET_ENOENT;
#endif
            goto out;

        case KERN_PS_STRINGS:
#if defined(TARGET_PS_STRINGS)
            (*(abi_ulong *)holdp) = tswapal(TARGET_PS_STRINGS);
            holdlen = sizeof(abi_ulong);
            ret = 0;
#else
            ret = -TARGET_ENOENT;
#endif
            goto out;

        case KERN_PROC:
            switch (snamep[2]) {
            case KERN_PROC_PATHNAME:
                holdlen = strlen(ts->bprm->fullpath) + 1;
                if (holdp) {
                    if (oldlen < holdlen) {
                        ret = -TARGET_EINVAL;
                        goto out;
                    }
                    strlcpy(holdp, ts->bprm->fullpath, oldlen);
                }
                ret = 0;
                goto out;

            default:
                break;
            }
            break;

        default:
            break;
        }
        break;

    case CTL_HW:
        switch (snamep[1]) {
        case HW_MACHINE:
            strlcpy(holdp, TARGET_HW_MACHINE, oldlen);
            ret = 0;
            goto out;

        case HW_MACHINE_ARCH:
            strlcpy(holdp, TARGET_HW_MACHINE_ARCH, oldlen);
            ret = 0;
            goto out;

        case 851: /* hw.availpages */
            {
                long lvalue;
                size_t len = sizeof(lvalue);

                if (sysctlbyname("hw.availpages", &lvalue, &len, NULL, 0)
                        == -1) {
                    ret = -1;
                } else {
                    (*(abi_ulong *)holdp) = tswapal((abi_ulong)lvalue);
                    holdlen = sizeof(abi_ulong);
                    ret = 0;
                }
            }
            goto out;

        default:
            break;
        }
    default:
        break;
    }

    ret = get_errno(sysctl(snamep, namelen, holdp, &holdlen, hnewp, newlen));
    if (!ret && (holdp != 0 && holdlen != 0)) {
        if (0 == snamep[0] && (3 == snamep[1] || 4 == snamep[1])) {
            if (3 == snamep[1]) {
                /* Handle the undocumented name2oid special case. */
                sysctl_name2oid(holdp, holdlen);
            } else {
                /* Handle oidfmt */
                sysctl_oidfmt(holdp);
            }
        } else {
            sysctl_oldcvt(holdp, holdlen, kind);
        }
    }
#ifdef DEBUG
    else {
        printf("sysctl(mib[0]=%d, mib[1]=%d, mib[3]=%d...) returned %d\n",
        snamep[0], snamep[1], snamep[2], (int)ret);
    }
#endif

out:
    if (oldlenp) {
        put_user_ual(holdlen, oldlenp);
    }
    unlock_user(hnamep, namep, 0);
    unlock_user(holdp, oldp, holdlen);
    if (hnewp) {
        unlock_user(hnewp, newp, 0);
    }
    g_free(snamep);
    return ret;
}

/* sysarch() is architecture dependent. */
abi_long do_freebsd_sysarch(void *cpu_env, abi_long arg1, abi_long arg2)
{

    return do_freebsd_arch_sysarch(cpu_env, arg1, arg2);
}
