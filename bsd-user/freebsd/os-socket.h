/*
 *  FreeBSD socket related system call shims
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
#ifndef __FREEBSD_SOCKET_H_
#define __FREEBSD_SOCKET_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

#include "qemu-os.h"

/* sendmsg(2) */
static inline abi_long do_freebsd_sendmsg(int fd, abi_ulong target_msg,
        int flags)
{
    abi_long ret;
    struct target_msghdr *msgp;
    struct msghdr msg;
    int count;
    struct iovec *vec;
    abi_ulong target_vec;

    if (!lock_user_struct(VERIFY_READ, msgp, target_msg, 1)) {
        return -TARGET_EFAULT;
    }
    if (msgp->msg_name) {
        msg.msg_namelen = tswap32(msgp->msg_namelen);
        msg.msg_name = alloca(msg.msg_namelen);
        ret = target_to_host_sockaddr(msg.msg_name,
            tswapal(msgp->msg_name), msg.msg_namelen);

        if (is_error(ret)) {
            unlock_user_struct(msgp, target_msg, 0);
            return ret;
        }
    } else {
        msg.msg_name = NULL;
        msg.msg_namelen = 0;
    }
    msg.msg_controllen = 2 * tswapal(msgp->msg_controllen);
    msg.msg_control = alloca(msg.msg_controllen);
    msg.msg_flags = tswap32(msgp->msg_flags);

    count = tswapal(msgp->msg_iovlen);
    vec = alloca(count * sizeof(struct iovec));
    target_vec = tswapal(msgp->msg_iov);
    lock_iovec(VERIFY_READ, vec, target_vec, count, 1);
    msg.msg_iovlen = count;
    msg.msg_iov = vec;

    ret = t2h_freebsd_cmsg(&msg, msgp);
    if (!is_error(ret)) {
        ret = get_errno(sendmsg(fd, &msg, flags));
    }
    unlock_iovec(vec, target_vec, count, 0);
    unlock_user_struct(msgp, target_msg, 0);
    return ret;
}

/* recvmsg(2) */
static inline abi_long do_freebsd_recvmsg(int fd, abi_ulong target_msg,
        int flags)
{
    abi_long ret, len;
    struct target_msghdr *msgp;
    struct msghdr msg;
    int count;
    struct iovec *vec;
    abi_ulong target_vec;

    if (!lock_user_struct(VERIFY_WRITE, msgp, target_msg, 0)) {
        return -TARGET_EFAULT;
    }
    if (msgp->msg_name) {
        msg.msg_namelen = tswap32(msgp->msg_namelen);
        msg.msg_name = alloca(msg.msg_namelen);
        ret = target_to_host_sockaddr(msg.msg_name,
            tswapal(msgp->msg_name), msg.msg_namelen);

        if (is_error(ret)) {
            unlock_user_struct(msgp, target_msg, 1);
            return ret;
        }
    } else {
        msg.msg_name = NULL;
        msg.msg_namelen = 0;
    }
    msg.msg_controllen = 2 * tswapal(msgp->msg_controllen);
    msg.msg_control = alloca(msg.msg_controllen);
    msg.msg_flags = tswap32(msgp->msg_flags);

    count = tswapal(msgp->msg_iovlen);
    vec = alloca(count * sizeof(struct iovec));
    target_vec = tswapal(msgp->msg_iov);
    lock_iovec(VERIFY_WRITE, vec, target_vec, count, 0);
    msg.msg_iovlen = count;
    msg.msg_iov = vec;

    ret = get_errno(recvmsg(fd, &msg, flags));
    if (!is_error(ret)) {
        len = ret;
        ret = h2t_freebsd_cmsg(msgp, &msg);
        if (!is_error(ret)) {
            msgp->msg_namelen = tswap32(msg.msg_namelen);
            if (msg.msg_name != NULL) {
                ret = host_to_target_sockaddr(tswapal(msgp->msg_name),
                        msg.msg_name, msg.msg_namelen);
                if (is_error(ret)) {
                    goto out;
                }
            }
        }
        ret = len;
    }
out:
    unlock_iovec(vec, target_vec, count, 1);
    unlock_user_struct(msgp, target_msg, 1);
    return ret;
}

/* setsockopt(2) */
static inline abi_long do_bsd_setsockopt(int sockfd, int level, int optname,
        abi_ulong optval_addr, socklen_t optlen)
{
    abi_long ret;
    int val;
    struct ip_mreqn *ip_mreq;

    switch (level) {
    case IPPROTO_TCP:
        /* TCP options all take an 'int' value. */
        if (optlen < sizeof(uint32_t)) {
            return -TARGET_EINVAL;
        }
        if (get_user_u32(val, optval_addr)) {
            return -TARGET_EFAULT;
        }
        ret = get_errno(setsockopt(sockfd, level, optname, &val, sizeof(val)));
        break;

    case IPPROTO_IP:
        switch (optname) {
        case IP_HDRINCL:/* int; header is included with data */
        case IP_TOS:    /* int; IP type of service and preced. */
        case IP_TTL:    /* int; IP time to live */
        case IP_RECVOPTS: /* bool; receive all IP opts w/dgram */
        case IP_RECVRETOPTS: /* bool; receive IP opts for response */
        case IP_RECVDSTADDR: /* bool; receive IP dst addr w/dgram */
        case IP_MULTICAST_IF:/* u_char; set/get IP multicast i/f  */
        case IP_MULTICAST_TTL:/* u_char; set/get IP multicast ttl */
        case IP_MULTICAST_LOOP:/*u_char;set/get IP multicast loopback */
        case IP_PORTRANGE: /* int; range to choose for unspec port */
        case IP_RECVIF: /* bool; receive reception if w/dgram */
        case IP_IPSEC_POLICY:   /* int; set/get security policy */
        case IP_FAITH:  /* bool; accept FAITH'ed connections */
        case IP_RECVTTL: /* bool; receive reception TTL w/dgram */
            val = 0;
            if (optlen >= sizeof(uint32_t)) {
                if (get_user_u32(val, optval_addr)) {
                    return -TARGET_EFAULT;
                }
            } else if (optlen >= 1) {
                if (get_user_u8(val, optval_addr)) {
                    return -TARGET_EFAULT;
                }
            }
            ret = get_errno(setsockopt(sockfd, level, optname, &val,
                        sizeof(val)));
            break;

        case IP_ADD_MEMBERSHIP: /*ip_mreq; add an IP group membership */
        case IP_DROP_MEMBERSHIP:/*ip_mreq; drop an IP group membership*/
            if (optlen < sizeof(struct target_ip_mreq) ||
                    optlen > sizeof(struct target_ip_mreqn)) {
                return -TARGET_EINVAL;
            }
            ip_mreq = (struct ip_mreqn *) alloca(optlen);
            target_to_host_ip_mreq(ip_mreq, optval_addr, optlen);
            ret = get_errno(setsockopt(sockfd, level, optname, ip_mreq,
                        optlen));
            break;

        default:
            goto unimplemented;
        }
        break;

    case TARGET_SOL_SOCKET:
        switch (optname) {
        /* Options with 'int' argument.  */
        case TARGET_SO_DEBUG:
            optname = SO_DEBUG;
            break;

        case TARGET_SO_REUSEADDR:
            optname = SO_REUSEADDR;
            break;

        case TARGET_SO_REUSEPORT:
            optname = SO_REUSEADDR;
            break;

        case TARGET_SO_KEEPALIVE:
            optname = SO_KEEPALIVE;
            break;

        case TARGET_SO_DONTROUTE:
            optname = SO_DONTROUTE;
            break;

        case TARGET_SO_LINGER:
            optname = SO_LINGER;
            break;

        case TARGET_SO_BROADCAST:
            optname = SO_BROADCAST;
            break;

        case TARGET_SO_OOBINLINE:
            optname = SO_OOBINLINE;
            break;

        case TARGET_SO_SNDBUF:
            optname = SO_SNDBUF;
            break;

        case TARGET_SO_RCVBUF:
            optname = SO_RCVBUF;
            break;

        case TARGET_SO_SNDLOWAT:
            optname = SO_RCVLOWAT;
            break;

        case TARGET_SO_RCVLOWAT:
            optname = SO_RCVLOWAT;
            break;

        case TARGET_SO_SNDTIMEO:
            optname = SO_SNDTIMEO;
            break;

        case TARGET_SO_RCVTIMEO:
            optname = SO_RCVTIMEO;
            break;

        case TARGET_SO_ACCEPTFILTER:
            goto unimplemented;

        case TARGET_SO_NOSIGPIPE:
            optname = SO_NOSIGPIPE;
            break;

        case TARGET_SO_TIMESTAMP:
            optname = SO_TIMESTAMP;
            break;

        case TARGET_SO_BINTIME:
            optname = SO_BINTIME;
            break;

        case TARGET_SO_ERROR:
            optname = SO_ERROR;
            break;

        case TARGET_SO_SETFIB:
            optname = SO_ERROR;
            break;

#ifdef SO_USER_COOKIE
        case TARGET_SO_USER_COOKIE:
            optname = SO_USER_COOKIE;
            break;
#endif
        default:
            goto unimplemented;
        }
        if (optlen < sizeof(uint32_t)) {
            return -TARGET_EINVAL;
        }
        if (get_user_u32(val, optval_addr)) {
            return -TARGET_EFAULT;
        }
        ret = get_errno(setsockopt(sockfd, SOL_SOCKET, optname, &val,
                    sizeof(val)));
        break;
    default:
unimplemented:
    gemu_log("Unsupported setsockopt level=%d optname=%d\n",
        level, optname);
    ret = -TARGET_ENOPROTOOPT;
    }

    return ret;
}

/* getsockopt(2) */
static inline abi_long do_bsd_getsockopt(int sockfd, int level, int optname,
        abi_ulong optval_addr, abi_ulong optlen)
{
    abi_long ret;
    int len, val;
    socklen_t lv;

    switch (level) {
    case TARGET_SOL_SOCKET:
        level = SOL_SOCKET;
        switch (optname) {

        /* These don't just return a single integer */
        case TARGET_SO_LINGER:
        case TARGET_SO_RCVTIMEO:
        case TARGET_SO_SNDTIMEO:
        case TARGET_SO_ACCEPTFILTER:
            goto unimplemented;

        /* Options with 'int' argument.  */
        case TARGET_SO_DEBUG:
            optname = SO_DEBUG;
            goto int_case;

        case TARGET_SO_REUSEADDR:
            optname = SO_REUSEADDR;
            goto int_case;

        case TARGET_SO_REUSEPORT:
            optname = SO_REUSEPORT;
            goto int_case;

        case TARGET_SO_TYPE:
            optname = SO_TYPE;
            goto int_case;

        case TARGET_SO_ERROR:
            optname = SO_ERROR;
            goto int_case;

        case TARGET_SO_DONTROUTE:
            optname = SO_DONTROUTE;
            goto int_case;

        case TARGET_SO_BROADCAST:
            optname = SO_BROADCAST;
            goto int_case;

        case TARGET_SO_SNDBUF:
            optname = SO_SNDBUF;
            goto int_case;

        case TARGET_SO_RCVBUF:
            optname = SO_RCVBUF;
            goto int_case;

        case TARGET_SO_KEEPALIVE:
            optname = SO_KEEPALIVE;
            goto int_case;

        case TARGET_SO_OOBINLINE:
            optname = SO_OOBINLINE;
            goto int_case;

        case TARGET_SO_TIMESTAMP:
            optname = SO_TIMESTAMP;
            goto int_case;

        case TARGET_SO_RCVLOWAT:
            optname = SO_RCVLOWAT;
            goto int_case;

        case TARGET_SO_LISTENINCQLEN:
            optname = SO_LISTENINCQLEN;
            goto int_case;

        default:
int_case:
            if (get_user_u32(len, optlen)) {
                return -TARGET_EFAULT;
            }
            if (len < 0) {
                return -TARGET_EINVAL;
            }
            lv = sizeof(lv);
            ret = get_errno(getsockopt(sockfd, level, optname, &val, &lv));
            if (ret < 0) {
                return ret;
            }
            if (len > lv) {
                len = lv;
            }
            if (len == 4) {
                if (put_user_u32(val, optval_addr)) {
                    return -TARGET_EFAULT;
                }
            } else {
                if (put_user_u8(val, optval_addr)) {
                    return -TARGET_EFAULT;
                }
            }
            if (put_user_u32(len, optlen)) {
                return -TARGET_EFAULT;
            }
            break;

        }
        break;

    case IPPROTO_TCP:
        /* TCP options all take an 'int' value. */
        goto int_case;

    case IPPROTO_IP:
        switch (optname) {
        case IP_HDRINCL:
        case IP_TOS:
        case IP_TTL:
        case IP_RECVOPTS:
        case IP_RECVRETOPTS:
        case IP_RECVDSTADDR:

        case IP_RETOPTS:
#if defined(__FreeBSD_version) && __FreeBSD_version > 900000 && defined(IP_RECVTOS)
        case IP_RECVTOS:
#endif
        case IP_MULTICAST_TTL:
        case IP_MULTICAST_LOOP:
        case IP_PORTRANGE:
        case IP_IPSEC_POLICY:
        case IP_FAITH:
        case IP_ONESBCAST:
        case IP_BINDANY:
            if (get_user_u32(len, optlen)) {
                return -TARGET_EFAULT;
            }
            if (len < 0) {
                return -TARGET_EINVAL;
            }
            lv = sizeof(lv);
            ret = get_errno(getsockopt(sockfd, level, optname,
                &val, &lv));
            if (ret < 0) {
                return ret;
            }
            if (len < sizeof(int) && len > 0 && val >= 0 &&
                val < 255) {
                len = 1;
                if (put_user_u32(len, optlen) ||
                        put_user_u8(val, optval_addr)) {
                    return -TARGET_EFAULT;
                }
            } else {
                if (len > sizeof(int)) {
                    len = sizeof(int);
                }
                if (put_user_u32(len, optlen) ||
                        put_user_u32(val, optval_addr)) {
                    return -TARGET_EFAULT;
                }
            }
            break;

        default:
            goto unimplemented;
        }
        break;

    default:
unimplemented:
        gemu_log("getsockopt level=%d optname=%d not yet supported\n",
            level, optname);
        ret = -TARGET_EOPNOTSUPP;
        break;
    }
    return ret;
}

/* setfib(2) */
static inline abi_long do_freebsd_setfib(abi_long fib)
{

    return get_errno(setfib(fib));
}

/* sctp_peeloff(2) */
static inline abi_long do_freebsd_sctp_peeloff(abi_long s, abi_ulong id)
{

    qemu_log("qemu: Unsupported syscall sctp_peeloff()\n");
    return -TARGET_ENOSYS;
}

/* sctp_generic_sendmsg(2) */
static inline abi_long do_freebsd_sctp_generic_sendmsg(abi_long s,
        abi_ulong target_msg, abi_long msglen, abi_ulong target_to,
        abi_ulong len, abi_ulong target_sinfo, abi_long flags)
{

    qemu_log("qemu: Unsupported syscall sctp_generic_sendmsg()\n");
    return -TARGET_ENOSYS;
}

/* sctp_generic_recvmsg(2) */
static inline abi_long do_freebsd_sctp_generic_recvmsg(abi_long s,
        abi_ulong target_iov, abi_long iovlen, abi_ulong target_from,
        abi_ulong fromlen, abi_ulong target_sinfo, abi_ulong target_msgflags)
{

    qemu_log("qemu: Unsupported syscall sctp_generic_recvmsg()\n");
    return -TARGET_ENOSYS;
}

/* freebsd4_sendfile(2) */
static inline abi_long do_freebsd_freebsd4_sendfile(abi_long fd, abi_long s,
        abi_ulong arg3, abi_ulong arg4, abi_ulong nbytes, abi_ulong target_hdtr,
        abi_ulong target_sbytes, abi_long flags)
{

    qemu_log("qemu: Unsupported syscall freebsd4_sendfile()\n");
    return -TARGET_ENOSYS;
}

/* sendfile(2) */
static inline abi_long do_freebsd_sendfile(abi_long fd, abi_long s,
        abi_ulong arg3, abi_ulong arg4, abi_ulong nbytes, abi_ulong target_hdtr,
        abi_ulong target_sbytes, abi_long flags)
{

    qemu_log("qemu: Unsupported syscall sendfile()\n");
    return -TARGET_ENOSYS;
}

#endif /* !__FREEBSD_SOCKET_H_ */
