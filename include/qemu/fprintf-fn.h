/*
 * Typedef for fprintf-alike function pointers.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef QEMU_FPRINTF_FN_H
#define QEMU_FPRINTF_FN_H 1

/* 
 * FreeBSD uses CLANG which doesn't appear to have GCC_FMT_ATTR
 * support.  Drop it for now.
 */
#ifdef __clang__
typedef int (*fprintf_function)(FILE *f, const char *fmt, ...)
    __printflike(2,3); 
#else
typedef int (*fprintf_function)(FILE *f, const char *fmt, ...)
    GCC_FMT_ATTR(2, 3);
#endif

#endif
