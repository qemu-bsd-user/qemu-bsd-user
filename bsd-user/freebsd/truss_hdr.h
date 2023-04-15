/*
 * Glue code needed to use a lightly-edited truss + sysdecode library
 */

#ifndef TRUSS_HDR_H
#define TRUSS_HDR_H 1

void record_syscall(TaskState *ts, int num, abi_long arg1, abi_long arg2,
                    abi_long arg3, abi_long arg4, abi_long arg5, abi_long arg6,
                    abi_long arg7, abi_long arg8);
void record_syscall_ret(TaskState *ts, int num, abi_ulong ret, abi_ulong ret2);

#endif /* TRUSS_HDR_H */
