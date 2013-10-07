
#ifndef _TARGET_ARCH_SIGTRAMP_H_
#define _TARGET_ARCH_SIGTRAMP_H_

/* Compare to arm/arm/locore.S ENTRY_NP(sigcode) */
static inline abi_long setup_sigtramp(abi_ulong offset, unsigned sigf_uc,
        unsigned sys_sigreturn)
{
    int i;
    uint32_t sys_exit = TARGET_FREEBSD_NR_exit;
    /*
     * The code has to load r7 manually rather than using
     * "ldr r7, =SYS_return to make sure the size of the
     * code is correct.
     */
    uint32_t sigtramp_code[] = {
    /* 1 */ 0xE1A0000D,         /* mov r0, sp */
    /* 2 */ 0xE59F700C,         /* ldr r7, [pc, #12] */
    /* 3 */ 0xEF000000 + sys_sigreturn, /* swi (SYS_sigreturn) */
    /* 4 */ 0xE59F7008,         /* ldr r7, [pc, #8] */
    /* 5 */ 0xEF000000 + sys_exit,      /* swi (SYS_exit)*/
    /* 6 */ 0xEAFFFFFA,         /* b . -16 */
    /* 7 */ sys_sigreturn,
    /* 8 */ sys_exit
    };

    for (i = 0; i < 8; i++) {
        tswap32s(&sigtramp_code[i]);
    }

    return memcpy_to_target(offset, sigtramp_code, TARGET_SZSIGCODE);
}
#endif /* _TARGET_ARCH_SIGTRAMP_H_ */
