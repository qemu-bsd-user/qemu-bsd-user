/*
 *  Emulation of BSD signals
 *
 *  Copyright (c) 2003 - 2008 Fabrice Bellard
 *  Copyright (c) 2013 Stacey Son
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
#include "qemu.h"
#include "qemu-common.h"
#include "signal-common.h"
#include "os-time.h"
#include "trace.h"
#include "hw/core/tcg-cpu-ops.h"
#include "host-signal.h"

static struct target_sigaction sigact_table[TARGET_NSIG];
static void host_signal_handler(int host_sig, siginfo_t *info, void *puc);
static void target_to_host_sigset_internal(sigset_t *d,
        const target_sigset_t *s);

static inline int on_sig_stack(TaskState *ts, unsigned long sp)
{
    return sp - ts->sigaltstack_used.ss_sp < ts->sigaltstack_used.ss_size;
}

static inline int sas_ss_flags(TaskState *ts, unsigned long sp)
{
    return ts->sigaltstack_used.ss_size == 0 ? SS_DISABLE :
        on_sig_stack(ts, sp) ? SS_ONSTACK : 0;
}

/*
 * The BSD ABIs use the same singal numbers across all the CPU architectures, so
 * (unlike Linux) these functions are just the identity mapping. This might not
 * be true for XyzBSD running on AbcBSD, which doesn't currently work.
 */
int host_to_target_signal(int sig)
{
    return sig;
}

int target_to_host_signal(int sig)
{
    return sig;
}

static inline void target_sigemptyset(target_sigset_t *set)
{
    memset(set, 0, sizeof(*set));
}

#include <signal.h>

int
qemu_sigorset(sigset_t *dest, const sigset_t *left, const sigset_t *right)
{
    sigset_t work;
    int i;

    sigemptyset(&work);
    for (i = 1; i < NSIG; ++i) {
        if (sigismember(left, i) || sigismember(right, i)) {
            sigaddset(&work, i);
        }
    }

    *dest = work;
    return 0;
}

static inline void target_sigaddset(target_sigset_t *set, int signum)
{
    signum--;
    uint32_t mask = (uint32_t)1 << (signum % TARGET_NSIG_BPW);
    set->__bits[signum / TARGET_NSIG_BPW] |= mask;
}

static inline int target_sigismember(const target_sigset_t *set, int signum)
{
    signum--;
    abi_ulong mask = (abi_ulong)1 << (signum % TARGET_NSIG_BPW);
    return (set->__bits[signum / TARGET_NSIG_BPW] & mask) != 0;
}

/* Adjust the signal context to rewind out of safe-syscall if we're in it */
static inline void rewind_if_in_safe_syscall(void *puc)
{
    ucontext_t *uc = (ucontext_t *)puc;
    uintptr_t pcreg = host_signal_pc(uc);

    if (pcreg > (uintptr_t)safe_syscall_start
        && pcreg < (uintptr_t)safe_syscall_end) {
        host_signal_set_pc(uc, (uintptr_t)safe_syscall_start);
    }
}

static void host_to_target_sigset_internal(target_sigset_t *d,
        const sigset_t *s)
{
    int i;

    target_sigemptyset(d);
    for (i = 1; i <= TARGET_NSIG; i++) {
        if (sigismember(s, i)) {
            target_sigaddset(d, host_to_target_signal(i));
        }
    }
}

void host_to_target_sigset(target_sigset_t *d, const sigset_t *s)
{
    target_sigset_t d1;
    int i;

    host_to_target_sigset_internal(&d1, s);
    for (i = 0; i < TARGET_NSIG_WORDS; i++) {
        d->__bits[i] = tswap32(d1.__bits[i]);
    }
}

static void target_to_host_sigset_internal(sigset_t *d,
        const target_sigset_t *s)
{
    int i;

    sigemptyset(d);
    for (i = 1; i <= TARGET_NSIG; i++) {
        if (target_sigismember(s, i)) {
            sigaddset(d, target_to_host_signal(i));
        }
    }
}

void target_to_host_sigset(sigset_t *d, const target_sigset_t *s)
{
    target_sigset_t s1;
    int i;

    for (i = 0; i < TARGET_NSIG_WORDS; i++) {
        s1.__bits[i] = tswap32(s->__bits[i]);
    }
    target_to_host_sigset_internal(d, &s1);
}

static bool has_trapno(int sig)
{
    return sig == SIGILL || sig == SIGFPE || sig == SIGSEGV || sig == SIGBUS ||
        sig == SIGTRAP;
}

/* Siginfo conversion. */

static inline void host_to_target_siginfo_noswap(target_siginfo_t *tinfo,
        const siginfo_t *info)
{
    int sig, code;

    sig = host_to_target_signal(info->si_signo);
    /* XXX should have host_to_target_si_code() */
    code = tswap32(info->si_code);
    tinfo->si_signo = sig;
    tinfo->si_errno = info->si_errno;
    tinfo->si_code = info->si_code;
    tinfo->si_pid = info->si_pid;
    tinfo->si_uid = info->si_uid;
    tinfo->si_status = info->si_status;
    tinfo->si_addr = (abi_ulong)(unsigned long)info->si_addr;
    /* si_value is opaque to kernel */
    tinfo->si_value.sival_ptr =
        (abi_ulong)(unsigned long)info->si_value.sival_ptr;
    if (has_trapno(sig)) {
        tinfo->_reason._fault._trapno = info->_reason._fault._trapno;
    }
#ifdef SIGPOLL
    if (sig == SIGPOLL) {
        tinfo->_reason._poll._band = info->_reason._poll._band;
    }
#endif
    if (code == SI_TIMER) {
        int timerid;

        timerid = info->_reason._timer._timerid;
#ifdef __FreeBSD__
        timerid = host_to_target_timerid(timerid);
#endif
        tinfo->_reason._timer._timerid = timerid;
        tinfo->_reason._timer._overrun = info->_reason._timer._overrun;
    }
}

static void tswap_siginfo(target_siginfo_t *tinfo, const target_siginfo_t *info)
{
    int sig, code;

    sig = info->si_signo;
    code = info->si_code;
    tinfo->si_signo = tswap32(sig);
    tinfo->si_errno = tswap32(info->si_errno);
    tinfo->si_code = tswap32(info->si_code);
    tinfo->si_pid = tswap32(info->si_pid);
    tinfo->si_uid = tswap32(info->si_uid);
    tinfo->si_status = tswap32(info->si_status);
    tinfo->si_addr = tswapal(info->si_addr);
    /*
     * Unswapped, because we passed it through mostly untouched.  si_value is
     * opaque to the kernel, so we didn't bother with potentially wasting cycles
     * to swap it into host byte order.
     */
    tinfo->si_value.sival_ptr = info->si_value.sival_ptr;
    if (has_trapno(sig)) {
        tinfo->_reason._fault._trapno = tswap32(info->_reason._fault._trapno);
    }
#ifdef SIGPOLL
    if (sig == SIGPOLL) {
        tinfo->_reason._poll._band = tswap32(info->_reason._poll._band);
    }
#endif
    if (code == SI_TIMER) {
        tinfo->_reason._timer._timerid = tswap32(info->_reason._timer._timerid);
        tinfo->_reason._timer._overrun = tswap32(info->_reason._timer._overrun);
    }
}

void host_to_target_siginfo(target_siginfo_t *tinfo, const siginfo_t *info)
{

    host_to_target_siginfo_noswap(tinfo, info);
    tswap_siginfo(tinfo, tinfo);
}

int block_signals(void)
{
    TaskState *ts = (TaskState *)thread_cpu->opaque;
    sigset_t set;

    /*
     * It's OK to block everything including SIGSEGV, because we won't run any
     * further guest code before unblocking signals in
     * process_pending_signals().
     */
    sigfillset(&set);
    sigprocmask(SIG_SETMASK, &set, 0);

    return qatomic_xchg(&ts->signal_pending, 1);
}

abi_long target_to_host_sigevent(struct sigevent *host_sevp,
                                               abi_ulong target_addr)
{
    struct target_sigevent *target_sevp;

    if (!lock_user_struct(VERIFY_READ, target_sevp, target_addr, 1)) {
        return -TARGET_EFAULT;
    }

    /* This union is awkward on 64 bit systems because it has a 32 bit
     * integer and a pointer in it; we follow the conversion approach
     * used for handling sigval types in signal.c so the guest should get
     * the correct value back even if we did a 64 bit byteswap and it's
     * using the 32 bit integer.
     */
    host_sevp->sigev_value.sival_ptr =
        (void *)(uintptr_t)target_sevp->sigev_value.sival_ptr;
    host_sevp->sigev_signo =
        target_to_host_signal(tswap32(target_sevp->sigev_signo));
    host_sevp->sigev_notify = tswap32(target_sevp->sigev_notify);
    host_sevp->_sigev_un._threadid = tswap32(target_sevp->_sigev_un._threadid);

    unlock_user_struct(target_sevp, target_addr, 1);
    return 0;
}

/* Returns 1 if given signal should dump core if not handled. */
static int core_dump_signal(int sig)
{
    switch (sig) {
    case TARGET_SIGABRT:
    case TARGET_SIGFPE:
    case TARGET_SIGILL:
    case TARGET_SIGQUIT:
    case TARGET_SIGSEGV:
    case TARGET_SIGTRAP:
    case TARGET_SIGBUS:
        return 1;
    default:
        return 0;
    }
}

/* Abort execution with signal. */
void QEMU_NORETURN force_sig(int target_sig)
{
    CPUArchState *env = thread_cpu->env_ptr;
    CPUState *cpu = env_cpu(env);
    TaskState *ts = cpu->opaque;
    int core_dumped = 0;
    int host_sig;
    struct sigaction act;

    host_sig = target_to_host_signal(target_sig);
    gdb_signalled(env, target_sig);

    /* Dump core if supported by target binary format */
    if (core_dump_signal(target_sig) && (ts->bprm->core_dump != NULL)) {
        stop_all_tasks();
        core_dumped =
            ((*ts->bprm->core_dump)(target_sig, env) == 0);
    }
    if (core_dumped) {
        struct rlimit nodump;

        /*
         * We already dumped the core of target process, we don't want
         * a coredump of qemu itself.
         */
         getrlimit(RLIMIT_CORE, &nodump);
         nodump.rlim_cur = 0;
         setrlimit(RLIMIT_CORE, &nodump);
         (void) fprintf(stderr, "qemu: uncaught target signal %d (%s) "
             "- %s\n", target_sig, strsignal(host_sig), "core dumped");
    }

    /*
     * The proper exit code for dying from an uncaught signal is
     * -<signal>.  The kernel doesn't allow exit() or _exit() to pass
     * a negative value.  To get the proper exit code we need to
     * actually die from an uncaught signal.  Here the default signal
     * handler is installed, we send ourself a signal and we wait for
     * it to arrive.
     */
    memset(&act, 0, sizeof(act));
    sigfillset(&act.sa_mask);
    act.sa_handler = SIG_DFL;
    sigaction(host_sig, &act, NULL);

    kill(getpid(), host_sig);

    /*
     * Make sure the signal isn't masked (just reuse the mask inside
     * of act).
     */
    sigdelset(&act.sa_mask, host_sig);
    sigsuspend(&act.sa_mask);

    /* unreachable */
    abort();
}

/*
 * Queue a signal so that it will be send to the virtual CPU as soon as
 * possible.
 */
void queue_signal(CPUArchState *env, int sig, int si_type, target_siginfo_t *info)
{
    CPUState *cpu = env_cpu(env);
    TaskState *ts = cpu->opaque;
    struct emulated_sigtable *k;

    k = &ts->sigtab[sig - 1];
    trace_user_queue_signal(env, sig);
    if (sig == TARGET_SIGSEGV && sigismember(&ts->signal_mask, SIGSEGV)) {
        /*
         * Guest has blocked SIGSEGV but we got one anyway. Assume this is a
         * forced SIGSEGV (ie one the kernel handles via force_sig_info because
         * it got a real MMU fault). A blocked SIGSEGV in that situation is
         * treated as if using the default handler. This is not correct if some
         * other process has randomly sent us a SIGSEGV via kill(), but that is
         * not easy to distinguish at this point, so we assume it doesn't
         * happen.
         */
        force_sig(sig);
    }

    k->info = *info;
    k->pending = 1;
    /* Signal that a new signal is pending. */
    ts->signal_pending = 1;
    return;
}

static int fatal_signal(int sig)
{

    switch (sig) {
    case TARGET_SIGCHLD:
    case TARGET_SIGURG:
    case TARGET_SIGWINCH:
    case TARGET_SIGINFO:
        /* Ignored by default. */
        return 0;
    case TARGET_SIGCONT:
    case TARGET_SIGSTOP:
    case TARGET_SIGTSTP:
    case TARGET_SIGTTIN:
    case TARGET_SIGTTOU:
        /* Job control signals.  */
        return 0;
    default:
        return 1;
    }
}

/*
 * Force a synchronously taken QEMU_SI_FAULT signal. For QEMU the
 * 'force' part is handled in process_pending_signals().
 */
void force_sig_fault(int sig, int code, abi_ulong addr)
{
    CPUState *cpu = thread_cpu;
    CPUArchState *env = cpu->env_ptr;
    target_siginfo_t info = {};

    info.si_signo = sig;
    info.si_errno = 0;
    info.si_code = code;
    info.si_addr = addr;
    queue_signal(env, sig, QEMU_SI_FAULT, &info);
}

static void host_signal_handler(int host_sig, siginfo_t *info, void *puc)
{
    CPUArchState *env = thread_cpu->env_ptr;
    CPUState *cpu = env_cpu(env);
    TaskState *ts = cpu->opaque;
    target_siginfo_t tinfo;
    ucontext_t *uc = puc;
    struct emulated_sigtable *k;
    int guest_sig;
    uintptr_t pc = 0;
    bool sync_sig = false;

    /*
     * Non-spoofed SIGSEGV and SIGBUS are synchronous, and need special
     * handling wrt signal blocking and unwinding.
     */
    if ((host_sig == SIGSEGV || host_sig == SIGBUS) && info->si_code > 0) {
        MMUAccessType access_type;
        uintptr_t host_addr;
        abi_ptr guest_addr;
        bool is_write;

        host_addr = (uintptr_t)info->si_addr;

        /*
         * Convert forcefully to guest address space: addresses outside
         * reserved_va are still valid to report via SEGV_MAPERR.
         */
        guest_addr = h2g_nocheck(host_addr);

        pc = host_signal_pc(uc);
        is_write = host_signal_write(info, uc);
        access_type = adjust_signal_pc(&pc, is_write);

        if (host_sig == SIGSEGV) {
            bool maperr = true;

            if (info->si_code == SEGV_ACCERR && h2g_valid(host_addr)) {
                /* If this was a write to a TB protected page, restart. */
                if (is_write &&
                    handle_sigsegv_accerr_write(cpu, &uc->uc_sigmask,
                                                pc, guest_addr)) {
                    return;
                }

                /*
                 * With reserved_va, the whole address space is PROT_NONE,
                 * which means that we may get ACCERR when we want MAPERR.
                 */
                if (page_get_flags(guest_addr) & PAGE_VALID) {
                    maperr = false;
                } else {
                    info->si_code = SEGV_MAPERR;
                }
            }

            sigprocmask(SIG_SETMASK, &uc->uc_sigmask, NULL);
            cpu_loop_exit_sigsegv(cpu, guest_addr, access_type, maperr, pc);
        } else {
            sigprocmask(SIG_SETMASK, &uc->uc_sigmask, NULL);
            if (info->si_code == BUS_ADRALN) {
                cpu_loop_exit_sigbus(cpu, guest_addr, access_type, pc);
            }
        }

        sync_sig = true;
    }

    /* Get the target signal number. */
    guest_sig = host_to_target_signal(host_sig);
    if (guest_sig < 1 || guest_sig > TARGET_NSIG) {
        return;
    }
    trace_user_host_signal(cpu, host_sig, guest_sig);

    host_to_target_siginfo_noswap(&tinfo, info);

    k = &ts->sigtab[guest_sig - 1];
    k->info = tinfo;
    k->pending = guest_sig;
    ts->signal_pending = 1;

    /*
     * For synchronous signals, unwind the cpu state to the faulting
     * insn and then exit back to the main loop so that the signal
     * is delivered immediately.
     */
    if (sync_sig) {
        cpu->exception_index = EXCP_INTERRUPT;
        cpu_loop_exit_restore(cpu, pc);
    }

    rewind_if_in_safe_syscall(puc);

    /*
     * Block host signals until target signal handler entered. We
     * can't block SIGSEGV or SIGBUS while we're executing guest
     * code in case the guest code provokes one in the window between
     * now and it getting out to the main loop. Signals will be
     * unblocked again in process_pending_signals().
     */
    sigfillset(&uc->uc_sigmask);
    sigdelset(&uc->uc_sigmask, SIGSEGV);
    sigdelset(&uc->uc_sigmask, SIGBUS);

    /* Interrupt the virtual CPU as soon as possible. */
    cpu_exit(thread_cpu);
}

/* do_sigaltstack() returns target values and errnos. */
/* compare to kern/kern_sig.c sys_sigaltstack() and kern_sigaltstack() */
abi_long do_sigaltstack(abi_ulong uss_addr, abi_ulong uoss_addr, abi_ulong sp)
{
    TaskState *ts = (TaskState *)thread_cpu->opaque;
    int ret;
    target_stack_t oss;

    if (uoss_addr) {
        /* Save current signal stack params */
        oss.ss_sp = tswapl(ts->sigaltstack_used.ss_sp);
        oss.ss_size = tswapl(ts->sigaltstack_used.ss_size);
        oss.ss_flags = tswapl(sas_ss_flags(ts, sp));
    }

    if (uss_addr) {
        target_stack_t *uss;
        target_stack_t ss;
        size_t minstacksize = TARGET_MINSIGSTKSZ;

        ret = -TARGET_EFAULT;
        if (!lock_user_struct(VERIFY_READ, uss, uss_addr, 1)) {
            goto out;
        }
        __get_user(ss.ss_sp, &uss->ss_sp);
        __get_user(ss.ss_size, &uss->ss_size);
        __get_user(ss.ss_flags, &uss->ss_flags);
        unlock_user_struct(uss, uss_addr, 0);

        ret = -TARGET_EPERM;
        if (on_sig_stack(ts, sp)) {
            goto out;
        }

        ret = -TARGET_EINVAL;
        if (ss.ss_flags != TARGET_SS_DISABLE
            && ss.ss_flags != TARGET_SS_ONSTACK
            && ss.ss_flags != 0) {
            goto out;
        }

        if (ss.ss_flags == TARGET_SS_DISABLE) {
            ss.ss_size = 0;
            ss.ss_sp = 0;
        } else {
            ret = -TARGET_ENOMEM;
            if (ss.ss_size < minstacksize) {
                goto out;
            }
        }

        ts->sigaltstack_used.ss_sp = ss.ss_sp;
        ts->sigaltstack_used.ss_size = ss.ss_size;
    }

    if (uoss_addr) {
        ret = -TARGET_EFAULT;
        if (copy_to_user(uoss_addr, &oss, sizeof(oss))) {
            goto out;
        }
    }

    ret = 0;
out:
    return ret;
}

/* do_sigaction() return host values and errnos */
int do_sigaction(int sig, const struct target_sigaction *act,
        struct target_sigaction *oact)
{
    struct target_sigaction *k;
    struct sigaction act1;
    int host_sig;
    int ret = 0;

    if (sig < 1 || sig > TARGET_NSIG || sig == TARGET_SIGKILL ||
        sig == TARGET_SIGSTOP) {
        return -EINVAL;
    }

    if (block_signals()) {
        return -TARGET_ERESTART;
    }

    k = &sigact_table[sig - 1];
    if (oact) {
        oact->_sa_handler = tswapal(k->_sa_handler);
        oact->sa_flags = tswap32(k->sa_flags);
        oact->sa_mask = k->sa_mask;
    }
    if (act) {
        /* XXX: this is most likely not threadsafe. */
        k->_sa_handler = tswapal(act->_sa_handler);
        k->sa_flags = tswap32(act->sa_flags);
        k->sa_mask = act->sa_mask;

        /* Update the host signal state. */
        host_sig = target_to_host_signal(sig);
        if (host_sig != SIGSEGV && host_sig != SIGBUS) {
            memset(&act1, 0, sizeof(struct sigaction));
            sigfillset(&act1.sa_mask);
            act1.sa_flags = SA_SIGINFO;
            if (k->sa_flags & TARGET_SA_RESTART) {
                act1.sa_flags |= SA_RESTART;
            }
            /*
             *  Note: It is important to update the host kernel signal mask to
             *  avoid getting unexpected interrupted system calls.
             */
            if (k->_sa_handler == TARGET_SIG_IGN) {
                act1.sa_sigaction = (void *)SIG_IGN;
            } else if (k->_sa_handler == TARGET_SIG_DFL) {
                if (fatal_signal(sig)) {
                    act1.sa_sigaction = host_signal_handler;
                } else {
                    act1.sa_sigaction = (void *)SIG_DFL;
                }
            } else {
                act1.sa_sigaction = host_signal_handler;
            }
            ret = sigaction(host_sig, &act1, NULL);
        }
    }
    return ret;
}

static inline abi_ulong get_sigframe(struct target_sigaction *ka,
        CPUArchState *regs, size_t frame_size)
{
    TaskState *ts = (TaskState *)thread_cpu->opaque;
    abi_ulong sp;

    /* Use default user stack */
    sp = get_sp_from_cpustate(regs);

    if ((ka->sa_flags & TARGET_SA_ONSTACK) && sas_ss_flags(ts, sp) == 0) {
        sp = ts->sigaltstack_used.ss_sp + ts->sigaltstack_used.ss_size;
    }

#if defined(TARGET_ARM)
    return (sp - frame_size) & ~7;
#elif defined(TARGET_AARCH64)
    return (sp - frame_size) & ~15;
#else
    return sp - frame_size;
#endif
}

/* compare to $M/$M/exec_machdep.c sendsig() */

static void setup_frame(int sig, int code, struct target_sigaction *ka,
    target_sigset_t *set, target_siginfo_t *tinfo, CPUArchState *regs)
{
    struct target_sigframe *frame;
    abi_ulong frame_addr;
    int i;

    frame_addr = get_sigframe(ka, regs, sizeof(*frame));
    trace_user_setup_frame(regs, frame_addr);
    if (!lock_user_struct(VERIFY_WRITE, frame, frame_addr, 0)) {
        goto give_sigsegv;
    }

    memset(frame, 0, sizeof(*frame));
    if (get_mcontext(regs, &frame->sf_uc.uc_mcontext, 0)) {
        goto give_sigsegv;
    }

    for (i = 0; i < TARGET_NSIG_WORDS; i++) {
        if (__put_user(set->__bits[i], &frame->sf_uc.uc_sigmask.__bits[i])) {
            goto give_sigsegv;
        }
    }

    if (tinfo) {
        frame->sf_si.si_signo = tinfo->si_signo;
        frame->sf_si.si_errno = tinfo->si_errno;
        frame->sf_si.si_code = tinfo->si_code;
        frame->sf_si.si_pid = tinfo->si_pid;
        frame->sf_si.si_uid = tinfo->si_uid;
        frame->sf_si.si_status = tinfo->si_status;
        frame->sf_si.si_addr = tinfo->si_addr;

        if (has_trapno(sig)) {
            frame->sf_si._reason._fault._trapno = tinfo->_reason._fault._trapno;
        }

        /*
         * If si_code is one of SI_QUEUE, SI_TIMER, SI_ASYNCIO, or
         * SI_MESGQ, then si_value contains the application-specified
         * signal value. Otherwise, the contents of si_value are
         * undefined.
         */
        if (code == SI_QUEUE || code == SI_TIMER || code == SI_ASYNCIO ||
            code == SI_MESGQ) {
            frame->sf_si.si_value.sival_int = tinfo->si_value.sival_int;
        }

        if (code == SI_TIMER) {
            frame->sf_si._reason._timer._timerid =
                tinfo->_reason._timer._timerid;
            frame->sf_si._reason._timer._overrun =
                tinfo->_reason._timer._overrun;
        }

#ifdef SIGPOLL
        if (sig == SIGPOLL) {
            frame->sf_si._reason._band = tinfo->_reason._band;
        }
#endif

    }

    if (set_sigtramp_args(regs, sig, frame, frame_addr, ka)) {
        goto give_sigsegv;
    }

    unlock_user_struct(frame, frame_addr, 1);
    return;

give_sigsegv:
    unlock_user_struct(frame, frame_addr, 1);
    force_sig(TARGET_SIGSEGV);
}

static int reset_signal_mask(target_ucontext_t *ucontext)
{
    int i;
    sigset_t blocked;
    target_sigset_t target_set;
    TaskState *ts = (TaskState *)thread_cpu->opaque;

    for (i = 0; i < TARGET_NSIG_WORDS; i++)
        if (__get_user(target_set.__bits[i],
                    &ucontext->uc_sigmask.__bits[i])) {
            return -TARGET_EFAULT;
        }
    target_to_host_sigset_internal(&blocked, &target_set);
    ts->signal_mask = blocked;
    sigprocmask(SIG_SETMASK, &ts->signal_mask, NULL);

    return 0;
}

long do_sigreturn(CPUArchState *regs, abi_ulong addr)
{
    long ret;
    abi_ulong target_ucontext;
    target_ucontext_t *ucontext = NULL;

    /* Get the target ucontext address from the stack frame */
    ret = get_ucontext_sigreturn(regs, addr, &target_ucontext);
    if (is_error(ret)) {
        return ret;
    }
    trace_user_do_sigreturn(regs, addr);
    if (!lock_user_struct(VERIFY_READ, ucontext, target_ucontext, 0)) {
        goto badframe;
    }

    /* Set the register state back to before the signal. */
    if (set_mcontext(regs, &ucontext->uc_mcontext, 1)) {
        goto badframe;
    }

    /* And reset the signal mask. */
    if (reset_signal_mask(ucontext)) {
        goto badframe;
    }

    unlock_user_struct(ucontext, target_ucontext, 0);
    return -TARGET_EJUSTRETURN;

badframe:
    if (ucontext != NULL) {
        unlock_user_struct(ucontext, target_ucontext, 0);
    }
    force_sig(TARGET_SIGSEGV);
    return -TARGET_EFAULT;
}

void signal_init(void)
{
    TaskState *ts = (TaskState *)thread_cpu->opaque;
    struct sigaction act;
    struct sigaction oact;
    int i;
    int host_sig;

    /* Set the signal mask from the host mask. */
    sigprocmask(0, 0, &ts->signal_mask);

    sigfillset(&act.sa_mask);
    act.sa_sigaction = host_signal_handler;
    act.sa_flags = SA_SIGINFO;

    for (i = 1; i <= TARGET_NSIG; i++) {
        host_sig = target_to_host_signal(i);
        sigaction(host_sig, NULL, &oact);
        if (oact.sa_sigaction == (void *)SIG_IGN) {
            sigact_table[i - 1]._sa_handler = TARGET_SIG_IGN;
        } else if (oact.sa_sigaction == (void *)SIG_DFL) {
            sigact_table[i - 1]._sa_handler = TARGET_SIG_DFL;
        }
        /*
         * If there's already a handler installed then something has
         * gone horribly wrong, so don't even try to handle that case.
         * Install some handlers for our own use.  We need at least
         * SIGSEGV and SIGBUS, to detect exceptions.  We can not just
         * trap all signals because it affects syscall interrupt
         * behavior.  But do trap all default-fatal signals.
         */
        if (fatal_signal(i)) {
            sigaction(host_sig, &act, NULL);
        }
    }
}

static void handle_pending_signal(CPUArchState *cpu_env, int sig,
                                  struct emulated_sigtable *k)
{
    CPUState *cpu = env_cpu(cpu_env);
    TaskState *ts = cpu->opaque;
    struct target_sigaction *sa;
    int code;
    sigset_t set;
    abi_ulong handler;
    target_siginfo_t tinfo;
    target_sigset_t target_old_set;

    trace_user_handle_signal(cpu_env, sig);

    k->pending = 0;

    sig = gdb_handlesig(cpu, sig);
    if (!sig) {
        sa = NULL;
        handler = TARGET_SIG_IGN;
    } else {
        sa = &sigact_table[sig - 1];
        handler = sa->_sa_handler;
    }

    if (do_strace) {
        print_taken_signal(sig, &k->info);
    }

    if (handler == TARGET_SIG_DFL) {
        /*
         * default handler : ignore some signal. The other are job
         * control or fatal.
         */
        if (sig == TARGET_SIGTSTP || sig == TARGET_SIGTTIN ||
            sig == TARGET_SIGTTOU) {
            kill(getpid(), SIGSTOP);
        } else if (sig != TARGET_SIGCHLD && sig != TARGET_SIGURG &&
                   sig != TARGET_SIGINFO && sig != TARGET_SIGWINCH &&
                   sig != TARGET_SIGCONT) {
            force_sig(sig);
        }
    } else if (handler == TARGET_SIG_IGN) {
        /* ignore sig */
    } else if (handler == TARGET_SIG_ERR) {
        force_sig(sig);
    } else {
        /* compute the blocked signals during the handler execution */
        sigset_t *blocked_set;

        target_to_host_sigset(&set, &sa->sa_mask);
        /*
         * SA_NODEFER indicates that the current signal should not be
         * blocked during the handler.
         */
        if (!(sa->sa_flags & TARGET_SA_NODEFER)) {
            sigaddset(&set, target_to_host_signal(sig));
        }

        /*
         * Save the previous blocked signal state to restore it at the
         * end of the signal execution (see do_sigreturn).
         */
        host_to_target_sigset_internal(&target_old_set, &ts->signal_mask);

        blocked_set = ts->in_sigsuspend ?
            &ts->sigsuspend_mask : &ts->signal_mask;
        qemu_sigorset(&ts->signal_mask, blocked_set, &set);
        ts->in_sigsuspend = false;
        sigprocmask(SIG_SETMASK, &ts->signal_mask, NULL);

#if 0  /* not yet */
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
        /* if the CPU is in VM86 mode, we restore the 32 bit values */
        {
            CPUX86State *env = cpu_env;
            if (env->eflags & VM_MASK) {
                save_v86_state(env);
            }
        }
#endif
#endif /* not yet */

        code = k->info.si_code;
        /* prepare the stack frame of the virtual CPU */
        if (sa->sa_flags & TARGET_SA_SIGINFO) {
            tswap_siginfo(&tinfo, &k->info);
            setup_frame(sig, code, sa, &target_old_set, &tinfo, cpu_env);
        } else {
            setup_frame(sig, code, sa, &target_old_set, NULL, cpu_env);
        }
        if (sa->sa_flags & TARGET_SA_RESETHAND) {
            sa->_sa_handler = TARGET_SIG_DFL;
        }
    }
}

void process_pending_signals(CPUArchState *cpu_env)
{
    CPUState *cpu = env_cpu(cpu_env);
    int sig;
    sigset_t *blocked_set, set;
    struct emulated_sigtable *k;
    TaskState *ts = cpu->opaque;

    while (qatomic_read(&ts->signal_pending)) {
        /* FIXME: This is not threadsafe. */

        sigfillset(&set);
        sigprocmask(SIG_SETMASK, &set, 0);

        k = ts->sigtab;
        blocked_set = ts->in_sigsuspend ?
            &ts->sigsuspend_mask : &ts->signal_mask;
        for (sig = 1; sig <= TARGET_NSIG; sig++, k++) {
            if (k->pending &&
                !sigismember(blocked_set, target_to_host_signal(sig))) {
                handle_pending_signal(cpu_env, sig, k);
            }
        }

        /*
         * unblock signals and check one more time. Unblocking signals may cause
         * us to take anothe rhost signal, which will set signal_pending again.
         */
        qatomic_set(&ts->signal_pending, 0);
        ts->in_sigsuspend = false;
        set = ts->signal_mask;
        sigdelset(&set, SIGSEGV);
        sigdelset(&set, SIGBUS);
        sigprocmask(SIG_SETMASK, &set, 0);
    }
    ts->in_sigsuspend = false;
}

void cpu_loop_exit_sigsegv(CPUState *cpu, target_ulong addr,
                           MMUAccessType access_type, bool maperr, uintptr_t ra)
{
    const struct TCGCPUOps *tcg_ops = CPU_GET_CLASS(cpu)->tcg_ops;

    if (tcg_ops->record_sigsegv) {
        tcg_ops->record_sigsegv(cpu, addr, access_type, maperr, ra);
    }

    force_sig_fault(TARGET_SIGSEGV,
                    maperr ? TARGET_SEGV_MAPERR : TARGET_SEGV_ACCERR,
                    addr);
    cpu->exception_index = EXCP_INTERRUPT;
    cpu_loop_exit_restore(cpu, ra);
}

void cpu_loop_exit_sigbus(CPUState *cpu, target_ulong addr,
                          MMUAccessType access_type, uintptr_t ra)
{
    const struct TCGCPUOps *tcg_ops = CPU_GET_CLASS(cpu)->tcg_ops;

    if (tcg_ops->record_sigbus) {
        tcg_ops->record_sigbus(cpu, addr, access_type, ra);
    }

    force_sig_fault(TARGET_SIGBUS, TARGET_BUS_ADRALN, addr);
    cpu->exception_index = EXCP_INTERRUPT;
    cpu_loop_exit_restore(cpu, ra);
}
