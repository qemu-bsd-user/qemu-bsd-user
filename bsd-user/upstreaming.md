# bsd-user upstreaming status

Living status doc for getting blitz's bsd-user work into upstream QEMU.
Lives only on `blitz` (like `BSD-USER.rst` and this same directory's
`TODO`) — never part of what actually gets mailed upstream.

## Workflow

- `upstream-queue` branch (qemu-claude repo): holding pen for everything
  destined for upstream eventually, cherry-picked out of blitz's real
  history. Grows as more gets triaged out of blitz; commits get dropped
  from it once they've actually landed upstream (rebase upstream-queue
  onto master after each merge-master-into-blitz cycle — already-applied
  commits go empty and get skipped automatically).
- `bsd-user-2026q3` branch: the branch actually being prepared for
  submission. Cherry-picked *from* `upstream-queue`, kept to roughly
  10-20 commits at a time so a review round stays tractable.
- Truss, elfcore, and the powerpc arch are excluded from both branches —
  each is its own separate upstreaming effort.

## Review status of upstream-queue (2026-09-20, 52 commits)

Status values: `upstream` (ready, going in the current batch) / `defer`
(good, holding back to keep the batch small) / `blitz-fix` (blitz's
version is wrong — the fix should go the other way, into blitz) /
`rejected` (upstream/you already said no) / `drop` (not suitable at
all). Blank = not yet reviewed.

| hash | subject | status | note |
|------|---------|--------|------|
| ec7b44bb9e | bsd-user/freebsd: Small header and refactor fixes | | regrouped by Claude from blitz-tip content, no single 1:1 blitz source commit |
| 9246a1a04c | bsd-user: Fix core_dump_signal signal set, add clarifying comments | | regrouped, no single 1:1 blitz source commit |
| 1a1476e2aa | bsd-user: main.c misc cleanup | | regrouped, no single 1:1 blitz source commit |
| 828e4d07c2 | bsd-user: Dynamically allocate bprm->page, fix loader_exec error path | | regrouped, no single 1:1 blitz source commit |
| 2a6bdcbde5 | bsd-user: Small per-arch cpu-loop and thread fixes | | regrouped, no single 1:1 blitz source commit |
| 9d03c2fb9d | bsd-user: Add get_second_rval for x86_64, i386, and arm | | regrouped, no single 1:1 blitz source commit |
| e3c466232e | bsd-user/x86_64,i386: Implement TLS, upcall, and sigtramp args | | regrouped, no single 1:1 blitz source commit |
| e7e6f6b989 | bsd-user/i386: Implement the signal trampoline | | regrouped, no single 1:1 blitz source commit |
| 6082dd5ab8 | bsd-user: Fix aarch64 host signal implementation | | real typo fix, mc_gregs -> mc_gpregs |
| ef3d5d4ee1 | bsd-user: eliminate the BSDtype and related infrastructure | | also fixed a latent qemu_proc_pathname extern-without-definition bug found while resolving |
| 6d6664b8f0 | bsd-user: Eliminate unused regs arg in load_elf_binary | | |
| 7a6aff1933 | bsd-user: Shell script to run kyua tests | | |
| 2eb85f851c | bsd-user/riscv: note ELF_HWCAP divergence from FreeBSD kernel | | comment-only, authored by Claude this session (couldn't find the real source commit — full-history -G search timed out) |
| c611fb7f62 | bsd-user/riscv64: Fix build | | |
| c1e65bf3bc | bsd-user/host-signal.h: Add host-signal for all the hosts we support | | partial: only the aarch64 hunk (arm/i386/x86_64 already upstream, ppc/ppc64 excluded) |
| a628f8823e | bsd-user-smoke: drop powerpc from smoke test list | | Claude's own commit, keeps smoke tests scoped since ppc is excluded |
| ea4c2ff788 | riscv: Don't need to specify ABI | | |
| d1d81a59e4 | bsd-user: smoke test only good on bsd-user | | |
| 575c715d31 | Kludge the lenght | | |
| af47626203 | bsd-user-smoke: Import sources and build them | | |
| c9c238c626 | bsd-user-smoke: Kill mips | | |
| 5f22195afb | tcg: i386 hello world for FreeBSD | | |
| 0cfe18d183 | bsd-user: fix smoke test for meson < 0.56 | | |
| 44f08b5cd0 | Add smoke tests for bsd-user. | | author Gleb Popov, not in QEMU-SOBS |
| 46ffcffd2c | common-user: remove duplicate FreeBSD read_self_maps | | Claude's own fix — cherry-picking onto this branch triggered a rename-detection merge collision in common-user/selfmap.c; blitz itself still has the duplicate |
| e7a5c47da2 | bsd-user: declare cpu in do_freebsd_syscall for gdb_syscall_entry/return | | Claude's own fix — gap from excluding truss's cpu/ts locals |
| f1d77d1605 | bsd-user: do not pass MAP_EXCL through to the host mmap under reserved_va | | author Rick Richard, not in QEMU-SOBS |
| d81ab36f22 | bsd-user: Implement sigfastblock | | |
| 2c103a1bfd | bsd-user: Implement exterrctl(2) | | |
| 94d3211562 | bsd-user: Fix MAP_TYPE definition. | | |
| 10b3f56e65 | bsd-user: Move tb_flush stuff to begin_parallel_context | | |
| b10ae1c6db | bsd-user: FreeBSD 14 fixes | | |
| 67d4e3644a | bsd-user: catch up to cryptodev changes | | |
| d964015f23 | bsd-user: preemtively do style pass for upstreaming | | subject implies it may already be redundant with how upstream actually formatted things — double check |
| bf1fc8608a | bsd-user: Drop support for FreeBSD 12 | | policy call, confirm still wanted |
| 99fdde30a7 | bsd-user: Update copyright headers to QEMU normal. | | may overlap with the real SPDX commit (74f474eddf), which was found fully superseded/empty when tried standalone |
| bf839f2324 | bsd-user: Fix crazy bug with mmap | | |
| 13a55e8688 | bsd-user: kill tabs | | partial: only i386/x86_64/target_syscall.h (rest already reformatted differently upstream, or ppc-excluded) |
| 741fb285ee | bsd-user: HOST_BIG_ENDIAN and TARGET_BIG_ENDIAN are always | | partial: only bsd-file.h/os-misc.h/os-thread.h (truss.c + ppc hunks dropped); author Rick Richard, not in QEMU-SOBS |
| d6a3f7c523 | bsd-user: Bump FreeBSD container images | | |
| 57b5c9e472 | bsd-user: Initialize per-arch child registers | | |
| 76bdace798 | bsd-user: Add gdb for system calls | | |
| 9abd7d0289 | bsd-user: Slight rearrangement of tests | | despite the name, this is a null-check refactor in os-file.h, not test infra |
| 753949215b | bsd-user: Flag shared memory as needing atomics | | |
| b5b5948b08 | bsd-user: Make all the capacity syscalls return ENOSYS | | |
| 884fdf3209 | When loading non-PIE binary... set MAP_EXCL... | | author Maksym Sobolyev, not in QEMU-SOBS |
| 5695eaea86 | bsd-user: Add container file prototypes for 14 and 15 | | |
| 5a6460c364 | bsd-user: Create FreeBSD specific read_self_maps | | landed via git rename-detection into common-user/selfmap.c (file moved from util/ upstream) |
| 4d9487fd7b | bsd-user: Provide struct target_crypto_op | | |
| ef3385c5e5 | bsd-user: more things to ignore | | |
| c0a16676dd | bsd-user: List commits that we should ignore with git blame | | |
| 18df00038b | bsd-user: git blame ignore file | | |

Already reviewed and rejected: `target_sched_param`/`TARGET_MADV_DONTNEED`
(added, then pulled back out of both blitz and upstream-queue — see
blitz commit `4d79c035bf`).

## Known structural gaps (real design work, not mechanical cherry-picks)

- **mmap.c**: `target_mprotect`/`target_mmap` here predate a real
  multi-range rewrite in blitz (adds `validate_prot_to_pageflags`,
  coalesced host-page-range handling, a `target_to_host_prot`). Two
  small "fix" commits from blitz's recent history assumed that rewrite
  and produced code that compiled but referenced undefined variables
  when applied here alone — dropped both. Your own stashes look like
  exactly the missing piece: `ba69313010` ("fix flags to mmap", on
  `blitz`) and `697a7061ef` ("copy linux-user target_mprotect impl",
  no branch).
- **elfload.c / probe_guest_base**: `bsd-user: Copy linux-user
  probe_guest_base, with small tweaks` (51239ccbb8) targets an older
  linux-user API. Current master's `include/user/probe-guest-base.h`
  already moved to a `PGBRange`-based signature — needs porting, not
  reconciliation. Dropped, along with its dependent errno fix
  (3b22ee2524).
- **elfload.c / zero_bss**: the real, clean introduction of `zero_bss()`
  is `5b664063ce` ("Replace set_brk and padzero with zerobss from
  linux-user", 2024-06-07) plus `e3bcbd1c5d` ("Pass image name down the
  stack") threading `elf_interpreter`/image name through
  `load_elf_interp`. A later "fix a regression" commit assumed both
  were already present; landing it alone left `load_elf_interp`
  referencing an `elf_interpreter` parameter it doesn't have. Dropped.
  Should redo properly from the two real source commits above.
- **hostdep.h**: master has deprecated the whole per-arch
  `bsd-user/host/<arch>/hostdep.h` + `HAVE_SAFE_SYSCALL` +
  `ADJUST_SYSCALL_RETCODE` pattern in favor of shared
  `common-user/safe-syscall.S` + `common-user/host/<arch>/safe-syscall.inc.S`.
  That shared mechanism currently only covers 64-bit hosts (aarch64,
  loongarch64, ppc64, riscv64, s390x, sparc64, x86_64) — no i386/arm.
  Need to decide: wait for upstream to add 32-bit support, or
  contribute it.
- **bsd-proc.h**: `bsd-user/freebsd/target_os_elf.h` wants
  `#include "bsd-proc.h"` (for `bsd_get_ncpu()`) but no `bsd-proc.h`
  exists anywhere findable in blitz's history. Only the trivial
  `TARGET_ELF_PAGELENGTH` macro from that same diff got landed;
  the `#include` swap was skipped. Needs investigation — never-finished
  work, or exists somewhere not yet searched?
- **os-sys.c**: 1140-line diff vs master, completely unexamined this
  round.
- Residual diff also remains in `elfload.c`, `qemu.h`, `main.c`,
  `os-syscall.c` beyond what's captured above — likely entangled with
  the same gaps (mostly probe_guest_base/zero_bss/mmap follow-on).

## Permanently out of scope for upstream-queue

- **truss**: `bsd-user/freebsd/truss.c`, `truss_hdr.h`, `systruss.h`,
  the non-static function exposure in `strace.c`, `strace.list`
  removal — separate series.
- **elfcore**: `bsd-user/elfcore.c` — separate series.
- **powerpc**: `bsd-user/ppc/*`, `bsd-user/host/ppc*`,
  `configs/targets/ppc*.mak` — separate series.

## Blitz-local only, never upstream

`QEMU-SOBS`, `BSD-USER.rst`, `bsd-user/TODO`, the
`.github/workflows/lockdown.yml` removal, `roms/*` submodule-pointer
drift (unrelated noise from periodic upstream merges).
