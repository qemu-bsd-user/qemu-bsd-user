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

## Review status of upstream-queue (2026-09-26, 38 commits)

Status values: `upstream` (ready, going in the current batch) / `defer`
(good, holding back to keep the batch small) / `blitz-fix` (blitz's
version is wrong — the fix should go the other way, into blitz) /
`rejected` (upstream/you already said no) / `drop` (not suitable at
all). Blank = not yet reviewed.

| hash | subject | status | note |
|------|---------|--------|------|
| 9316b446b9 | bsd-user/freebsd: Small header and refactor fixes | | regrouped by Claude from blitz-tip content, no single 1:1 blitz source commit |
| 11e90600fd | bsd-user: Fix core_dump_signal signal set, add clarifying comments | | regrouped, no single 1:1 blitz source commit |
| 4ba0feeaac | bsd-user: main.c misc cleanup | | regrouped, no single 1:1 blitz source commit |
| bafa74e8f0 | bsd-user: Dynamically allocate bprm->page, fix loader_exec error path | | regrouped, no single 1:1 blitz source commit |
| 529b6eae94 | bsd-user: Small per-arch cpu-loop and thread fixes | | regrouped, no single 1:1 blitz source commit |
| bd5753e50e | bsd-user: Add get_second_rval for x86_64, i386, and arm | | regrouped, no single 1:1 blitz source commit |
| 3172713171 | bsd-user/x86_64,i386: Implement TLS, upcall, and sigtramp args | | regrouped, no single 1:1 blitz source commit |
| c1634748fb | bsd-user/i386: Implement the signal trampoline | | regrouped, no single 1:1 blitz source commit |
| d576a3f497 | bsd-user: Fix aarch64 host signal implementation | | real typo fix, mc_gregs -> mc_gpregs |
| 8bcbd66bb1 | bsd-user: eliminate the BSDtype and related infrastructure | | **reconcile before sending**: this commit restores `qemu_proc_pathname`'s definition (fixing the extern-without-definition bug found while resolving it), but blitz commit `0f0f8ed305` (2026-09-26) later removed `qemu_proc_pathname` entirely as dead code — leftover from the pre-imgact_binmisc execve self-reexec logic (see [[history-execve-prepend-vs-imgact-binmisc]]). Warner believes the restoration here is a mismerge. Drop that hunk before this goes out. |
| b823abb6bb | bsd-user: Shell script to run kyua tests | | |
| 58354d6d17 | bsd-user/riscv: note ELF_HWCAP divergence from FreeBSD kernel | | comment-only, authored by Claude this session (couldn't find the real source commit — full-history -G search timed out) |
| 7973c64e84 | bsd-user/riscv64: Fix build | | |
| 484836bea3 | bsd-user/host-signal.h: Add host-signal for all the hosts we support | | partial: only the aarch64 hunk (arm/i386/x86_64 already upstream, ppc/ppc64 excluded) |
| a3082ca19d | bsd-user-smoke: drop powerpc from smoke test list | | Claude's own commit, keeps smoke tests scoped since ppc is excluded |
| 1ec1caae75 | riscv: Don't need to specify ABI | | |
| f63476348a | bsd-user: smoke test only good on bsd-user | | |
| 5a8040840c | Kludge the lenght | | |
| 3ba98c7b71 | bsd-user-smoke: Import sources and build them | | |
| 5e3bb4ead5 | bsd-user-smoke: Kill mips | | |
| fa50987ec8 | tcg: i386 hello world for FreeBSD | | |
| 00ab33c101 | bsd-user: fix smoke test for meson < 0.56 | | |
| a60649fc98 | Add smoke tests for bsd-user. | | author Gleb Popov, not in QEMU-SOBS |
| cc4d649c97 | common-user: remove duplicate FreeBSD read_self_maps | | Claude's own fix — cherry-picking onto this branch triggered a rename-detection merge collision in common-user/selfmap.c; blitz itself still has the duplicate |
| 0025815380 | bsd-user: do not pass MAP_EXCL through to the host mmap under reserved_va | | author Rick Richard, not in QEMU-SOBS |
| 911ccd5a33 | bsd-user: FreeBSD 14 fixes | | |
| 77436fea13 | bsd-user: catch up to cryptodev changes | | |
| 43b9c86d54 | bsd-user: preemtively do style pass for upstreaming | | subject implies it may already be redundant with how upstream actually formatted things — double check |
| 98dd36ce71 | bsd-user: Update copyright headers to QEMU normal. | | may overlap with the real SPDX commit (74f474eddf), which was found fully superseded/empty when tried standalone |
| 8436a6d185 | bsd-user: kill tabs | | partial: only i386/x86_64/target_syscall.h (rest already reformatted differently upstream, or ppc-excluded) |
| 5aabf4bd00 | bsd-user: Slight rearrangement of tests | | despite the name, this is a null-check refactor in os-file.h, not test infra |
| 330a7a6e22 | bsd-user: Make all the capacity syscalls return ENOSYS | | |
| d6500db0f1 | bsd-user: Add container file prototypes for 14 and 15 | | |
| 5ab5b1c957 | bsd-user: Create FreeBSD specific read_self_maps | | landed via git rename-detection into common-user/selfmap.c (file moved from util/ upstream) |
| fe20ae817e | bsd-user: Provide struct target_crypto_op | | |
| 0ddc6c13de | When loading non-PIE binary... set MAP_EXCL while mapping the program text | drop | superseded *within blitz itself*, not just upstream: commit `58d6d6f035` ("bsd-user: Use probe_guest_base", already upstream) replaced this whole self-detect-and-retry mechanism with proactive guest_base placement in `probe_guest_base`. Sending this narrower fix now would contradict what already landed. Author Maksym Sobolyev (PR #55, closed as superseded). See [[history-execve-prepend-vs-imgact-binmisc]] for the same-shaped lesson on `qemu_proc_pathname` above. |
| b8420eb6b1 | bsd-user: Implement sigfastblock | | partial: `do_freebsd_sigfastblock()` itself already landed upstream (reformatted); only the `default:` case's `abort()` on unimplemented syscalls survives from this commit |
| 29bfded4ff | bsd-user: Add gdb for system calls | | |

Already reviewed and rejected: `target_sched_param`/`TARGET_MADV_DONTNEED`
(added, then pulled back out of both blitz and upstream-queue — see
blitz commit `4d79c035bf`).

**Dropped 2026-09-26** (rebased upstream-queue onto upstream/master
`efa3b9d5ac`; confirmed landed upstream, content now empty): `bsd-user:
Bump FreeBSD container images`, `bsd-user: declare cpu in
do_freebsd_syscall for gdb_syscall_entry/return`, `bsd-user: Drop
support for FreeBSD 12`, `bsd-user: Eliminate unused regs arg in
load_elf_binary` (confirmed — `load_elf_binary()` upstream already
takes no `regs` arg), `bsd-user: Fix crazy bug with mmap` (confirmed —
upstream's `MAP_TYPE = (MAP_PRIVATE | MAP_SHARED)` with explanatory
comment supersedes this commit's cruder `0xf`), `bsd-user: Fix MAP_TYPE
definition.`, `bsd-user: Flag shared memory as needing atomics`,
`bsd-user: git blame ignore file`, `bsd-user: HOST_BIG_ENDIAN and
TARGET_BIG_ENDIAN are always` (confirmed — the code it patches was
deleted outright by a bigger upstream refactor, not just reformatted),
`bsd-user: Implement exterrctl(2)` (confirmed — matches today's
merge-master-into-blitz conflict in `os-syscall.c`), `bsd-user:
Initialize per-arch child registers`, `bsd-user: List commits that we
should ignore with git blame`, `bsd-user: more things to ignore`,
`bsd-user: Move tb_flush stuff to begin_parallel_context` (confirmed —
matches today's `qemu.h` merge conflict, `begin_parallel_context` is
already upstream). The "confirmed" ones were hand-resolved conflicts;
the rest were automatic empty-patch-id skips from `git rebase`, trusted
without individual re-verification.

## Known structural gaps (real design work, not mechanical cherry-picks)

- **hostdep.h**: master has deprecated the whole per-arch
  `bsd-user/host/<arch>/hostdep.h` + `HAVE_SAFE_SYSCALL` +
  `ADJUST_SYSCALL_RETCODE` pattern in favor of shared
  `common-user/safe-syscall.S` + `common-user/host/<arch>/safe-syscall.inc.S`.
  That shared mechanism currently only covers 64-bit hosts (aarch64,
  loongarch64, ppc64, riscv64, s390x, sparc64, x86_64) — no i386/arm.
  Need to decide: wait for upstream to add 32-bit support, or
  contribute it. (Still open as of 2026-09-26: blitz still has all six
  per-arch `hostdep.h` files.)
- **elfload.c / zero_bss**: the real, clean introduction of `zero_bss()`
  is `5b664063ce` ("Replace set_brk and padzero with zerobss from
  linux-user", 2024-06-07) plus `e3bcbd1c5d` ("Pass image name down the
  stack") threading `elf_interpreter`/image name through
  `load_elf_interp`. A later "fix a regression" commit assumed both
  were already present; landing it alone left `load_elf_interp`
  referencing an `elf_interpreter` parameter it doesn't have. Dropped.
  Should redo properly from the two real source commits above. (Still
  open as of 2026-09-26: `5b664063ce` confirmed not an ancestor of
  upstream/master.)
- **os-sys.c**: 1140-line diff vs master, completely unexamined this
  round.
- Residual diff also remains in `elfload.c`, `qemu.h`, `main.c`,
  `os-syscall.c` beyond what's captured above.

**Resolved since last pass** (both had been listed here as open gaps;
both are actually closed):
- **probe_guest_base**: previously listed as needing porting to
  master's `PGBRange`-based signature. It's done — `58d6d6f035`
  ("bsd-user: Use probe_guest_base") is already an ancestor of
  upstream/master, and blitz's current `elfload.c:763` already calls
  it with the modern `PGBRange` signature.
- **bsd-proc.h**: previously listed as "no `bsd-proc.h` exists anywhere
  findable in blitz's history". It exists now (`bsd-user/bsd-proc.h`,
  included from `bsd-proc.c`, `target_os_elf.h`, `os-sys.c`,
  `os-syscall.c`). Unclear when/how it reappeared — not re-investigated,
  just confirmed present. If picking this back up, check whether it's
  actually complete or another partial landing.

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
