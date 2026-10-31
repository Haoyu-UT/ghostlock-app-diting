# 32-bit compat victim and the `_newselect` carrier (plan)

Level: **L** — a new victim architecture and a new select carrier on the attack-critical path.
Plan first, then code (`AGENTS.md`); this document is the operator-approval artifact.

Status: **design only, 2026-10-31 — QEMU measurements complete; no code; no device run.**
Awaiting the operator's decision between the options below.

## The problem

The sigreturn-only kernels (5.10.43, 5.10.81, 5.10.101; six store images) have no 64-bit
blocking carrier. The stale `rt_mutex_waiter` strip sits at depth **0x1c0** below the
syscall-entry sp (0x58 bytes at depths 0x168–0x1c0). A 42-candidate sweep of unprivileged
64-bit syscalls found only `rt_sigreturn`'s 0x200-byte fpsimd copy (destination 0x300)
spanning it: the closest others are `clone3` 0x1a0, `recvmmsg` 0x198, `bpf` 0x190 and
`sendmmsg` 0x180 (each short at the deep end), while `pselect6`'s 0x210 buffer zeroes the
shallow half through its `res_*` slots and the `ptrace` regset copies are too deep
(0x338/0x460). `PR_SET_MM_MAP` is compiled out, mqueue/SysV IPC are off, and the remaining
big copies are capability-gated.

`rt_sigreturn` stamps correctly but returns the victim to EL0, where the `+0x188`
context-switch class can paint the strip: ~50 % on 5.10.236 and 4/5 on the 81-era rig
(one unrelated W3 failure). A carrier that parks the victim in-kernel would remove that
exposure on the kernels that need it.

## What the 2026-10-31 measurements say (QEMU, host-only)

A 32-bit (AArch32/compat) victim changes both sides of the geometry, because the futex
chain and the select implementation are different kernel code. All numbers below are
measured on the six store images (identical), with the armv7 victim under the existing
QEMU harness; the direct readbacks were taken with a kprobe over the parked victim's
stack.

### Required depth

| victim | futex entry | entry→`do_futex` | entry→`futex_wait_requeue_pi` | strip home |
|---|---|---|---|---|
| 64-bit | `__arm64_sys_futex` | 0x90 | 0xb0 | 0x1c0 |
| 32-bit | futex_time32 (240) | 0x80 | 0xa0 | **0x1b0** |
| 32-bit | futex_time64 (422, `__arm64_sys_futex`) | 0x90 | 0xb0 | **0x1c0** |

(waiter local at `futex_wait_requeue_pi.sp − 0x110`.)

### Compat select carriers

- `pselect6` (335) and `pselect6_time64` (413): the `compat_core_sys_select` buffer
  destination is **0x250**; the user region is [0x1d8,0x250] and the `res_*` zeroing
  [0x160,0x1d8] covers the strip. **Fails**, and is 0x40 deeper than the 64-bit buffer.
- `_newselect` (ARM syscall 142, `compat_sys_select`): the buffer destination is **0x1e0**;
  the three in/out/ex copies span **0x78 bytes at [0x168,0x1e0]**.
  - With **futex_time64** (strip 0x1c0), the 0x58-byte stamp occupies buffer offsets
    0x20–0x77, so the whole strip is user-copied — one byte of margin.
  - With **futex_time32** (strip 0x1b0), the user copy covers strip bytes 0–0x47 and the
    kernel's `res_*` zeroing supplies bytes 0x48–0x57 — exactly the stamp's zero
    `deadline`/`ww_ctx` (`waiter_words()` sets both to 0).

### Readback and parking

- The 11 stamp words are read back exactly from the parked victim's stack on every one of
  the six images: `0x1122334455667700..770a` at home 0x1c0 (time64) and
  `0x2233445566778800..8808, 0, 0` at home 0x1b0 (time32).
- The fd_set bytes **are** the stamp, so every set bit must map to an open, non-ready fd.
  320 empty-pipe read ends at fds 0..319 (write ends kept open at 640..959; max_fds 1024;
  nfds 320 is not clamped and stays on the 256-byte stack path: size 0x28, 6×0x28 ≤ 0x100)
  satisfy it: the victim parks in `do_select` and is killed by SIGKILL with the stamp in
  place. The stamp's low bits fall on fds 0..7, which are read ends too.
- Other compat candidates fail: ppoll 0xf0 @0x404; sendmsg compat msghdr 0x1c @0x1a0
  (partial); recvmsg msghdr @0x120; sendto sockaddr @0xe8; compat iovec imports are
  `__get_user` loops; the compat sigreturn path copies only 8 bytes.

### The 5.10.236 control and the scope

On 5.10.236 the compat strips are **0x200** (time32 chain 0xf0) and **0x210** (time64
chain 0x100), while the `_newselect` buffer stays at 0x1e0 — it cannot reach them. A
32-bit-only app (or a 32-bit victim on 5.10.136+) would lose the select route, so the
compat carrier must be scoped to the sigreturn-only kernels.

## Design options

**A. A 32-bit build of the exploit native, run as its own helper process on the affected
kernels (recommended).** Both exploit threads live in the 32-bit process, so private
futexes and the existing choreography are unchanged; only the syscall numbers
(futex 240/422, select 142) and the carrier's buffer placement differ. The 64-bit app
stays the supervisor/UI and keeps its 64-bit route for 5.10.136+.

**B. A victim-only 32-bit helper with the 64-bit native as collaborator.** Requires the
futex to be shared (`MAP_SHARED` key) and a cross-process version of the requeue/walk
choreography. The kernel supports shared PI futexes, but the exploit's races and the
anchor handoff would cross a process boundary; more unknown, more code.

**C. Status quo.** The 81/101 floor stays sigreturn (4/5 on the 81-era rig); nothing
changes.

Recommendation: **A** for the first gate; **B** only if A's shipping/exec path is blocked.

## Implementation outline (option A)

1. **Build**: add the `armv7-linux-androideabi` native target. Audit the native for
   64-bit pointer assumptions in the victim/route paths; the stamp's kernel words stay
   64-bit values written as bytes, and the shared-memory protocol uses fixed-width fields.
2. **Helper lifecycle**: ship the 32-bit native, launch it when the profile's kernel family
   is the sigreturn-only series, supervise it, and relay its log/run-store records. The
   helper must be exec'able by the app *before* W1 makes SELinux permissive (open question
   below).
3. **Carrier**: a compat variant of the select route.
   - Prepare the fd table: 320 empty-pipe read ends at fds 0..319, write ends kept open,
     RLIMIT_NOFILE/max_fds checked.
   - Wait via futex_time64 (422) where possible (strip 0x1c0, full user stamp); futex_time32
     (240) is the fallback with the zero tail.
   - Build the 0x78-byte select bitmap with the stamp at offset 0x20 (time64) or 0x30
     (time32).
   - Call `_newselect` (142) with nfds 320 and let the victim park in `do_select`.
   - The route's existing anchor/scratch policy applies unchanged; the carrier is
     orthogonal to the page-free flag.
4. **Route selection**: gate the compat route on the kernel family; 5.10.136+ keeps the
   64-bit select; the sigreturn route stays as the fallback.
5. **Tests**: a host unit for the buffer offsets and the fd-table setup; a QEMU
   end-to-end run (futex dance → select park → walk) on the 81/101 images; the readback
   harness as a regression.
6. **Device gates**: 5.10.81 (the era rig, re-flash with in-turn approval) and a 5.10.101
   ROM; 5 fresh boots each, the run store as the metric; 5.10.236 is the control (the
   64-bit route unchanged). 5.10.43 has no device — derivation only.

## Open questions / risks

- **Which task is the stack donor.** If the victim must also be the W2/W3/handoff task,
  the helper carries the root chain; a 32-bit process can `exec` the 64-bit `ksud` after
  W1, but the handoff protocol needs a design.
- **Android exec of the helper before W1.** `W^X`/SELinux may refuse `execve` from the
  app's native-lib dir or data dir. This is the decisive product question; if blocked,
  option B or a 32-bit variant APK is the fallback.
- **Helper ↔ app protocol / run-store identity.** The app's run store is written by the
  64-bit native today.
- **The fd table**: fds 0..319 are replaced, so the helper must log through fds ≥ 320 (or
  the write ends); `RLIMIT_NOFILE` and `max_fds` must admit 320.
- **The one-byte margin**: a +8 shift of the compat select chain on a future image would
  clip the last stamp byte (the zero `ww_ctx` high byte); keep the per-image derivation in
  the gate.
- **time32 vs time64**: time64 gives the full user stamp; time32 relies on `deadline` and
  `ww_ctx` staying zero, which `waiter_words()` guarantees today.
- **Device logistics**: the era rig is a re-flash and the 101 ROM must be staged; the
  operator approves flashes per turn.
- If **B** is chosen instead: shared PI-futex semantics across processes and the anchor
  handoff are the first gates.

## Approval

Awaiting the operator's decision on option A vs B (or C). No code until then.
