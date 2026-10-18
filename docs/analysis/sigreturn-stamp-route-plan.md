# Sigreturn fpsimd stamp — a delivery route for the pre-5.10.136 geometry

Level: **L** — a new middleware route on the attack-critical path. This document is the
operator-approval artifact; the measurements it cites are recorded in the port's run archive.

## The problem

`route.select_stack` cannot stamp the fake waiter on the two Android-12-era diting kernels
(`5.10.81`, `5.10.101`). `do_futex`'s frame is `0x20` there versus `0x70` from `5.10.136` on, which
places the `futex_wait_requeue_pi` waiter at depth `0x1c0` instead of `0x210` below the
syscall-entry sp. The pselect6 fd_set buffer's depth is fixed at `0x210`; only waiter bytes
0x00–0x27 land in it, and the walk dereferences `lock` (+0x38), `prio` (+0x40) and `deadline`
(+0x48). The route refuses at `prepare()` rather than feed the walk zeros.

A partial stamp cannot work: `core_sys_select` zeroes its `res_*` slots unconditionally after the
user copy and before `do_select`, and on that geometry the waiter's words 5–10 land in exactly
those slots. The fix must land deeper: a syscall that copies the full 0x58-byte strip while its
frame is live.

## The primitive

`rt_sigreturn` → `restore_sigframe` → `restore_sve_fpsimd_context` (SVE frames) or
`restore_fpsimd_context` (plain), which performs `__copy_from_user(vregs, ctx->vregs, 0x200)`.
Frame geometry on 5.10.81/101 (image disassembly; Σ = chain sum):

| function | frame | chain Σ |
|---|---|---|
| `__arm64_sys_rt_sigreturn` | 0x50 | 0x50 |
| `restore_sigframe` | 0x60 | 0xb0 |
| `restore_sve_fpsimd_context` | 0x270 | **0x320** |
| `restore_fpsimd_context` | 0x250 | **0x300** |

The copy destination is sp+0x10 on the SVE path and sp+0x00 on the plain path, so waiter byte 0
maps to buffer offset `Σ − dst_off − waiter_depth`: **0x150 / 0x140** on 5.10.81, **0x100 / 0xf0**
on 5.10.236. Both are 8-byte aligned, and the 0x200-byte copy covers the whole strip.

The copied bytes are opaque user memory from the signal frame; no post-copy rewrite touches the
strip (only `fpsr`/`fpcr` at ≥0x1f0 and the task's SVE state elsewhere). `rt_sigreturn` is syscall
139 with no capability gate.

## Choreography (variant B, as built)

Variant A — stamp from a delivered frame and return to EL0 — was measured dead: every interrupt
from EL0 writes scheduler frames through the strip (depth 0x290 measured), and the next
`tgkill`'s own delivery clobbers it. The route instead makes `rt_sigreturn` the carrier:

1. `prepare()` installs an `SA_SIGINFO` handler for the first free of `SIGUSR1`, `SIGRTMIN+4`,
   `SIGRTMIN+5`, blocks every other async signal for the window, and builds the first stamp.
2. One `tgkill` enters the handler. The handler splices the eleven waiter words into the delivered
   frame's fpsimd record, copies the frame twice (0x2000 bytes, 16-aligned), and rewrites `sp`/`pc`
   in both the delivered frame and the loop copy.
3. The `rt_sigreturn` that follows resumes at `sigreturn_loop_trampoline` with `sp = loop_frame`.
   The naked loop spins on `cntvct_el0` until the next copy is due (500 µs), performs
   `mov x8, #139; svc #0`, and repeats. The copy is the region's only writer; `parse_user_sigframe`
   recreates its local at exactly the strip's depths at the top of each iteration, so the spin is
   what keeps the strip stable for the walk.
4. On the `cntvct` deadline the loop restores the pristine frame and returns; `stamp_window`
   resumes and `execute()` drains the consumer, disarms, and reads its counters as usual.

The write vehicle is untouched: `waiter_tree_stamp()`, the zeroed pi triple, the anchor-slot grid
and the leaf/pointer arms are the select route's. Only the delivery changes.

## Profile surface

```
route.sigreturn {
    waiter_off_sve   = 0x150
    waiter_off_plain = 0x140
    lock_anchor_image / lock_anchor_bytes / lock_anchor_stride   # the select route's trio
}
```

`waiter_off = Σ_variant − dst_off − waiter_depth`, derived from each image's own frames. Both
offsets are required, 8-aligned, non-zero, and must leave room for the strip in the copy window;
otherwise the route refuses at `prepare()`. A document never merges another route's section, so the
anchor trio is stated here too.

## Gates and evidence

- Host: `sigreturn_route_test` pins the geometry refusals, the record walk, the strip placement
  (including "nothing outside the strip moves"), and the lifecycle.
- Attack path: native build with zero warnings, `lint-tidy`, `cmp_disasm` against a baseline, and a
  real-device gate with an archived record.
- Device evidence for the route: the 236 rig delivered the stamp byte-for-byte at the predicted
  offset (`pi_blocked_on − copy_dst = 0xf0`) with the walk reading the anchor, and the era rig
  (5.10.81) carried the whole chain in 4/5 fresh-boot runs at the 500 µs interval. The 500 µs
  value is the measured arm: 500 µs ran 4/4 where 20 µs ran 4/6 and 100 µs 2/4.

## Risks

- **Preemption of the spinning victim.** An IRQ from EL0 writes `pt_regs` and the deferred
  scheduler frames through the strip (measured depth 0x290). The 500 µs re-stamp loop repairs a
  clobbered window; only a tick inside the sub-µs read window costs the attempt, which is the
  route's normal retry unit.
- **FP side effect.** The restore loads the strip into the victim's FP/SIMD registers; the loop and
  everything after the first stamp are integer-only.
- **Signal hygiene.** The route refuses if every trigger candidate is already handled; the previous
  disposition and the thread mask are restored in `destroy()`.
- **Anchor accounting.** One slot per attempt from the same boot-scoped allocator as select_stack;
  a spent budget is a clean refusal, never a walk past the region.
