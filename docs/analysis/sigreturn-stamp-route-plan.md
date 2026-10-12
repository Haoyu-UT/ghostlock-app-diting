# Sigreturn fpsimd stamp — a delivery route for the pre-5.10.136 geometry (plan)

Level: **L** — a new middleware route on the attack-critical path. Plan first, then code, per
`AGENTS.md`; this document is the operator-approval artifact.

Status: **P1 built offline, 2026-10-12 — uncommitted, no device run.** The route, its encoder, the
profile plumbing and the host tests exist on `experiment/sigreturn-stamp` (off `port/diting-5.10`,
uncommitted); native build, `lint-tidy`, the host suite and the offline APK build are green. The
branch is not a review or release unit — per `BRANCH-POLICY.md` the port line remains the home of
the eventual commit cluster, and nothing moves there until a real-device gate passes. What the
device still has to answer is itemized at the end of this document.

## The problem

`route.select_stack` cannot stamp the fake waiter on the two Android-12-era diting kernels
(`5.10.81`, `5.10.101`). Measured on those images: `do_futex`'s frame is `0x20` there versus `0x70`
from `5.10.136` on, which places the `futex_wait_requeue_pi` waiter at depth `0x1c0` instead of
`0x210` below the syscall-entry sp. The pselect6 fd_set buffer's depth is fixed at `0x210`; the
route can only reach waiter words via its 15 user-controlled window words, which now touch waiter
words 0–4 only (bytes 0x00–0x27 — the tree-entry triple plus `pi_tree.pc`/`right`). The walk
dereferences `waiter->lock` (+0x38), `prio` (+0x40) and `deadline` (+0x48). The route refuses at
`prepare()` rather than feed the walk zeros.

The alternative — a partial-stamp mode running with whatever content sits in the unreachable tail —
is refuted. `core_sys_select`'s stack buffer is 30 contiguous words: 15 user-copied (`in/out/ex`),
then 15 `res_*` slots that `zero_fd_set` zeroes **unconditionally, after the copy, before
`do_select`**. On the below-floor geometry the waiter's words 5–10 land exactly in those zeroed
slots, so the pselect call itself zeroes `pi_left`, `task`, `lock`, `prio`, `deadline` and
`ww_ctx` on every attempt; while the call is blocked the res slots are exactly zero (any ready fd
would set a bit, increment `retval`, and return the call). `lock = 0` is a NULL dereference in the
walk. No workaround survives: a pre-stamp from an earlier syscall is destroyed by the same call's
`zero_fd_set`, and shaping the res bits through ready fds is self-defeating (readiness is what
returns the call, and a returned call has no frame to walk).

The fix must therefore *land deeper*: a syscall that copies ≥ 0x48 user-controlled bytes spanning
the waiter's 0x58-byte strip while its frame is live.

## The primitive

`rt_sigreturn` → `restore_sigframe` → `restore_sve_fpsimd_context` (SVE-carrying frames) or
`restore_fpsimd_context` (plain), which performs:

```
__copy_from_user(fpsimd.vregs /* sp+0x10 */, ctx->vregs, 0x200);
```

Measured on the 5.10.81 image (frame sizes from the image's own disassembly; Σ = chain sum):

| function | frame | chain Σ |
|---|---|---|
| `__arm64_sys_rt_sigreturn` | 0x50 | 0x50 |
| `restore_sigframe` | 0x60 | 0xb0 |
| `restore_sve_fpsimd_context` | 0x270 | **0x320** |
| `restore_fpsimd_context` | 0x250 | **0x300** |

The copy destination differs between the two helpers — **SVE: sp+0x10, plain: sp+0x00**
(disassembly-verified on both images; the plain offset was *corrected by the P1.5b device run*,
which caught it at runtime). The waiter byte 0 therefore maps to buffer offset
`Σ − dst_off − 0x1c0`: **0x150** (SVE) / **0x140** (plain) on 5.10.81 — 8-byte aligned. The 0x200-byte copy spans
waiter bytes −0x150…0xa8 (SVE), i.e. it covers the whole 0x00–0x57 strip with room to spare.

Why it clears the filters that killed every other candidate:

- **Content is ours.** The copy source is the fpsimd record inside the *user's own* signal frame —
  plain user memory. The record's format checks (`FPSIMD_MAGIC`, size) are `get_user` reads of user
  memory performed *before* the copy, and they live at the record's header (bytes 0–7), not in the
  copied `vregs` region. The 0x200 copied bytes are opaque.
- **No post-copy rewrite of the strip.** At instruction level, the only writes into the local after
  the copy are `fpsr`/`fpcr` at buffer offsets ≥ 0x1f0 — outside the waiter mapping; the function's
  other `memset` targets the task's SVE state buffer (`[x22, #0x10c0]`), not the stack local.
- **Reachability.** `rt_sigreturn` is syscall 139, wired in `sys_call_table`, no capability gate.
- **No block needed.** `rt_sigreturn` returns; the stamp then survives the return path (shallow
  exit frames) and is only rewritten by later syscalls on that thread — see the linger model in
  "Choreography".

## Why this fits the exploit unchanged

The write vehicle is untouched: the fake waiter's contents come from the same shared definition
(`waiter_tree_stamp()` — the tree triple {pc/right/left}, the zeroed pi triple, task/lock/prio/
deadline/ww_ctx), the same anchor-slot mechanism, the same leaf-collateral zero-write and pointer
arms. Only the *delivery* changes: which syscall carries the stamp into the stale stack slot.
The route is additive — a fourth backend beside `select_stack`, `tcp_zerocopy` and
`multicast_waiter`, selected by a `route.sigreturn` block; `select_stack` stays the default where
it is feasible.

## Choreography

**Variant A (primary) — a real signal whose frame the handler patches.** The kernel builds the
sigframe (so the frame is valid by construction), and the handler edits only the vregs region.

1. Setup: the victim installs a `SA_SIGINFO` handler for one trigger signal and blocks every other
   signal, so nothing else can disturb the window.
2. The futex dance runs exactly as today (the stale waiter is left by the victim's
   `futex_wait_requeue_pi`; the anchor operations are the collaborator's).
3. The victim publishes "ready" in shared memory and enters an **integer-only** spin loop (no
   syscalls, no FP dependencies — see the side effect below).
4. The collaborator observes "ready" and sends the trigger with `tgkill`.
5. The handler runs. It locates the fpsimd record in its own `ucontext` (walk the record list by
   magic — which also tells it which variant the kernel delivered: SVE record present → SVE path),
   writes the 11 waiter words into the record's `vregs` at the variant's offset, publishes
   "patched", and returns. No syscalls in the handler.
6. The handler's return invokes `rt_sigreturn`; the kernel performs the copy — **this is the
   stamp** — and resumes the interrupted context (the spin loop, by construction: the signal hit the
   victim *while it was spinning*). The spin loop's first instruction publishes "back".
7. The collaborator sees "back" and drives the anchor/walk sequence.

**Variant B (alternative) — SROP: call syscall 139 directly.** The victim builds the whole sigframe
in user memory and executes `mov sp, frame; mov x18, <saved>; mov x8, #139; svc #0` — no signal, no
handler, no `tgkill`. The kernel restores *all* registers from our frame, so the resume state is
ours. Simpler sync, but the frame must be complete and valid (x18/shadow-call-stack, pstate, the
`access_ok`-checked frame extent) or the kernel force-sends SIGSEGV. Only worth pursuing after
variant A works; the frame format should be lifted from a real sigframe captured on the device
rather than guessed.

**Invariants the implementation must keep.** The copy is the *last* writer of the strip; the victim
makes no syscalls between step 6 and the walk; all non-trigger signals are blocked for the whole
window; no anchor operation is issued between the futex dance and "back".

## New risks, and the measurements that decide them

1. **Preemption of the spinning victim — measured (P1.5a, 2026-10-12), bounded, mitigated by
   re-stamping.** In the linger window the victim is in user mode; an IRQ entry from EL0 takes
   `pt_regs` on the *task* stack, and the deferred work (`ret_to_user` → `do_notify_resume` →
   `schedule()`) then runs from that reference downward. Measured statically on both 5.10.236 and
   5.10.81 (identical shapes): `do_notify_resume` 0xa0 + `schedule` 0x20 + `__schedule` 0x80 =
   0x140, plus the callees that run before the switch point — `rcu_note_context_switch` 0x70,
   `pick_next_task_fair` 0x60 (+ `update_curr` 0x40), `psi_task_switch` 0x60 →
   `psi_group_change` 0x80, `check_and_switch_context` 0x40, `__switch_to` 0x40 — for a
   common-path bound of **≈0x1e0** and a worst case of **≈0x220**. Both exceed the strip's shallow
   end (0x1b9 on 236, 0x169 on 81): *a tick (HZ=250, PREEMPT=y) landing inside the window can
   write into the stamp*. This refutes the earlier hope that the chain would be shallow enough to
   be nil. (The incumbent select_stack route is immune by design — its carrier parks *inside* a
   syscall, so scheduler frames nest below the fd_set buffer; the linger model gives that up.)
   **Mitigation: the victim re-stamps on a timer.** Re-running the sigreturn rewrites the strip by
   construction, so the victim loops — stamp, spin for ~100–200 µs of `cntvct_el0` counter time,
   stamp again — until the collaborator reports the walk fired. A clobbered window is refreshed;
   only a tick landing inside the sub-µs read window itself costs the attempt, and a failed attempt
   is already the route's normal retry unit. **Empirical depth measured by P1.5b: 0x290** (8/8
   samples during a user-mode spin, via the `__switch_to %sp` probe) — the static estimate ran
   low; trust the measured number. P2 measures the residual failure rate with the re-stamp loop
   active.
2. **FP side effect.** The restore loads the stamp bytes into the victim's FP/SIMD registers. The
   spin loop and everything between the stamp and process exit must be integer-only (a purpose-built
   carrier, not compiled C relying on FP). The kernel does not touch the task stack for FP state
   (saves go to `thread_struct`), so the side effect is userspace-only.
3. **Frame validity (variant B only).** A malformed frame → `force_sig(SIGSEGV)`. Mitigated by
   capturing a real frame first.
4. **Timing margins.** The collaborator's "back"→walk latency must fit inside the (short) window
   where the stamp is live and the victim is otherwise idle; the existing knobs
   (`route_wait_ms`-class delays) shrink to a memory-polled handshake, which is *tighter* than the
   current 30 ms park but has no kernel-side keep-alive.

## Profile surface (as built)

```
route.sigreturn {
    waiter_off_sve   = 0x150   ; waiter byte 0 inside the copied vregs (SVE path)
    waiter_off_plain = 0x140   ; same for the plain path
    lock_anchor_image  = …     ; the same three anchor keys route.select_stack carries --
    lock_anchor_bytes  = …     ; the anchor region is one shared kernel object, and a document
    lock_anchor_stride = …     ; never merges another route's section
}
```

Derived mechanically from the build's frames (`waiter_off = Σ_variant − dst_off − waiter_depth`).
5.10.81: 0x150 / 0x130 (disassembly-verified). 5.10.101 shares the same `do_futex` geometry and its
image is in hand, but its own frames are not yet measured — verify from that image before writing
its profile row. The current device build (5.10.236, waiter depth 0x210) was measured as well:
Σ 0x320 (SVE) → 0x100, plain 0x300 → 0xf0, full coverage — and the plain-path placement was
**confirmed at runtime** by the P1.5b falsifier (below) — **so the mechanism is fully gate-able on
the hardware in hand**; the below-floor rows stay *candidate* (that kernel does not boot the installed userspace —
measured separately), with their geometry resting on static disassembly.

## Implementation sketch (P1)

- `src/core/route/sigreturn_route.{h,cpp}` — feasibility check, the sync protocol, the signal
  choreography (A) and, later, the SROP trampoline (B).
- An encoder, pure and host-testable: `sigreturn_stamp_encode(frame_bytes, off, layout)` reusing
  `waiter_tree_stamp()`; fixed-vector test in the style of `payload_builder_fixed_vector_test`.
- Profile plumbing: the `route.sigreturn` block; backend registration; default selection unchanged.
- Native gates: NDK build with zero warnings, `make -C src lint-tidy`; attack-path gate
  `tools/cmp_disasm.py` if any shared payload code moves (it should not), then a real-device gate
  with an archived record.

## Sequencing

- **P0** — scratch branch `experiment/sigreturn-stamp` (off the port line). All experiment commits
  stay here; on a passing gate they land as one commit cluster on `port/diting-5.10`.
- **P1** — host: encoder + route skeleton + vector tests; off by default.
- **P1.5 (cheap falsifiers, no exploit involved)** — (a) **done, 2026-10-12: the preemption chain
  is NOT shallower than the strip** — it bounds at ≈0x1e0 common / ≈0x220 worst on both builds
  (numbers in Risk 1), so the design gains the re-stamp loop and P2 must measure the residual rate.
  (b) **done, 2026-10-12, on 5.10.236 (rooted session): the depth model is VALIDATED at runtime.**
  The probe caught the copy itself (`__arch_copy_from_user d=… n=0x200`) landing at Σ-depth 0x300 —
  exactly the static value (wrapper 0x50 + restore_sigframe 0x60 + plain helper 0x250, dst sp+0x00);
  the wrapper-entry reference sp is *identical* across syscalls (rt_sigreturn vs getpid); and the
  handler's ramp pattern appeared on the kernel stack byte-for-byte at the predicted offset. Two
  corrections came out of it: the **plain helper's dst is sp+0x00, not sp+0x10** (plan offsets
  fixed above), and **kprobe traps cannot observe the shallow ~0x230 of the buffer** (the trap's own
  pt_regs+handler footprint covers it — method note for all future stack readbacks). It also pinned
  the empirical preemption depth during a user-mode spin: **0x290** (Risk 1). Evidence under
  `sigret/run-1/` in the port tree; the (c) item (real sigframe for variant B) is not needed unless
  B is pursued.
- **P2** — single gate run on 5.10.236 with the new route selected.
- **P3** — 3-run series (reboot between runs), then the below-floor geometry rows marked candidate.
- **P4** — docs (port README, k81-era analysis) and PR evaluation.

## P1 as built (offline, 2026-10-12)

Native:

- `src/core/route/sigreturn_route.{h,cpp}` — the route. Pure, host-testable core
  (`geometry_from`, `locate_fpstate`, `patch_fpstate`) plus the Android half: the SA_SIGINFO handler
  that locates the delivered frame's fpsimd record and splices the strip into it, the
  `tgkill(self)` re-stamp loop (30 ms window, 4 attempts, one anchor slot per attempt, the same
  page-respray-on-retry ladder as select_stack), and the same prepare/execute/disarm/destroy
  lifecycle. The trigger signal is chosen at runtime: the first of `SIGUSR1`, `SIGRTMIN+4`,
  `SIGRTMIN+5` whose disposition is still `SIG_DFL`, so the route can never silently take over a
  handler another component installed; the previous disposition and the thread's signal mask are
  restored in `destroy()`. The window blocks the process's other asynchronous signals (synchronous
  faults stay deliverable) and unblocks the trigger on the victim thread.
- `memory/payload_builder.{h,cpp}` — `WaiterWords` + `waiter_words()` + `encode_waiter_words()`:
  the eleven-word strip the select route's compact branch stamps, now a single definition
  (`payload_builder_test` pins the exact bytes: leaf `{target-8,0,0}` / pointer
  `{value,0,target}`, zero pi triple, `prio` 140).
- `route/lock_anchor.{h,cpp}` — the anchor grid + boot-scoped slot allocator, moved out of
  `select_stack_route.cpp` unchanged (statement order, log text, error numbers preserved) so both
  routes draw from one serial. The select route's call site is the only edit there.
- `profile/model.h`, `profile/binary.cpp` — `RouteKind::Sigreturn` (wire 4), the `route.sigreturn`
  section (`waiter_off_sve`, `waiter_off_plain`, plus the shared `lock_anchor_*` trio), and the
  route accepted by the decoder.
- `route/route_policy.hpp`, `route/component_catalog.hpp`, `route/orchestrator.hpp`,
  `session/backend/cve_2026_43499_backend.cpp` — the policy, the middleware id, the dispatch
  target, the pipeline, the explicit instantiations. Every capability is the neutral default:
  same write vehicle, same W3 leaf-direction probe, no fallback.

Kotlin:

- `RouteKind.SIGRETURN(4)` + `SigreturnConfig` (the two offsets + the anchor trio), the
  `route.sigreturn` section name, and the resolver mapping for the bare `sig.*` paths.
- **Cross-route contract change (flag for review):** the consumer's `consumer_max_calls` /
  `consumer_burst_calls` were always sourced from the *select_stack* branch of the merged profile.
  They are now read from the active route's own group with the select_stack path kept as the legacy
  source, so every existing profile resolves to exactly the value it did before while a sigreturn
  profile can state its cadence. `execution-sigreturn.conf` (1 call / 1 burst, the measured diting
  cadence) ships as the preset, and `ProfileConfig.Routes` lists the route.

Gates run: native build (0 warnings), `make -C src lint-tidy` (exit 0), the full host suite green
(the pre-existing x86_64-only `tcp_zerocopy_route_test` build failure aside), `:profile-core:test`
green, `:app:testDebugUnitTest` green apart from the pre-existing
`ProfileMigrationEquivalenceTest` fixture-count failure, `:app:assembleDebug` offline green.

`tools/cmp_disasm.py` (baseline = this branch at `2d83582`, built in a scratch worktree) **FAILs**,
and as the tool's own note requires, it has to be read:
`MISSING multicast_owner_worker/multicast_waiter_worker` on both binaries is the documented
baseline-vs-itself artifact; `owner_thread`, `consumer_thread`, `run_main_route_threads`,
`do_kernel5_fake_lock_route`, `do_one_write` are LAYOUT-SHIFT only (annotated address operands);
the one real difference is `waiter_thread`: 895 → 276 instructions. Isolated in a scratch copy, the
cause is the **fourth entry in `RoutePolicyList`**: with `SigreturnPolicy` removed from the list (my
other changes kept) `waiter_thread` returns to its baseline shape, and the inlined route dispatch
reappears inside `run_orchestrated_pipeline` (+0x1134) instead. Behavior is unchanged — the
statements and their order are identical, the dispatch is simply no longer inlined into the worker
— but the project treats every attack-path shape change as device-gated, so P2's regression item
covers it, and a reviewer may want the dispatch kept out of the worker on purpose rather than by
inliner accident.

## P1.5c — the in-app measurement (2026-10-12, device, verdict: variant A as designed does not deliver)

Run on 5.10.236 with the KSU-patched boot flashed (persistent root), the port's probe
kit plus purpose-built probes (adjust_pi with task/waiter prios, the eleven waiter
words read through `pi_blocked_on` at the walk, the fpsimd copy's destination, and a
pre-copy sampler of the copy's own local). Evidence: `sigret-app/` in the port tree.

What is now **measured, not inferred**:

- The stamp is delivered *identically to the design*: `stamps=3659 misses=0 path_sve=0`
  (plain path, `off_plain=0xf0`), trigger SIGUSR1, anchor rotation and account exact,
  W1's stamp shape byte-identical to select's.
- **The geometry is right in-app**: `copy_dst = rt_sigreturn_entry_sp − 0x300` (the
  static Σ) and the walk's `pi_blocked_on − copy_dst = 0xf0` exactly — the strip lands
  on the byte the walk dereferences.
- **The walk runs** on every consumer call: `rt_mutex_adjust_pi` → chain, with the
  victim at prio 120 vs the stamp's 140 (the prio gate passes) and `orig_lock == 0`,
  `orig_waiter == 0` — the same signature the working select route shows.
- **But the walk reads clobbered stack**: in the control (select, W1 landed) the walk's
  `next_lock` is the anchor every time; in the sigreturn route eight consumer-side
  walks read a task pointer, image pointers or 0 — never the anchor. One of the zeros
  oopsed at `rt_mutex_adjust_prio_chain+0x188` dereferencing it as `lock`.
- The clobbering writer is the loop's own syscall traffic: a ladder probe shows the
  signal-delivery frames (canaries, self-referential stack pointers) at exactly the
  strip's depths, and a pre-copy sampler of the copy's own 0x200-byte local shows the
  region zeroed between consecutive stamps. A 300 µs *user-mode* spin between stamps
  (99 stamps/30 ms) did not change it.

**Structural reading.** `route.select_stack` parks the victim inside the carrier, so
the stamp *is* the carrier's own local and everything else nests below it — the walk
can never read anything but the stamp. Variant A writes into a dead region, and every
subsequent syscall on that thread (above all the next `tgkill`'s delivery) runs
through those depths. Variant B's `rt_sigreturn` loop is the carrier that owns the
region continuously (its only writer is the copy itself), so the sequencing in
"Sequencing" above is superseded: **B is now the route, A is the measured-dead
scaffold** (kept for its evidence and for the probe kit's calibration path).

Consequence for the profile surface: unchanged (the offsets are the same arithmetic);
what changes is the choreography — userspace builds one valid frame (captured from a
real delivered frame, per Risk 3), the handler's first delivery points `sp` at it and
`pc` at a `svc #139` loop, and the loop exits on a `cntvct_el0` deadline.

## Device verification list (P2/P3)

1. **Route recognition.** Import a profile whose `route { sigreturn { … } }` block carries the
   5.10.236 offsets (`waiter_off_sve = 256`, `waiter_off_plain = 240`) on the current build; the run
   log must show `sigreturn pre-stamp` with both offsets echoed, not `geometry unusable`.
2. **Trigger-signal selection.** The log's `sigreturn trigger: signal=…` line must name a signal the
   process had free; if every candidate was already handled, that is a finding (the route refuses —
   check whether ART owns `SIGUSR1` on this ROM).
3. **The stamp actually happens.** `post-stamp … stamps=N misses=M path_sve=P` with `N` in the high
   hundreds to thousands (one stamp per tgkill round trip, for the ~5 ms until the walk fires) and
   `M` near zero; `path_sve=0` expected on this userspace.
   `M` climbing with `N` near zero means the frame never carried a fpsimd record.
4. **The write lands at all.** W1 (`selinux_enforcing` → permissive) observed by the existing
   verify path on the first attempt or a retry; this is the first proof the walk accepts a
   sigreturn-stamped waiter.
5. **The full chain.** `child uid = 0` → seccomp cleared → `exploit complete` → KernelSU late-load,
   with the same stage-by-stage log as the select_stack route.
6. **Re-stamp rate vs the walk (Risk 1).** Per-attempt failure distribution over ≥10 attempts: the
   tick-clobber exposure is only bounded by the loop, so this measures whether the residual rate
   beats the incumbent route's.
7. **Signal hygiene.** After a run, the process's disposition for the chosen signal and the victim
   thread's mask are back to their previous values (no leaked handler), and ART-side behaviour
   (GC, ANR dumps) is unaffected during the window.
8. **FP side effect.** Confirm the victim's integer-only loop survives the strip landing in its FP
   registers, and that the *stage verify* (which runs after the route, on the main thread) is
   unaffected.
9. **Anchor accounting.** `anchor slots: reserved a..b of N` and the per-attempt slot rotation lines
   behave exactly as under select_stack (one slot per attempt, budget exhausted → clean refusal).
10. **Below-floor geometry (P3).** Only after the above: a 5.10.81/5.10.101 candidate profile with
    its own offsets (`0x150`/`0x140`) — which needs that era's userspace booted first, since the
    current userspace does not come up on that kernel.
11. **Regression on the incumbent.** A select_stack run on the same build must be unchanged
    (the only select_stack edit is the anchor call site).
12. **Frame validity under load.** If variant B (SROP) is ever pursued, capture a real frame first;
    variant A alone does not need it.

## What would kill this plan

The P1.5b read-back showing the copy does not land where the Σ arithmetic says (which would
invalidate the depth model itself, not just this route); or, after the re-stamp mitigation, a
measured per-attempt failure rate worse than the incumbent route's; or the write-vehicle checks
(K-class) failing on device in a way the select_stack route does not already exhibit.
