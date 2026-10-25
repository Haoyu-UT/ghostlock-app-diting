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

## Variant B as built (2026-10-12, device-measured)

The carrier is rt_sigreturn itself, entered once per attempt:

- One `tgkill`. The `SA_SIGINFO` handler patches the strip into the delivered
  frame's fpsimd record, `memcpy`s the frame twice (0x2000 bytes each, 16-aligned so
  the records keep the kernel's 128-bit alignment; the copies live in `extern "C"`
  globals with `[[gnu::used]]`, because LTO drops asm-only references), and rewrites
  `sp`/`pc` in **both** the delivered frame and the loop copy, so the `rt_sigreturn`
  that follows the handler resumes at `sigreturn_loop_trampoline` with
  `sp = loop_frame`.
- The trampoline is naked asm: spin on `cntvct_el0` until the next copy is due
  (`kCopyIntervalNs = 100 µs`), then `mov x8, #139; svc #0`; on the `cntvct` deadline
  it loads `sp = return_frame` and `svc`s once more, which restores the interrupted
  context exactly — `stamp_window` resumes as if nothing had happened, and the route
  reads the consumer's counters as usual.
- Measured: ~5285 copies in 5 ms (~1 µs per iteration); the copy's own source reads
  the strip word-for-word (`tree_pc = page+0x100`, `lock` = the anchor, `prio` =
  140); the destination is zero *before* each copy, because `parse_user_sigframe`
  re-creates its local at exactly the strip's depths at the top of every
  `rt_sigreturn` — hence the inter-copy spin, which is the one piece **not yet
  measured on the route** (the last runs never started; see RESTORE.md).
- `kAttempts`/per-attempt page respray and the anchor rotation are unchanged from A;
  the loop counter currently reads 1 (globals placement — item 2 in RESTORE.md).

Device state, the exact probe set, the run recipes and the ordered open items live in
`external/port/sigret-app/RESTORE.md` (root repo).

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

## Carrier study, 2026-10-12 (measured; the design input for item 43)

The route's flaw is structural, and it is now quantified. The strip lives at a fixed depth on
the victim's kernel stack -- the stale waiter is `futex_wait_requeue_pi`'s local at `sp+0x90`,
so the walk's words sit at **0x210** below the syscall entry sp on 5.10.236 and **0x1c0** on
5.10.81/101 (the 0x50 is `do_futex`'s frame, 0x70 vs 0x20). The rt_sigreturn carrier fits both
(its copy covers depths [0x100, 0x300)), but it returns the victim to EL0, where every interrupt
writes frames through the strip.

The obvious fix -- a syscall that copies user bytes over the strip and then *blocks*, parking the
victim in EL1 so interrupts go to the IRQ stack -- was measured across the standard set, in QEMU,
with two harnesses (`external/port/k81/qemu/{carriers,marker-sweep}.txt`, sources beside them):

| carrier copy | L | depth | fits 236 (0x210) | fits 81/101 (0x1c0) |
|---|---|---|---|---|
| readv/writev iovec (wrapper) | 0x80 | 0xf8 | no | no |
| recvmsg iovec | 0x80 | 0xe8 | no | no |
| sendto sockaddr | 0x6e | 0x11c | no | no |
| sendmsg iovec | 0x80 | 0x290 | no | no |
| pselect6 fd_sets | 3*size | **0x210** | **yes** | no -- 0x50 deep of the strip |
| ppoll pollfds | 0xf0 | 0x454 | no | no |
| rt_sigreturn fpsimd local | 0x200 | **0x300** | **yes** | **yes** |
| semop sembuf array | 0x100 | -- | SYSVIPC is not enabled in this kernel | |

A carrier fits iff its copy spans the strip: `Sigma <= home <= Sigma + L - 0x58`. Two conclusions:

1. **"Stamp, then park somewhere harmless" does not exist.** Every parking syscall in the set
   (pause, rt_sigsuspend, read, futex-wait, nanosleep) was tested with a ramp already written at
   the strip's depth: all of them overwrite those bytes with their own frames. A parked path's
   frames *are* the clobberer.
2. **The below-floor slack is 0x50 bytes of frame geometry.** select's buffer starts exactly at
   the strip on 236 (which is why that route works there) and 0x50 below it on 81 -- no `nfds`,
   shift or alignment choice can bridge that, because the buffer's start depth is a property of
   `core_sys_select`'s frame, not of the copy length.

So the remaining design space is: (a) tune the EL0 loop (item 47 -- the exposure is real but the
rate is a measurement, not a model); (b) find a carrier outside the set measured here whose copy
starts at depth <= 0x1c0 with L >= 0x78 (the band's mouth is ~0x1c0-0x1c0+L-0x58); or (c) accept
the floor at 5.10.136 and ship the three supported builds. What is *ruled out* is the cheapest
idea -- parking the victim somewhere shallow after the stamp.

## Rate by kernel: 5.10.81 vs 5.10.236 (2026-10-24)

The sigreturn route is not uniformly bad; its rate tracks the strip's exposure to the
context-switch writer, and that exposure changed with the kernel's frame geometry.

**Measured rates.**

| kernel / build | route | completed | failure census |
|---|---|---|---|
| 5.10.81 era rig (2026-10-13) | sigreturn | **4/5** | one deep W3 `TIF_SECCOMP` hang; no `+0x188` |
| 5.10.236, legacy test profile (2026-10-17) | sigreturn | **8/15 (53 %)** | every failure `+0x188` |
| 5.10.236, fork line 2×2 (2026-10-20) | sigreturn | **5/12 (42 %)** | 7/7 crashes `+0x188` |
| 5.10.236, same 2×2 | select_stack | **11/11 (100 %)** | no select crash |

The 81 row is `external/port/k81/era-rate/`; the 236 rows are
`external/port/nice-route/RESULT-partial.md` and the legacy sigreturn test series. The route pooled
11/11 vs 5/12 at p = 0.0046 (exploratory, partial series); the 81-vs-236 difference is directional
but not statistically established at n = 5 vs 12/15 (Fisher p ≈ 0.2–0.35). The 236 select result is
the strong, same-kernel comparison.

**The geometry delta.** The strip depth below the syscall entry sp is **0x210 on 5.10.236** and
**0x1c0 on 5.10.81/101** (the 0x50 is `do_futex`'s frame, 0x70 vs 0x20; carrier study above). The
sigreturn copy destination is 0x300 on both, so `waiter_off_plain` is **0xf0 on 236** and
**0x140 on 81** — the 236 strip is 0x50 closer to the copy destination / 0x50 deeper below the
entry. The 236 extractor derives the same shift independently: `off_plain = 0xf0`,
`off_sve = 0x100`, `copy_dst_plain = 0x300`, `strip_home = 0x210`; the 81/43 family is
`0x140/0x150`. The route's copy loop and timing are unchanged (`copies=61 misses=0 drain=0ms`,
500 µs on both), so the copy-count/interval levers are not the difference.

**The failure class.** `external/port/strip-writer/`: the `+0x188` writer is an interrupt-triggered
context switch on the victim's stack (`__switch_to`'s sp descends past the strip); the consumer's
walk then reads the clobbered lock word. On 236 every sigreturn failure is that class; on the 81 era
rig the single failure was a W3 hang and none of the 4/5 completed runs carried crash text. The
236 strip is 0x50 deeper and the 236 kernel's entry/switch frames reach it (the strip-writer
probes); the 81 frames (and the era userspace) evidently did not, or far less often. The exact
frame-size split between the two kernels is not measured — the strip depth is, and the class is.

**5.10.43.** The zeus 5.10.43 profile carries the 81-family sigreturn offsets (`0x150/0x140`) and
was verified only as a profile (QEMU/on-device parity); it was never run as a chain. If it were, the
geometry predicts 81-like behaviour, not 236-like — but this is unmeasured.

**Consequence for the release.** On 236 the shipped route is **select_stack** (11/11 vs 5/12 in
the same series); sigreturn remains for 81/101, where select is infeasible (the 0x50 frame gap).
A future 236 sigreturn improvement is structural — move the strip out of any depth a kernel
entry/switch frame traverses, which is what the select fd_set surface already does — not a timing
knob; the EL0 copy interval is saturated at 500 µs.

**Which line those numbers belong to.** The 11/11 is the **clean dev line** `port/diting-5.10` @
`0cf2878`. The document-based release candidate does not contain that line (its routes lack the
per-attempt `support::ghost_disarm` and the rest of `9bacaf6`), and its own 5-run document-line
series measured **2/5** (2 box deaths after `Write 1`, 1 W2). That 2/5 is a document-line result,
not a select-route result; the route ranking above stands on the clean line. The extractor plan's
Priority 1 is to **port the clean line's missing fixes into the working branch** (at minimum
`9bacaf6`'s per-attempt `support::ghost_disarm`, plus the bounded drain and W2 robustness) — the
clean line stays the curated dev line; the working/release branch receives the fixes.

**2026-10-24 post-mortem — the port was attempted, regressed, and was reverted.** On the same
rig/day, the clean line re-read **5/5** with the S1 APK (`external/port/cleanline-recheck/`). The
port of `9bacaf6`'s attempt protocol onto `feat/extractor-5x-geometry` was then A/B'd on fresh
boots: pre-port completed (`ab-pre` 1/1 + the prior 2/5), while the ported build wedged in **all
three** route-reaching runs (`r3`, `ab-post`, `ab-post2`): `pselect post-select ... drain=-1ms` /
`pselect consumer still inflight` → dirty failure → box reset. Raising `kConsumerDrainMs` 1000 →
3000 ms did not change it. The patch is saved at
`external/port/extractor-5x-port/port-code-{1s,3s}.patch`; the working tree was reverted to
`e510ea9`. The disarm/drain is **not** an independently transplantable fix: on the document line
the consumer's call does not return while the route waits, whereas the clean line's returns in
100–230 ms.

**Top suspects for the line difference** (ranked; each postdates the 11/11):

1. **Spray slab stride / object count.** The clean 236 profile carries
   `kernelsnitch.mm_struct_sz = 960`; `prepare_kernel_page()` computes
   `mm_objs_per_slab = ORDER3_SIZE / stride` = **34**. The document line removed the field
   (`95016e9`) and now uses `MM_STRUCT_SZ = 0x500` → **25** objects/slab
   (`src/core/support/util.cpp:667`). Every spray array scales (prepare 8×34 vs 8×25; spray
   `(1+MM_PARTIALS)×`; pre/post), so the heap grooming and the leaked page differ. This is the
   single most direct difference between today's 5/5 and the 2/5 series; the document runs'
   page-prep rejections (`page ... stores an even byte over selinux_state.initialized`) are
   consistent with the changed leak page.
2. **KernelSnitch scan grid.** The clean line still scans with the profile stride (960, `MM_ORDER`)
   in two passes and leaks in **~0.86–0.94 s** (native logs `+122ms` → `+982ms`). The document
   line's `7f859eb` grid (`SCAN_PRIMARY_INNER=32`, `SCAN_LAST_RESORT_INNER=8`,
   `SCAN_OUTER=4096`, four passes, `ranges=14 source=banks`) leaks in **~4.4–4.6 s**; the longer
   scan changes the heap state at route time and the page that is leaked. The 4 KiB outer grid
   also removed the slab-order assumption the clean line still relies on.
3. **Attempt protocol (bounded drain + per-attempt disarm).** The clean line has it; the document
   line lacks it. The port showed it is coupled to suspects 1–2: with 25 objects/slab and the
   4.5 s scan, the consumer's walk does not return within 3 s while the route waits, and the
   clean-line protocol turns that into a fatal dirty failure; the pre-port route retried and
   completed. Re-port it only after the spray/scan baseline is restored.
4. **Lower:** the fd fix (`072579c`), the anchor (`select_lock_anchor`), the consumer thread and
   the profile's tuning values are present and equal on both lines (the profile value diff is the
   stride only); the document line's added routes (multicast) are not selected by the 236 profile.

**Next test, in order:** (a) force the 960 stride on the document line (temporarily, by restoring
the profile field or the native default) and run a 5-run fresh-boot series; if the rate returns to
the clean line's, the stride removal was the regression; (b) if not, restore the stride-based scan
for the 5.10 profile and repeat; (c) then re-port the attempt protocol. The clean line stays
curated and unchanged.

**Result (2026-10-24, `external/port/stride960-recheck/`): forcing 960 gives 4/5.** r1 was a box
reset at W2 attempt 1 (the old W2 class, not a select/page-prep failure); r2–r5 reached
`KernelSU ready`. Page prep accepted 8–14 pages in every 960 run, against 0–1 in the zero-accept
1280 fresh boots. The stride removal was the main regression; (b) is not needed for the recovery —
the stride-agnostic scan stayed in place and still reached 4/5. Next (decided 2026-10-24): the
**measured stride** — the candidate set (960/1024/1088/1216/1280) is probed by the leaked
`mm_struct`'s offset in its 32 KiB slab (`leaked & (ORDER3_SIZE-1)` must be a multiple of the
candidate); the clean-line logs already pick 960 and reject the rest. The generated profile carries
the verified value (the QEMU harness reads `/proc/slabinfo` for host-side generation); at runtime
the measured value is a per-kernel read-only DB entry, and the user applies it only by merging it
into a profile and exporting that profile (the `PORT-PLAN.md` Priority 1 storage/measurement
model). Use the value for the spray and an object-aligned first scan pass, with the full 32/8 grid
as fallback; an unknown stride still tries with the compiled default. The attempt protocol is
not re-ported now: the 4/5 came without it, and the earlier A/B showed it is not independently
transplantable.
