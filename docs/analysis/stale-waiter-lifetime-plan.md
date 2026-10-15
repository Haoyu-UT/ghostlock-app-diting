# Stale-waiter lifetime — plan (2026-10-09)

Level: **L** (attack-critical path). Plan first, then code, per `AGENTS.md`.

## The problem, measured

On diting the run dies with a data abort inside the PI walk:

```
pc : rt_mutex_adjust_prio_chain+0x188/0x1948      ; `ldapr w8, [x27]`
x28: ffffffc05107bc30   the waiter — a STACK address
x27: 00004d2600000000   *(x28 + 0x38) = waiter->lock
Call trace: rt_mutex_adjust_prio_chain / rt_mutex_cleanup_proxy_lock /
            futex_lock_pi / do_futex / __arm64_sys_futex
```

`+0x188` is `raw_spin_lock(&lock->wait_lock)`'s load, with `lock = waiter->lock`.
The walk is entitled to dereference that field; we handed it a non-canonical address.

Full evidence: `CLAUDE.md` → "Session (2026-10-09 ~00:45)".

## Why the field is garbage

The fake waiter is not allocated — it is the pselect fd_set bits living in **that syscall's kernel
stack frame**. `task->pi_blocked_on` keeps pointing at it after pselect returns, so any *later* walk
reads a frame the next syscall has since reused. Runs 1–2 read the correct anchor there; run 3, after
four attempts and a full 272-child reap, read `0x4d2600000000` — a value with a PID-shaped high half
(`0x4d26` = 19750) next to our PID 19749.

Inference, not proof. The read-back added to `pselect_put_waiter_word()` (same session) checks the
*user* copy; if every word verifies there and the walk still faults, the corruption is after the
stamp, which is what this plan assumes.

An unplaced word is **not** the cause: the sets are zeroed first, so a missing word leaves `0` and
the fault would be at address `0x0`.

## What triggers the fatal walk — and why it is ours

The trace and the call trace agree on a `futex_lock_pi` origin, and `threads.cpp:135-144` calls
exactly that:

```cpp
long sched_ret = support::sched_setattr_tid(tid, consumer_nice);
if (sched_ret != 0) {
    struct timespec ft = {.tv_sec = 0, .tv_nsec = 50000000};
    long fret = support::futex_op(&race->target_futex, FUTEX_LOCK_PI, 0, &ft, nullptr, 0);
    ...
}
```

A 50 ms timeout that expires takes `futex_lock_pi`'s failure path →
`rt_mutex_cleanup_proxy_lock` → `rt_mutex_adjust_prio_chain` — the oops's stack, frame for frame.

Run 3's route had already given up before the oops (`[!] pselect consumer still inflight; leaking
route fds`), so this fallback ran **after** the route stopped caring — the worst possible moment,
because the waiter's frame is by then the oldest it will ever be.

## Options

1. **Clear `task->pi_blocked_on` when the route finishes.** The durable fix: every later walk then
   takes the `if (!waiter) goto out_unlock_pi` fast exit, which 5 of 6 walks already take harmlessly.
   Needs the write vehicle again (`*(task+0x898) = 0`) and a careful look at whether the dance's own
   state machine depends on the task still appearing blocked. **Not in this change.**
2. **Stop issuing PI operations on that task once the route has moved on.** Cheap, non-destructive,
   reversible — and it directly tests the theory: if removing our own post-bail-out PI ops removes
   the oops, the stale-waiter story is confirmed and (1) becomes the durable version.
3. Pin the waiter's frame for as long as a walk might happen (route redesign) — not now.
4. Point `waiter->lock` somewhere permanently valid — impossible: the problem is the waiter's memory
   being reused, and we control its contents, not its address or lifetime. (This is precisely what
   option 2 of the payload-page work did for the *lock*; it has no analogue for the *waiter*.)

## This change: (2)

In `threads.cpp`, guard the `FUTEX_LOCK_PI` fallback with the same liveness test the enclosing burst
loop already uses:

```cpp
if (sched_ret != 0 && !race->consumer_stop.load() &&
    race->consumer_go.load() == seq) {
    ... fcntl fallback ...
}
```

Scope, stated plainly:

- It removes **our** trigger only. An ambient PI operation on the same task (another thread's futex,
  a scheduler path) can still walk the stale pointer. If the oops survives this change, that is the
  finding, and (1) is the answer.
- It is a race *reduction*, not a guarantee: the route can still move on between the check and the
  syscall. Closing that properly is (1)'s job.
- Cost: `consumer_success` no longer counts a fallback that we deliberately skipped, so a run that
  relied on the fallback for its nice change will report fewer successes. That is the intended
  behaviour — the fallback exists to force a priority change on 6.1 compact, and on 5.10 the
  `sched_setattr` path is what actually drives the dance.

## Gates

`make -C src ghostlock` (0 warnings) + `make -C src lint-tidy` (exit 0). `cmp_disasm` is a pre-PR
gate; run it before any upstream PR, not here.

## How this is judged

Next run, in order:

1. No `waiter word ... did not land` warnings — the stamp verified in user memory.
2. Either the run dies with the *same* `rt_mutex_adjust_prio_chain+0x188` oops (→ change (2) was
   not the trigger, go to (1)), or it does not (→ confirmed, and (1) becomes the durable fix).
3. W1 still lands. If it stops landing, the fallback was load-bearing on this device and this change
   needs rethinking rather than extending.

## RESULT (run 4, 2026-10-09 ~00:50) — criteria 1 passes, 2 says "not the trigger", and the fix moves

- **Criterion 1 PASSED.** No `did not land` / `INCOMPLETE` warnings, and the oops confirms it
  independently: `x27 = x24 = ffffff802aa3a590`, the anchor exactly as stamped.
- **Criterion 2: a DIFFERENT oops, and the guard was not involved.** The call trace is
  `__do_sys_sched_setattr → __sched_setscheduler`, not `futex_lock_pi` — so this walk came from our
  own nice rotation, which the dance needs and the guard does not touch. (The guard stays: it removes
  a genuine stale-walk trigger, just not this one.)
- **The fault moved one hop later**, because the lock word was finally correct:

```
03e4: ldr x8, [x27, #0x10]   ; x8 = lock->waiters.rb_leftmost
03ec: cbz x8, ...            ; <- where option 2 expected the walk to exit
03f0: ldr x9, [x8, #0x38]    ; <- FAULT: x8 = ffffffc0521bbc30, a STACK address, pte = 0
```

### What that means for this plan

The leading explanation was right but incomplete, and the **anchor itself is now implicated**.
`rb_add_cached()` sets `lock->waiters.rb_leftmost` when a waiter is enqueued on the lock — so using
the anchor as a lock makes the kernel write a *waiter pointer* into it, and the anchor is shared
across stages, so it accumulates them. `rp`'s `pi_bo` was `ffffffc05aff3c30` while the anchor's
`rb_leftmost` was `ffffffc0521bbc30`: two stacks, the second already unmapped. Most likely W1's
waiter, still sitting in the anchor when W2 walks — which runs 1-2 never had the chance to show.

**Revised fix, superseding (1) and (2) as the primary:**

- **Clear the references after each stage** — `task->pi_blocked_on` *and* `lock->waiters`
  (`rb_root.rb_node` + `rb_leftmost`), not just the first. The route already has a kernel write
  vehicle for this.
- **Or rotate the anchor per stage** so no stage inherits another's dead pointer. Cheaper if a
  second zeroed image region can be found (the profile carries one offset today), and it avoids
  needing a write at all.
- Still needed regardless: the read-back stays, because it is what made the lock word trustworthy
  enough to move the investigation forward.

**Confirming probe for the next run:** read `*(lock + 0x10)` (`rb_leftmost`) and `*(lock + 0x08)`
(`rb_node`) at the walk entry and check them against zero. If they are non-zero on a stage that has
not enqueued anything, the accumulation theory is proven.

## Addendum: rotate the anchor per attempt (chosen)

Chosen over clearing the references because it removes the shared state at its root: an attempt can
no longer be tripped by *any* earlier attempt's dead waiter, rather than by the ones we remembered
to clear.

**Granularity is per attempt, not per stage.** The route runs up to four pselect attempts
(`select_stack_route.cpp:573`) and they currently share one anchor, so the accumulation happens
*within* a stage as much as across stages. Each attempt gets its own offset.

**Where.** `select_stack_build_fdsets()` computes `lock_word` from `route.select_stack.
lock_anchor_image`. It gains an `attempt` parameter (two call sites: the initial build at `:533`
and the per-retry rebuild at `:582`, both already inside a scope that has the index).

**How much room.** `dump_skip.zeroes` spans image `+0x2a3a590` … `+0x2a3b8d4` — measured, ~78 KB,
ending where `kernfs_pr_cont_buf` begins. Stride **0x80**: an `rt_mutex` here is ~0x28 bytes and the
kernel touches only `wait_lock` (0x00), `waiters.rb_root`/`rb_leftmost` (0x08/0x10) and `owner`
(0x18), so 0x80 is a >2.5x margin. Four attempts consume 0x200 — 0.4% of the region. The rotated
addresses stay inside the same buffer, which `dump_skip()` only ever *reads* (verified earlier), so
nothing else writes there.

**What it does not fix, stated plainly.** `task->pi_blocked_on` still points at the attempt's waiter
after that attempt ends; a walk triggered from *outside* the route still reads a stale stack there
(the run-3 shape). That half is covered only by the P1 guard, which suppresses our own post-bail-out
`FUTEX_LOCK_PI` walks. Rotation and the guard are complementary, not substitutes — and the residual
risk is our own within-attempt timing, which neither addresses.

**Gates:** `make -C src ghostlock` (0 warnings) + lint-tidy (exit 0). Judged next run by: the
`[route] lock anchor:` line differing per attempt (image offset stepping by 0x80), no stamp
warnings, W1 still landing, and whether the `+0x3f0` oops recurs.

## Addendum 2026-10-14 — the surviving trigger is our own nice rotation, and the disarm is the lever

Three more deaths at the same pc on 236, two of them with full kernel text. They move the
priority from "ambient walk" (what the P1 guard and the rotation cannot cover) to **our own
`sched_setattr`, on the waiter thread, mid-run** — the 2026-10-09 run-4 trigger, now the
dominant one.

**The evidence** (this repo's port archive, `external/port/`):

1. `rate-500us/run-3/oops.txt` — `rcub/0` (PID 16), the RCU boost kthread; `x27 = x24 =
   0xb604e9328d1d9d00`. An unrelated kernel thread inherited the polluted PI chain and died.
   This is the ambient shape the plan already predicted; it is not the common one.
2. `cpuset-guard/run-1/oops.txt` and `cpuset-guard/run-7/oops.txt` — `CPU: 5 PID: … Comm:
   libghostlock.so`, i.e. **the exploit's own process**, right after
   `[*] sigreturn post-stamp attempt=1/4 stamps=1 copies=60/61 misses=0` (W1's first route
   call, ~T+7 s). Trace, identical in both:

   ```
   pc : rt_mutex_adjust_prio_chain+0x188/0x1948
   x28: ffffffc04f70bc30      ; the waiter — a kernel STACK address
   x27: 000000000000000c      ; waiter->lock (+0x38) — the faulting read (run-1: 0x11)
   Call trace:
     rt_mutex_adjust_prio_chain+0x188
     rt_mutex_adjust_pi+0x174
     __sched_setscheduler+0xee8
     __do_sys_sched_setattr+0x25c
   ```

   So the walk is `threads.cpp`'s consumer, `sched_setattr_tid(waiter_tid, consumer_nice)`:
   `__sched_setscheduler` → `rt_mutex_adjust_pi(waiter_task)` → the chain from
   `waiter_task->pi_blocked_on`. The P1 guard does not cover it by design — the call is the
   dance's own nice rotation, needed every burst — and `waiter->lock` holding a small
   integer (`0xc`, `0x11`) is a reused pselect frame, exactly the model in this plan.

**What clearing exists today, and its window.** The only mechanism is the per-race *ghost
disarm* (`race/threads.cpp:56-67`, `route::route_needs_ghost_disarm()` is true for every 5.x
profile): a `FUTEX_LOCK_PI` on the dummy word `0x80000000 | getpid()` with an expired timeout,
run once, after `controller.execute()` returns. Every archived run that reaches it logs
`mcast ghost disarm ret=-1 errno=110` (ETIMEDOUT — the expected return of the blocking path,
47 of 58 archived logs). Two things follow:

- The disarm is **per race, not per attempt**, and the route runs up to four pselect attempts
  per call, several calls per run. The stale `pi_blocked_on` lives for that whole span, which
  is the span in which the consumer's bursts walk it. The recorded crashes sit inside it.
- **It does clear the field — settled in source, with the ETIMEDOUT as the confirming
  signature.** The disarm's timeout forces the slow path, and stock 5.10
  (`external/kernel-bsp/kernel/locking/rtmutex.c`) is unambiguous: `rt_mutex_slowlock`
  overwrites it on the way in (`task_blocks_on_rt_mutex`: `task->pi_blocked_on = waiter`,
  :962) and the expired timer's `-ETIMEDOUT` reaches `if (unlikely(ret)) remove_waiter(lock,
  &waiter);` (:1271) whose first act is `current->pi_blocked_on = NULL` (:1077). The observed
  `errno=110` is the proof the path was taken: the fast path would have returned 0. (The one
  caveat: 5.10.81 vendor source vs the 5.10.236 GKI the device runs — the PI core is stock
  upstream and unchanged across the line, but that is an inference, not a measurement.)
  So the remaining defect is **when** the disarm runs, not whether it works.

**Optional confirmation (harness-side, no product code).** If a device measurement is wanted
before the change, one probe expresses the whole claim —
`p:gl_rma rt_mutex_adjust_pi pi_blocked=+2200(%x0):x64 pid=+1800(%x0):x32` (`0x898`/`0x708`
from this profile): during a run, a walk on the waiter thread whose `pi_blocked_on` is a stack
address that is *not* the live attempt's frame is the stale state caught live. Register-test
and falsify it first (`renice` on a PI-blocked pid; a fresh probe that never fires proves
nothing — see the pitfalls in `CLAUDE.md`). Not required to pick between A and B.

**Candidate A — hoist the disarm to per attempt (small, L) — recommended.** In
`SelectStackRoute::execute()`'s attempt loop, right after the post-stamp accounting and before
the next attempt rebuilds: run the same dummy-futex `FUTEX_LOCK_PI`. Extract today's inline
block into one helper both call sites share — and it belongs in `support/`, not `race/`:
`route/` cannot include `race/` (race already includes route; `route_policy.hpp` is included by
`threads.cpp`), so `support::ghost_disarm()` next to the other syscall helpers keeps the
dependency direction intact. The attempt's frame is dead weight by then; the window in which a
consumer burst can walk a reclaimed frame closes to the pselect-return→disarm gap. Cost: one
syscall per attempt, no route call, no anchor slot. Kept alongside it: today's per-race disarm
(it still covers the last attempt and any path that skips the loop), and the
`[!] pselect consumer still inflight` bail-out path stays as it is.

**Candidate B — clear with the write vehicle (the plan's option 1, larger, L).** A
`*(task + 0x898) = 0` write per stage through the existing W-vehicle. Durable in the strongest
sense — after it, no walk can find a waiter at all — but each clear costs a route call and an
anchor slot, roughly doubling a run's exposure, and it clears only what it remembers to clear.

**Not proposed:** gating the consumer's `sched_setattr` on an attempt-live flag. It is the
plan's option-2 shape again — a race reduction with the same check-to-syscall gap — and the
measured trigger is now precisely that call.

**Judged by**, after either: `make -C src ghostlock` (0 warnings) + `lint-tidy` (exit 0); then a
236 series (5 runs, one per boot, guard on) where the `+0x188` class does not recur, against
the current record — 3 deaths in 5 uninjected driven runs on 2026-10-14 (this session's
`external/port/cpuset-guard/run-1`, `run-3`, `run-7`), plus `rate-500us/run-3` earlier the same
day.

## RESULT (2026-10-14, `../port/stale-waiter-disarm/`) — the class does not recur

**Candidate A landed** (working tree, uncommitted): `support::ghost_disarm(why, &err_out)` — the
dummy-futex disarm extracted from `race/threads.cpp`, with the two silent-failure paths now
reported (fast path taken; non-timeout errno) — called after **every** attempt's stamp window in
`SigreturnRoute::execute()` and `SelectStackRoute::execute()`, before the post-stamp `pr_info`
write runs over the frame, plus the unchanged per-race call and its historical log line.

**Judged on the 236 rig** (the same build the strip gate ran as baseline; the rig's test
sigreturn profile restored for the build): five runs, one per boot, cpuset guard on —
**zero `+0x188` oopses, zero kernel-text deaths**, against a same-day pre-change base of 3 such
deaths in 5 uninjected runs. Three runs finished (`KernelSU ready`); the two failures are
*different* classes, both seen before the change: the `step=38` dirty race at the last stage
(6 archived instances) and the post-spray wedge with no oops text.

**Gates.** `make -C src ghostlock` 0 warnings, `lint-tidy` rc=0, and `cmp_disasm` with every
difference accounted for (`../port/stale-waiter-disarm/cmp_disasm.txt`); the baseline binary is
byte-identical to the strip gate's, and the candidate carries exactly three `ghost_disarm` call
sites (race end + both routes).

**What stays open.** The per-attempt disarm is not counted per attempt (its anomaly logs would
have fired; the optional `remove_waiter` kprobe stays unrun); n=5 has power against today's
rate, not against the historical ~1/9; the select route's call site is structural only (the rig
runs sigreturn).

**The clearing rationale, restated after the source read.** The disarm works because the kernel
rewrites the field itself on the block path (`task_blocks_on_rt_mutex`, `rtmutex.c:962`) and
nulls it on the expired-timeout path (`remove_waiter`, `:1077`); ETIMEDOUT is its success
signature, and the dummy word's "owned by tid == getpid()" encoding makes the block path the
one always taken. The write-vehicle variant (candidate B) remains unimplemented by choice —
per attempt it would cost a route call and an anchor slot each time.
