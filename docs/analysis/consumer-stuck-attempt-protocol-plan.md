# The `step=38` dirty race — the walk outlives the attempt, and we stamp over it (2026-10-14)

Level: **L** (attack-critical path, both routes' attempt protocol). Plan first, then code, per
`AGENTS.md`.

Class: `external/port/` — six archived instances (`sigret-app/run-17`, `run-28/30/31`,
`k81/era-rate/run-3`, `stale-waiter-disarm/run-1`), ~1 in 6 archived runs, every one of them a
*void*: the route reports `ROUTE_DIRTY_FAILURE`, the native stops itself, the box stays up and
produces no kernel text.

## The problem, measured

**`step = 38` is not a kernel event — it is the route's own `consumer_stuck` flag.** The lifecycle
runs `prepare → execute → disarm → destroy` (`route/route_lifecycle.hpp`), and `disarm()` is the
twin in both routes (`sigreturn_route.cpp:106`, `select_stack_route.cpp:78`):

```cpp
void SigreturnRoute::disarm() noexcept {
    race->consumer_go.store(0);
    if (race->consumer_inflight.load() != 0) {
        for (int32_t i = 0; i < 2000 && race->consumer_inflight.load() != 0; i++) usleep(1000);
        consumer_stuck = race->consumer_inflight.load() != 0;
    }
    status.kernel_disarmed = !consumer_stuck;
}
```

`destroy()` rewrites the status to `ROUTE_DIRTY_FAILURE` + `step = 38`, and
`race::run_main_route_threads()` treats that as terminal — `fail_stop_dirty_race()` →
`exit_group(70)`. So the observable is a two-second fact: *`consumer_inflight` never cleared*.

**The stuck call is the consumer's `sched_setattr` on the waiter thread.** The 2026-10-13
diagnostic build (`f829464`, stripped at `3e6a2c7`) recorded per-call state; the one archived
failure that carries it is `external/port/k81/era-rate/run-3`, W3/TIF_SECCOMP:

```
[*] sigreturn post-stamp attempt=1/4 stamps=1 copies=61 misses=0 path_sve=0 +30ms
[*] sigret consumer diag attempt=1 saw=1 inflight=1 new=1
[*] sigret consumer call seq=1 idx=0 nice=19 state=IN-FLIGHT phase=1 sched=0/e0 futex=0 ... dur_us=-1
[*] sigret consumer diag attempt=2 saw=1 inflight=1 new=0      <- attempts 3, 4 the same
[*] sigret consumer final seq=1 ... state=IN-FLIGHT phase=1 ... dur_us=-1
[*] sigreturn route done calls=1 success=0 status=3 clean=1/0 step=38 errno=0 stamps=14
```

`phase = 1` is `sched_setattr` (`race/threads.cpp:136`); `sched=0/e0` are its untouched zero
initialisers, i.e. the syscall never returned; `saw=1 new=0` on attempts 2–4 say the consumer never
picked up a later sequence — it is inside that one call. No `sched_setattr(...) ret=... errno=...`
line exists anywhere in the archive, which is consistent rather than informative: the logging sits
*after* the syscall.

## Why the walk outlives the attempt

The window is 30 ms (`kLoopWindowNs`); the call is issued ~5 ms in (`kWalkDelayUs`). The call is the
exploit's PI walk, and the walk is slow — the same run's preceding stage, from the same records:

```
[*] sigret consumer final seq=1 idx=0 nice=19 state=done phase=1 sched=0/e0 ... dur_us=226661
[*] sigret consumer final seq=2 idx=0 nice=19 state=done phase=1 sched=0/e0 ... dur_us=10
```

226 ms against a 30 ms window. So `execute()`'s read of `consumer_calls`/`consumer_success` — taken
immediately after `consumer_go.store(0)`, ~25 ms after the call started — *always* happens while the
only call that matters is still in the kernel. That is the whole of the healthy `calls=2 success=1`
shape — the dominant one, 280 archived instances against 22 of `calls=1 success=1` and no other
success shape at all:

- attempt 1's walk returns `sched_ret = 0` **after** the read → the route sees `calls=1 success=0`,
  `fail(33)`, and rebuilds;
- attempt 2's call returns in **10 µs**: it walks nothing. `k81/era-geom` measured the same thing
  from the kernel side — "each route call walks exactly once (`rw` fires once per call)" — and the
  inverted scoring is already recorded in `sigret-app/README.md` §12.

So the route's `ROUTE_OK` currently rides a no-op call, while the attempt that actually performs the
write is scored a failure. Whatever else changes, that pairing is wrong: it is what makes the route
re-spray and re-stamp at all.

## What writes the walk's data, and when

The walk's data is the stamp — the fake waiter the kernel's own sigreturn copy places into the
**waiter thread's kernel stack** at `dst + 0x140` (geometry measured on the device, `Σ = 0x300`,
`k81/era-geom`). Everything the walk reads for the next 100–230 ms lives there, and it is only
protected while the trampoline keeps copying: each `rt_sigreturn` re-zeroes and re-writes that
region, the loop repairs it ~60× per 30 ms window — and then the deadline fires and **the loop
never runs again for that attempt.**

Everything that follows the loop runs on the same thread, over the same region:

| when | what, on the waiter thread | reaches the strip? |
|---|---|---|
| +30 ms | per-attempt `ghost_disarm` — a `futex_lock_pi` that *sleeps* to its expired timeout | yes: `schedule()` → `__switch_to` is the deep nesting |
| +30 ms | `pr_info` (post-stamp line) | write path, shallower |
| +31 ms → +1.1 s | attempt 2's `prepare_good_kernel_page` — hundreds of forks, `sendmsg`s, closes, `waitpid`s | yes, repeatedly |
| +1.1 s | attempt 2's restamp: a **new** lock word, 60 more copy cycles | rewrites it wholesale |

and the walk is still inside attempt 1's call throughout. The counter-evidence that this is worth
fixing is `k81/era-geom`'s other finding: **at walk entry the stamp was complete and correct**
(0/125 bad post-copy samples, `pi_blocked_on − copy_dst = 0x140` exactly). Entry is not what goes
wrong — what follows is.

## This change

**Part A — the attempt does not end until its call has returned.** In both routes' attempt loops,
after the window (and before anything else runs on this thread):

```cpp
stamp_window(route_t0);                     /* or pselect() in the select twin */
const int32_t drained_ms = race::wait_consumer_idle(race, kDrainDeadlineMs);  /* NEW */
if (route::route_needs_ghost_disarm(...)) support::ghost_disarm("attempt", &e);   /* frame is dead
                                                                                     weight — now
                                                                                     it is dead */
pr_info("... post-stamp ... drain=%dms", drained_ms);
race->consumer_go.store(0);
const int32_t calls = race->consumer_calls.load();
const int32_t successes = race->consumer_success.load();
if (drained && calls > 0 && successes > 0) { ROUTE_OK; break; }
if (!drained) { consumer_stuck = 1; fail(38, 0); status.code = ROUTE_DIRTY_FAILURE; break; }
(void) fail(33, 0);                          /* the call returned, and failed: retry as today */
```

- **The poll is a userspace spin, not `usleep`.** `usleep` nests through `schedule()` →
  `__switch_to` — the same depth that overwrites the strip. The wait must be syscall-free, or it
  re-creates the hazard it exists to remove. (Bound: `kDrainDeadlineMs` = 1000, ~4× the measured
  226 ms; the lifecycle's 2 s disarm stays as the last-resort honesty check.)
- **`!drained` breaks the loop — no respray, no restamp.** That is the point: if a walk is wedged,
  the three remaining attempts can only pour more writers over it. The status stays dirty (a thread
  of ours really is stuck in the kernel), so the caller's policy is unchanged.
- The per-attempt disarm moves *after* the drain. Its job — clearing `pi_blocked_on` so no *later*
  walk reads a reclaimed frame — is unchanged; it just stops running while the frame is in use.

Consequences, all of them observable: a healthy route call becomes **one attempt**
(`calls=1 success=1 stamps=1`) taking ~250 ms instead of ~1.1 s; the respray storm leaves the walk's
lifetime entirely; the route's OK stops riding a no-op; and the `step=35` class (the retry's
page-prepare failure, six archived instances) loses most of its occasions with the retries.

**Withdrawn 2026-10-14: the "keep the strip repaired while a call is in flight" idea (this plan's
Part B).** It rested on the walk reading the strip for its whole 100-230 ms life. The probe trace
shows the reads all happen in the first ~35 µs — and the loop is already copying through that
window — so extending the repairs inverts the fix: it would add transients to the span that must
stay quiet. Nothing of it is to be implemented. What it got right is the *machinery* (the
trampoline reading a shared consumer word); the delivery class, if it is the copy, wants that
machinery inverted — freeze the strip while the walk's reads are in flight.

## What this does not claim

- **Which writer lands the fatal hit is not settled**, and Part A is worth doing either way. Two
  candidates remain: the strip being rewritten mid-walk (Part B's premise), and the *shared anchor*
  (`dump_skip.zeroes`) whose own bookkeeping the walk writes — `rtmutex.c`'s enqueue/dequeue can
  leave a node pointer there that a later iteration descends into, i.e. a cycle the walk builds for
  itself. The falsifier, if the class survives Part A: a probe pair on `rt_mutex_adjust_prio_chain`
  entry/exit (and a counter on its retry path) separates "one long walk" from "a walk that loops",
  and the loop case implicates the anchor, not the strip.
- **The walk's kernel-side duration is unmeasured.** 226 ms is the *userspace call phase* — the 5 ms
  delay plus any descheduling on a phone that is simultaneously forking hundreds of children. The
  mechanism above needs only "longer than the window", which the 2 s stuck-timeout already proves;
  the probe pair above would put a number on it.
- The existing 2 s dirty policy is deliberately unchanged. A wedged thread is not retryable and
  pretending otherwise would hang `join()`.
- n = 5 device runs has weak power against a ~1/6 class (0-in-5 ≈ p 0.4). The confirmation is the
  *shape* change in every run — `calls=1 success=1 stamps=1` plus a drain figure in the 100–250 ms
  band — not a rate.

## Gates

`make -C src ghostlock` (0 warnings), `make -C src lint-tidy` (exit 0), the Kotlin suite, and
`tools/cmp_disasm.py` if the trampoline changes (Part B) — Part A is C++ around the existing
syscalls and should show no attack-path delta beyond the call sites.

## RESULT (2026-10-14) — the device refutes this change as written

**The drain wedges the walk on both routes.** Four runs, one per boot, one rig, two arms
(`external/port/consumer-drain/`): with the change, attempt 1's call never returns
(`drain=-1ms`, 1000 ms) — 2/2 on sigreturn and 1/1 on select_stack, every one at W1 attempt 1
(slot 0), window normal (`copies=61`), **no crash text anywhere**. The control arm — the
*unmodified* pre-change APK, byte-identical to the build the disarm series ran (`5d4fed37…`) —
finished on the first try (`exploit complete` -> `KernelSU ready`) with every call in the old
`calls=2 success=1` shape. Under the null, p ≈ 0.03 for the two-run arm; the third wedge on a
second route settles it.

**Why — not settled.** A removes all *waiter-thread* activity from the second after the window (the
per-attempt `ghost_disarm`, the post-stamp `pr_info`, attempt 2's respray); which of the three the
walk needs is open. The leading candidate is the disarm — the chain walk re-reads
`task->pi_blocked_on` at every `retry`/`again` and exits when the chain changed (`rtmutex.c`
[2]/[3]), and the disarm rewrites that field — **but it is weakened**: `k81/era-rate/run-3` has a
healthy 226 ms attempt-1 call in a build with no per-attempt disarm at all. Alternatives: the
respray ends the walk by some other effect, or the drain's pure userspace spin (CPU 4 hogged for a
second where the old flow descheduled the thread) is itself the disturbance.

**The correction to try next (a change to this design, so it needs the operator's nod):** call
`ghost_disarm("attempt", …)` *before* `wait_consumer_idle()` in both attempt loops. Prediction if
the disarm hypothesis holds: the run completes and every call reads `calls=1 success=1 stamps=1`
with a real `drain=` figure — the wedge and the inverted scoring disappearing together. If it does
not, separate the spin from the storms (an `usleep` poll arm), then take the probe pair on
`rt_mutex_adjust_prio_chain` entry/exit + retry path, which names the mechanism outright.

## FOLLOW-UP ARMS (2026-10-14) — the probe trace names the call's tail

Disarm-before-drain: still wedges. `usleep`-poll drain: still wedges. So neither the disarm nor the
spin is what the walk needs. The instrumented run (`external/port/consumer-drain/arm-c/`) shows the
walk enters once (`next_lock` = the anchor), runs **one** main-loop iteration, performs the erase,
reads the anchor's tree root at the enqueue descent (`root=0 lmost=0 owner=0 wl=1`), and then
**returns 0 after 5.378 s** — with no probed event in between, no loop repeats, no depth exit, no
lock contention.

With `owner == 0` that tail is the `!rt_mutex_owner(lock)` arm, which ends in
`wake_up_process(rt_mutex_top_waiter(lock)->task)` — and the top waiter is our strip, whose `task`
word is `fake_task`: the walk **wakes the forged task_struct in the payload page**. The shipped flow
then frees that page in the respray ~30 ms after the window, while the walk may still be inside the
wake — a use-after-free on a recycled page, which is the right shape for both the `step=38` class
and the silent wedge/reboot class.

Consequences for this plan: the drain's premise is dead twice over (the tail is seconds long, and
removing the post-window activity makes it *slower*, not faster), and the next design round belongs
to the wake — either landing it on a real task (the page waiter's stamp already uses
`slide_init_task()`) or arranging `prerequeue_top_waiter == rt_mutex_top_waiter(lock)` so it is
skipped. The confirming measurement is one probe run on `try_to_wake_up` + `rb_insert_color`.

## MEASURED (arm d, 2026-10-14) — the wake *is* the call

A pre-A run with 35 probes armed (`external/port/consumer-drain/arm-d/`) times every route call:
entry -> erase -> enqueue -> **`try_to_wake_up` +35 µs in** -> return **131-186 ms later**. The wake
is 100% of the call, and its target is `page + 0x400` — `fake_task`. The same instrumented run also
died in the +0x188 class with kernel text, on *our own consumer's* walk (`__arm64_sys_sched_setattr
-> rt_mutex_adjust_prio_chain+0x188`, `waiter->lock = 0x11`), with the per-attempt disarm present.

So both failure classes are **delivery** failures at one strip word: `lock` read clobbered (the
oops), `task` read as the forged task (the long tail) or as garbage (a wild wake). The copy
interval governs both; the handshake this plan reworked governs neither. That is the correction the
next round starts from — fix the strip's `task` word (a real, running task; the page waiter's stamp
and the TCP route already do exactly that), and the call collapses to microseconds, at which point
the drain in this plan becomes both viable and cheap.

## IMPLEMENTED (2026-10-14) — the code as landed (host gates passed; refuted above on device)

Landed in the working tree (`port/diting-5.10` + this change, uncommitted):

- `PiRace::wait_consumer_idle(deadline_ms)` + `kConsumerDrainMs = 1000` (`race/pi_race.h`,
  `race/pi_race.cpp`): closes the sequence, then spins in userspace (guarded `yield`/`pause`
  hint, vDSO clock) until `consumer_inflight` clears; returns elapsed ms, or -1 at the deadline.
- `SigreturnRoute::execute()` and `SelectStackRoute::execute()`: the drain runs right after the
  window and before everything else on this thread; the post-stamp line carries `drain=%dms`; a
  timeout sets `consumer_stuck`, fails step 38 and breaks the attempt loop without respraying.
- `TcpZerocopyRoute`: the loop's drain is the same bounded primitive, its open end-of-route spin
  (`disarm()`) becomes bounded with an honest `kernel_disarmed`, and `destroy()` retains the
  punched mapping when a call is stuck — the same policy the select route applies to its fds.

Gates: `make -C src ghostlock` 0 warnings; `lint-tidy` exit 0; the six host tests that build on
x86_64 pass, `pi_race_test` extended with the primitive's idle / late-call / stuck cases;
`cmp_disasm` archived with every line accounted — record, and why the tool's `RESULT: FAIL` is its
documented control false alarm, in `external/port/consumer-drain/cmp_disasm.txt`.

Not claimed: no device run yet (the section below is the protocol for it), and the Kotlin suite
was not run because no Kotlin changed.

## How this is judged, next device session

1. **Shape, every route call**: `calls=1 success=1 status=0 clean=1/1 step=0 stamps=1`, and a
   `drain=` figure in the 100-250 ms band. This is the change's own signature and it is expected on
   *every* call — the pre-change `calls=2 success=1` was the defect, so **a series that shows it is
   a regression, not a confirmation, and nothing here is "run until a retry appears"**.
2. **The invariant that makes the handshake falsifiable per call.** After the change, a second
   attempt can only follow an attempt that counted *no* call at all — `calls=0` with `drain=0ms`
   (the window closed before the consumer was scheduled into its call; the sequence is closed, so
   it never calls, and the retry is legitimate). It can no longer follow an attempt whose call was
   in flight and merely unobserved: `consumer_calls` is incremented *before* `consumer_inflight`,
   so at the drain's read `inflight` set implies `calls >= 1`. So the falsifier is exact —
   **any `calls>0, success=0` attempt followed by a retry, or any retry whose predecessor line does
   not read `calls=0 … drain=0ms`, means the attempt did not wait for its call.** That check costs
   nothing: both figures are on the post-stamp line, per attempt, in every run.
3. **The chain still completes**: `exploit complete` -> handoff -> `KernelSU ready` in the healthy
   runs. This is the real gate — a shape change with a broken exploit is not a fix.
4. **The class**: 5 runs, one per boot, protocol of `external/port/rate-500us/README.md`, cpuset
   guard on — against the archive's base (six instances, `stale-waiter-disarm/run-1` the newest)
   and with the mechanism argument carrying what n=5 cannot.
5. **`step=35`** should get rarer with the retries; a run that still needs a second attempt is worth
   its own look against the invariant above.

**Two series, not one.** The rig's test build runs the *sigreturn* profile (every one of the six
archived failures), and the shipped 236 profile runs *select_stack* — so the change is gated per
route: sigreturn first (the rig as it stands), then a second, shorter series with the real-profile
build for the select call site. TCP waits for the 6.1 device (PORT-PLAN item 4, the two-artifact
protocol).
