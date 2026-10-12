# Sigreturn route — settle the attempt before scoring it (plan)

**Status.** Approved by the operator 2026-10-12 (L-level: attack-critical path + profile
surface). Implementation on `experiment/sigreturn-stamp`; it lands with that route's commit
cluster on `port/diting-5.10` per `BRANCH-POLICY.md`.

**Scope — operator decision, 2026-10-12: the sigreturn route is an *additional* route, never a
replacement.** The shipped 5.10 profiles keep `route = select_stack` (r5: 5.10.236 / 226 / 209);
sigreturn is selected by profile only where `select_stack` is out of band (the pre-5.10.136
geometry, 5.10.81 / 101) or by explicit choice. Nothing in this change touches the select route,
its offsets or its profiles — the deliverable is that the sigreturn route *scores its own
attempts honestly*, nothing else.

## The problem, device-measured (2026-10-12)

Per attempt the route arms the consumer (one `sched_setattr`, which makes the kernel walk the PI
chain through the stamped waiter), runs the victim's stamp window for 30 ms, then reads the
consumer's counters and scores the attempt **failed unless `calls > 0 && successes > 0`**.

Measured with a kretprobe/entry pair on the walk and on the syscall, plus a per-call record
inside the consumer (23 calls, five runs, `kCopyIntervalNs = 20 us` on 5.10.236):

- The walk **succeeds** — it returns 0 — but takes **71-158 ms**. The rest of the syscall is
  13 us before the walk and ~1 ms after it; the walk is 98.9 % of the call.
- So attempt 1 is scored a failure although it did the work. The route resprays (~1 s), spends a
  second anchor slot, and attempt 2's call returns in **4-20 us** — because the victim's
  `pi_blocked_on` has already been consumed by attempt 1's walk, so attempt 2 performs no walk at
  all (`rt_mutex_adjust_pi` is not entered). The route scores *that* as the success.
- The counters make it worse: each attempt's `consumer_calls.store(0) / consumer_success.store(0)`
  discards the late-arriving success of the call that is still in flight.
- One observed failure is the same call not returning for the whole route call (>3 s): the
  consumer never picked up the following sequences, four attempts scored 0, and the native
  stopped. That is the run-level failure this design has to make survivable.

Cost of the status quo, measured: **two anchor slots and ~1 s of respray per route call** — about
14 of a boot's 128 slots for a 7-call run, i.e. half the per-boot run budget is spent on retries
that confirm what attempt 1 already did.

Delivery is *not* the problem: at 20 us the strip carried the window's own anchor word at every
sampled copy (1503/1503 per window), and the walk read the complete stamp.

### The settle bound, measured (23 calls, five runs, 5.10.236, 2026-10-12)

| run | call durations (`seq=1`, us) |
|---|---|
| 1 | 71452, 97036, 151737, 79687, 78172, 84561, 152974 |
| 2 | 93237, 99905, 90992, 130755, 158148, 126320, 120220 |
| 3 | 151989 |
| 4 | 129354 |
| 5 | 104497, 137636, 119079, 113270, 119186, 120519, 106188 |

min 71.5 ms, median 119.1 ms, mean 114.6 ms, **max 158.1 ms**. `sigreturn_settle_ms` defaults to
**300** — just under 2x the observed maximum, which is the rule this doc fixes the value by: the
bound is not safety-critical (a call that outlives it is reported unresolved and the stage's own
verification arbitrates), so it trades "catch the walk and score it" against "declare unresolved
and pay a stage-level check".

The bound is also **interval-independent**: the same distribution holds at `kCopyIntervalNs =
500 us` (27 calls, median 99.0 ms, mean 104.7 ms, max 166.0 ms), i.e. 25x fewer copies of the
strip changed the walk's duration not at all. One value covers both.

### What this change does *not* address

Two of the five runs in that series died with the walk reading a junk word at
`rt_mutex_adjust_prio_chain+0x188` (kernel text captured for the first time; FAR =
`0xc4ded2d985001dd8`). That is the strip-clobber crash — ~2 runs in 6 at `kCopyIntervalNs = 20 us`,
untraced — and it is a *carrier* question (item 47), not a scoring one. It does, however, make
the timeout path below load-bearing rather than theoretical: a death like that leaves the
consumer's call in flight forever, and today's response to it is the worst possible one — four
more attempts, each respraying and re-stamping under a walk that will never finish.

## The design

1. **Wait for the call, bounded.** When the stamp window closes, wait up to
   `sigreturn_settle_ms` for the consumer's in-flight call to return, polling with a short sleep.
   The wait is passive — it touches neither the victim's stack nor the lock — and the strip
   survives it: the walks completed cleanly at 71-158 ms while the route thread was *already*
   respraying (fork storms) in the same thread whose kernel stack holds the strip.
2. **Score the real result.** An attempt is a success when its own call returned 0. Attempt 1
   then scores as the success it is, and the route stops there: **one anchor slot per call, no
   respray**, which is the point of the change.
3. **The timeout path is deliberately *not* a blind retry.** If the call has not returned within
   the bound the attempt's outcome is *unresolved*: the write may or may not have landed. Do not
   respray and re-stamp under a walk that has not finished — that is exactly what turned the >3 s
   case into a lost run (four attempts, none scorable). Instead report the attempt unresolved and
   let the **stage's own verification** arbitrate: every stage already verifies its own effect
   (`init_cred usage pinned`, `child uid = 0`, the leaf watch, `child seccomp fully bypassed`).
   Retry only when the stage verification fails *and* no call is in flight.
4. **Never wipe a live call's counters.** Move the per-attempt reset after the settle (or make
   the verdict a per-sequence record rather than a running counter), so a late return is
   attributed to the attempt that started it instead of being destroyed by the next attempt.
5. **What stays permanent vs. what is diagnostic.** The verdict needs only the existing
   `consumer_inflight` flag plus the returning call's result — both cheap and permanent. The
   `LOCAL DIAGNOSTIC (run-18)` blocks (per-call records, the two printers, `consumer_seq_seen`)
   stay diagnostics and are stripped before any PR, as planned.

## Falsified on the device — 2026-10-12, the same day it was written

The design above was implemented (native only: the settle gate, delta scoring, the unresolved
path; the profile key as an `OPT` with the accessor's default). **Four runs on 5.10.236 at
`kCopyIntervalNs = 500 us all died**, against **4/4 completing on that same interval without the
change** (p ~ 0.014, and 2 of the 4 deaths carry the documented wedge signature exactly:
`sched: RT throttling activated` once a second with `gh-watchdog` starved).

| | runs | complete | deaths | wedge signature |
|---|---|---|---|---|
| without the change (the 500 us arm) | 4 | 4 | 0 | 0 of 4 |
| with the settle gate | 4 | 0 | 4 | 2 of 4 (the others' samples are post-reboot) |

**Why, from three directions at once:**

1. Every one of the 23 measured calls in the arms *ended during the respray* the old code starts
   at the window's close. The walk does not terminate itself: it exits when the strip *changes*,
   and the respray's deep syscalls run on the very thread whose kernel stack holds the strip.
2. With the gate, the route waits quietly -- and the call never returns. Run-28 stood unsettled
   after the 300 ms bound *and* after `disarm()`'s own 2 s, i.e. the walk spins in-kernel holding
   the victim's `pi_lock`; that spin is the wedge (`RT throttling` + `gh-watchdog`, the crash label
   `scripts/analyze-rate.sh` already uses).
3. The design's own escape hatch is self-defeating: "declare unresolved and let the stage's
   verification arbitrate" hands control back to a stage whose *first* act is a heap spray --
   exactly the disturbance that is dangerous under a live walk. The route cannot return while a
   walk is live.

**Consequence: the respray the gate removes is load-bearing.** The efficiency the design was
buying -- one anchor slot and ~1 s of spray per route call -- is not available by waiting. It is
available only by finding a *cheaper deliberate disturbance* to terminate the walk (a deep syscall
on the victim thread, no anchor draw, measured for whether it ends the walk as reliably as the
respray does), or by taking the slot savings from item 11's clean-slot recycling instead.

**What survives from the change**, and is worth keeping on its own:

- Never wiping a live call's counters, and scoring an attempt from deltas -- behaviourally a no-op
  against the old flow, but the route's totals finally mean what they say.
- Reporting **unresolved** rather than a false OK when the last attempt's call is still in flight
  (the run-17 w3c case): the route's status should not claim a routed write it cannot see. What
  must *not* come with it is stopping the retry -- the retry is the terminator.
- The `OPT` profile key should follow the decision: it is dead weight if the gate does not return.

## Profile surface

- New execution knob **`sigreturn_settle_ms`** (OPT, default **300**): the bound from step 1. It
  belongs in the profile for the same reason `route_wait_ms` does — it is a property of the
  walk's timing on a given build, and the below-floor builds get their own value.
- Wire: the execution section of the binary profile. **The Kotlin side must land in the same
  change**: the app enumerates execution fields by name (`GhostlockModels.kt` carries
  `execution.race.route_wait_ms` / `setup_settle_us` and `FieldLabels.kt` labels them), and the
  Kotlin↔native digest refuses the run when the two sides disagree — so a native-only key would
  make the app refuse to start the attack. Four files, one commit: `model.h`, `binary.cpp`, the
  Kotlin field list + label + string resource. A profile that omits the key decodes to the
  default, so no shipped profile changes.
- The default is the measured rule, not a guess: **~2x the observed maximum** of the call
  duration, revisited when a build's geometry changes.

## Gates

- `make -C src ghostlock` with zero warnings; `make -C src lint-tidy` exit 0; the host tests; and
  `tools/cmp_disasm.py` on the final shape, archived, since this is the attack path.
- A device series on 5.10.236 (>= 4 runs, reboot between) reporting the route's rate and the
  per-call settle duration.
- **Both paths exercised**: a normal run (settle catches attempt 1) and a falsifier for the
  timeout path — `sigreturn_settle_ms = 1` — confirming the route reports *unresolved* rather
  than failure, does not respray under an unfinished walk, and that the stage verification still
  decides the run.
- The incumbent unaffected: the select route's consumer path is untouched once the diagnostic
  blocks are stripped (they add one relaxed load while present). Re-run the incumbent once to
  show it.

## Open

- The bound is a starting value from 23 calls; more runs tighten it, and the rule above (not a
  fitted number) is what a future build re-derives it by.
- **Why the walk takes ~100 ms** now has a measured answer rather than a mystery: it is the
  *respray's latency*, not the walk's own cost. The walk exits when the strip changes, and the
  respray the old flow starts at the window's close is what changes it -- which is why the
  duration is interval-independent (median 119 ms at 20 us, 99 ms at 500 us) and why removing the
  respray wedges the box (above). The bound in this doc measured that latency, so it must be
  re-derived if a deliberate terminator replaces the respray. What the chain is *waiting for*
  inside those 100 ms -- the `goto again` re-read loop is the obvious suspect -- is still not
  established, and it is what the cheaper-terminator design would need.
- How the bound behaves below the floor (5.10.81 / 101) is unknown until that geometry runs on a
  device; the knob exists so the answer can be a profile value rather than a code change.
- **The carrier's own rate is a separate question and is not fixed here**: the strip-clobber
  crash above (1 run in 5 at 20 us on 236) is item 47's, and this change neither causes nor cures
  it. It does remove the *response* to it that made the outcome worse — four more attempts,
  each respraying and re-stamping under a walk that never finished.
