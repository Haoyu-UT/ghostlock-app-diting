# The victim runs real-time for the loop window — remove the CFS preemption (2026-10-15)

Level: **L** (attack-critical path: it changes how the consumer's walk is triggered and how the
victim is scheduled). Plan first, then code, per `AGENTS.md`. Operator approved the Arm A
experiment this session.

## Measured inputs

`external/port/strip-writer/README.md`, `external/port/strip-clobber/README.md`,
`external/port/consumer-drain/arm-d/read-mine.txt`:

- The strip's `lock` word (+0x38 of the waiter the walk reads) is destroyed by a **context switch
  whose frames descend past the strip's depth on the victim's stack**. Measured with `__switch_to`
  (a probe that fires deep, so its own trap lands below its `sp` and cannot be the cause): **2 of 19
  switches on the victim's stack reached 0x160–0x170 below the strip**, and the scheduler's locals
  there are the small integers every recorded death value shows (`0x11` ×5, `0xc`, `0x7`).
- Both crossings went to **CFS** tasks (`UsbFfs-worker`, a sibling app thread) — i.e. the victim is
  preempted in favour of ordinary runnable work. It is a **SCHED_BATCH** task (`util.cpp`,
  `sched_policy = 3`) that spins for 5–30 ms per attempt, which is exactly the shape that burns its
  slice and gets preempted.
- Rate: ~40 crossings/s × the ≤500 µs repair window ≈ 1% per walk, against the class's measured
  ~2% death rate. The copy is not the writer (76/76 and 35/35 deliveries correct), and the walk's
  own reschedule IPI is dead (`smsr`/`smsrr` fired 0 times).

## This change

Run the **victim** as `SCHED_FIFO` for the loop window, instead of `SCHED_BATCH` with a rotating
nice:

- `constants.hpp`: `CONSUMER_RT_PRIO_BASE = 30`, with the reason in the comment.
- `util.cpp` `sched_setattr_tid()`: `sched_policy = SCHED_FIFO (1)`, `sched_priority = prio_value`
  (the zeroed `sched_nice` field stays 0 — the kernel rejects a non-zero nice on an RT policy).
- `threads.cpp` (the consumer loop): the rotating value becomes an RT priority,
  `base + (calls_this_seq % 8)`. The **rotation is load-bearing and stays**: `__sched_setscheduler`
  returns early — with no PI walk — when the call changes nothing, which is why the existing code
  rotates the nice. Only the *kind* of value changes.

## Why this removes the mechanism and not just its rate

`check_preempt_curr()` only reschedules when the waker's class is *above* the current task's, and
CFS is not above RT; an RT task has no slice for `task_tick_rt()` to expire. So with the victim in
FIFO, **a CFS task cannot take its CPU**, and the two measured crossings could not have happened.
Interrupts still run — but an interrupt that returns *without* a reschedule leaves only its own
(shallow) frames, not a switch's deep ones.

## Why it is safe for the walk

- `rt_mutex_adjust_pi()`'s early exit is `waiter->prio == task->prio && !dl_prio(task->prio)`. The
  stamp's `prio` word is `FAKE_WAITER_PRIO = 140`; an RT victim's priority is 30–37; they differ, so
  the walk proceeds exactly as today.
- The policy/prio change is what makes `__sched_setscheduler` take the `pi` path at all, and a
  policy change (`!=` the current one) or a priority change both `goto change` — the rotation keeps
  one of those true on every burst call.
- Step [9]'s wake still targets `slide_init_task()` (the task-word change, unchanged).
- RT throttling: the default `sched_rt_runtime_us` budget is 950 ms per second; a 30 ms window × a
  handful of calls is far inside it.

## What it does not touch

The write vehicle (tree stamp, leaf/pointer layouts, the anchor's lock word), the geometry, the
handshake, the profile schema, and every other route. It is one policy value and one rotation.

## Gates, and the revert

- `make -C src ghostlock` with zero warnings, `make -C src lint-tidy`, host tests; `cmp_disasm`
  before this is ever landed as a PR (the changed symbol is not part of the payload builder, so the
  expectation is "no payload delta" — but run it, don't assume).
- Device gate: `external/port/arm-a/` — the crossing rate with the **safe** probe kit
  (`swt` + `rfaP` + `rw` + `rp`, every one of which fires deeper than the strip or on another
  task), against the same-kit baseline on the installed build. Decision rule in `PORT-PLAN.md`
  item 1: crossings → ~0 ⇒ the stack design survives; unchanged ⇒ the structural fix (page-resident
  waiter) is justified.
- Revert: `sched_policy = 3` + the nice rotation, i.e. the two hunks in `util.cpp`/`threads.cpp`
  and the constant.
