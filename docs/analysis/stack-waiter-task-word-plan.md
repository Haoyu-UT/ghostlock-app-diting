# The stack waiter's `task` word — aim the one wake at a running task (2026-10-14)

Level: **L** (attack-critical path: the strip the walk reads and writes through). Plan first, then
code, per `AGENTS.md`. Operator pre-approved this round.

Measured inputs, all from `external/port/consumer-drain/`:

- `arm-d` times every route call: entry → erase → enqueue → **`try_to_wake_up` +35 µs in** → return
  **131–186 ms later**. The wake *is* the call, and its target ends in `0x400` — `page + 0x400`,
  i.e. `fake_task`, the forged task_struct in the payload page.
- `arm-c` shows the same walk, with A's idle waiter thread, taking **5.38 s** and still returning 0.
- `arm-d`'s oops (`run-1/oops.txt`) is the other class in the same run: our own consumer's walk
  faulting at `rt_mutex_adjust_prio_chain+0x188` with `waiter->lock = 0x11` — a strip word read
  *after* something had overwritten it.

## The word, and why it is read exactly once

`struct rt_mutex_waiter` word `+0x30` is `task`. In this flow the walk reads it in exactly one
place — step [9] of iteration 1, which our own enqueue makes reachable:

```c
	if (!rt_mutex_owner(lock)) {
		if (prerequeue_top_waiter != rt_mutex_top_waiter(lock))
			wake_up_process(rt_mutex_top_waiter(lock)->task);   /* ← the one read */
		...
		return 0;
	}
```

The *chain* does not use it: the walk follows the **lock's** `owner` field (`[10]`, and the design's
own `rt_mutex_dequeue_pi(fake_task, …)` note is about that field — the payload page's fake lock
carries `owner = fake_task | 1`). With the anchor, `owner == 0`, so [9] is the only reader.

It cannot simply be zero — `try_to_wake_up(NULL)` is a NULL deref — so the design must aim it
somewhere. Two of the three stamps already aim it at a **real task**, and that is the whole change:

| stamp | `+0x30` today |
|---|---|
| page waiter (`util.cpp`, `W0_OFF + 0x30`) | `slide_init_task()` — a real, permanently-running task |
| TCP route's on-stack waiter | `slide_init_task()` ("waiter->task carries init_task's phys alias") |
| **sigreturn / select_stack stack stamps** | **`heap.current.fake_task`** — the forged struct |

## This change

Point the two stack stamps at `ghostlock::profile::slide_init_task()` — one argument each:

- `sigreturn_route.cpp` `build_stamp()`: the `waiter_words(...)` call's task argument.
- `select_stack_route.cpp` `select_stack_build_fdsets()`: both `pselect_waiter_word` tables' `task`
  entry (word 8 in the compact table, word 12 in the non-compact one).

Both are the *same* word in the same struct, so both need it; leaving one would leave one route
with the slow, dangerous wake.

## Why this is safe, and what it does not touch

- **`try_to_wake_up` returns immediately.** `init_task.state` is `TASK_RUNNING` (0), and
  `if (!(p->state & state)) goto unlock;` is its first test — no runqueue, no `sched_class`, no
  `wake_cpu`, nothing read past `p->state` and `p->pi_lock`.
- **It is permanent.** `init_task` is a static object that exists for the whole boot, so there is
  no lifetime or refcount question (the forged page has both).
- **The write is untouched.** The store rides the *tree* triple's erase; `task` is not part of it.
- **The chain is untouched.** Termination comes from `rt_mutex_owner(lock)` — the anchor's owner is
  0, and the page-lock variant's owner is the fake task *inside the page*, which is unchanged.
- **Delivery, the interval, the anchor rotation and the disarm are untouched** — this change does
  not move the strip, only what one of its eleven words points at.

It is deliberately *not* the protocol simplification (dropping the inner retry loop): with the wake
fast, the drain this plan's sibling added becomes viable as written, the route's success criterion
finally tells the truth, and attempt 2 stops happening on its own. Simplify later if the device
agrees; do not bundle it into the measurement.

## Predictions, and the falsifier

On a healthy run, every route call should read:

- `calls=1 success=1 status=0 clean=1/1 step=0 stamps=1`, and
- `drain=` in the **microsecond** band (0 ms at the line's resolution) instead of 100–250 ms.

If instead `drain` stays in the hundreds of ms, the premise is wrong at the kernel level — check
the trace's `tw` rows first (still the forged task? then this build did not take; still slow but on
`init_task`? then the tail is not the wake-path early exit but something after it), and only then
look further. A `calls=2` call is the same signal: the attempt protocol did not close.

## Gates

Build 0 warnings, `lint-tidy`, the host tests that build on x86_64, and `cmp_disasm` with every
difference accounted (baseline: the pre-A build the rig ran, `1063b42f…`-tree, so the record shows
this change *and* the drain together against what shipped). Then a device series: five runs, one per
boot, `../port/rate-500us/README.md` protocol, cpuset guard on, sigreturn profile.

Judged by: the shape above on every call; the chain completing; and the two classes' absence in the
series (with the archive's base for each: `step=38` six instances, the `+0x188` class three
kernel-text deaths in five uninjected runs on 2026-10-14 before the disarm).

## RESULT (2026-10-14) — device-verified, first series

Five runs, one per boot, test sigreturn profile (`external/port/consumer-drain/task-word/`):
**every route call in all five runs read `calls=1 success=1 status=0 clean=1/1 step=0` with
`drain=0ms` — 29 of 29**; runs 1-3 finished the whole chain (`exploit complete` T+18.6/21.9/27.1 s,
`KernelSU ready`); run 4 died in the pre-existing post-spray wedge (no kernel text) and run 5 in the
pre-existing `+0x188` stale-frame class (text: `x27 = 0x7`), after 7 clean calls each. Zero `step=38`,
zero `calls=2`, zero `drain=-1` across the series.

Both predictions held exactly: the microsecond drain, and the shape change on every call. Runs also
got ~10-20 s faster (the inner retry loop's respray per route call is gone), and the payload page is
no longer freed while a walk is inside it.
