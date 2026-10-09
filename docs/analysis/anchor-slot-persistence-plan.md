# Anchor slot persistence — the run-to-run failure rate

Status: implemented 2026-10-09. L-level (attack-critical payload layout), operator
approved. Supersedes the "~1000 slots" note in `stale-waiter-lifetime-plan.md`.

## Symptom

On diting 5.10.236 the select_stack chain is reliable *within* a run but the run
after a completed run died in its **first dance**, 8/8 measured:

```
run 1 (fresh boot)  finished  [+] KernelSU ready
run 2 (after run 1) reboot    last log line: pselect pre-select attempt=1/4 +0ms
run 3 (fresh boot)  finished  ...
run 4 (after run 3) reboot    ...
```

Strict alternation over 8 runs, and every death:

* stops the app log at `pselect pre-select attempt=1/4` — the first dance never
  reaches `post-select` (a healthy one does, at +200 ms), so the thread doing the
  route died there;
* leaves an oops (3 of 4 captured, identical):

```
pc : rt_mutex_adjust_prio_chain+0x3f0/0x1948
x27 = x24 = ffffff802aa3a590     <- the anchor (slot 0), image +0x2a3a590
x8  = ffffffc054683c30           <- lock->waiters.rb_leftmost = a DEAD STACK
ESR = 0x96000007  pte = 0        <- that thread's stack is unmapped
call trace: rt_mutex_adjust_prio_chain <- rt_mutex_adjust_pi <- __sched_setscheduler
```

`+0x3f0` is `rt_mutex_top_waiter()`'s `BUG_ON(w->lock != lock)`, i.e. the load of
`rb_leftmost->lock` — the **first** dereference of the anchor's waiter tree, before
the walk can re-enqueue anything.

After the oops the box is not merely wounded: the killed task exits with
`preempt_count 3` (it was inside `__sched_setscheduler`), the lock it held is never
released, `gh-watchdog` spins on it, `sched: RT throttling activated for cpu 1` +
`current gh-watchdog (172) is running for … nsec` repeat every second, and the SoC's
hardware watchdog resets the device. That is why `panic_on_oops=0` does not save
these runs (it saved the earlier oopses, whose tasks held no lock).

## Root cause (measured, not inferred)

The anchor is **not private memory**: the requeue path enqueues the fake waiter into
`lock->waiters` (`rb_add_cached` sets `rb_leftmost`), and that waiter lives in the
pselect stack frame of the **waiter thread** — `race::waiter_thread` parks on
`FUTEX_WAIT_REQUEUE_PI` and then runs the route controller on the same thread, which
is what makes the freed waiter and the fd_set buffer the same memory. The thread
exits when the stage attempt ends, so its stack is unmapped (`VMAP_STACK` → the
level-3 PTE is cleared, which is exactly the `pte=0` in the oops).

Measured with a kprobe reading the anchor's boot-invariant direct map
(`0xffffff802aa3a590`; fetchargs `@0x<va>:x64` **do** work — the earlier note that
they were unreliable applied to KASLR-slid *image* addresses):

```
freshly booted, idle      -> o00=0 o08=0 o10=0 o18=0
after one successful run  -> o00=0 o08=0xffffffc0546f3c30
                                  o10=0xffffffc0546f3c30 o18=0
                            o20..o78 all 0
```

One run poisons the slots it used, for the rest of the boot. The old serial was a
**process-local `static`**, so every new process restarted at slot 0 and walked
straight into the previous process's dead pointer. A reboot cleared it — hence the
perfect alternation: `.bss` is zeroed at boot, `rb_leftmost` is NULL and
`rt_mutex_top_waiter()` returns before the `BUG_ON`. That is also why the first run
after a reboot always worked and why the Q-series device gates passed.

The same measurement gives the fake lock's write footprint: only `+0x08` and `+0x10`
are ever written, nothing reaches `+0x18`, so slots cannot overlap at a stride of the
object's own size (0x20 on this build — no `CONFIG_DEBUG_SPINLOCK` /
`DEBUG_LOCK_ALLOC` / `PROVE_LOCKING`).

## Second bug found while checking the budget

The rotation's own bound was wrong. `dump_skip.zeroes` is the page-sized
`static char zeroes[PAGE_SIZE]` in `fs/coredump.c` — only ever *read* (the zero source
for core-dump holes) — and its symbol extent is **0x1344, i.e. 4932 bytes**, not the
"~78 KB / ~1000 slots" the comment claimed. At the old 0x80 stride that is 38 slots,
and the next symbol is `kernfs_pr_cont_lock` / `kernfs_pr_cont_buf` (kernfs's **live**
printk continuation buffer, with `blocked_hash` and `lease_notifier_chain` on the
other side). Any run making more than ~38 attempts was already pointing the walk at a
live kernel variable. Nothing hit it only because failing runs die at attempt 1 and
healthy ones spend 10 slots.

## Fix

`route/select_stack_route.cpp`:

* `kLockAnchorStride` 0x80 → **0x20** (the measured object size) and an explicit
  `kLockAnchorBytes = 0x1000` → **128 slots** per boot.
* `select_stack_anchor_slot()` is now **boot-scoped and cross-process**: the
  reservation (`boot_id`, `next_slot`) is persisted in
  `$GHOSTLOCK_HOME/.ghostlock_anchor` (new `config::anchor_state_file()`), reset to 0
  when `/proc/sys/kernel/random/boot_id` changes, and **written before the slot is
  handed out** — so a lost write can skip a slot, never hand the same one out twice.
  `fflush` suffices: the next process reads the page cache, and a kernel-level loss
  means a reboot, which changes the boot id anyway.
* A missing/unreadable state file is *not* guessed as 0 (that is the bug). It starts
  at `uptime % slots` and warns loudly, telling the operator to reboot if this boot
  already ran the exploit.
* `select_stack_build_fdsets()` now returns `bool`; both call sites fail the route
  (`fail(34, ENOSPC)`) when the budget is spent or a waiter word did not land.
  Walking past the region is never an option.

## Gates

* `make -C src ghostlock` — 0 warnings.
* `make -C src lint-tidy` — exit 0.
* `runtime_paths_test` (host) — extended with the new path helper; passes.
* `cmp_disasm` — run, and the result has to be read carefully: the tool reports **FAIL for a
  baseline-vs-itself control** too, because `multicast_owner_worker` / `multicast_waiter_worker`
  are absent from *both* binaries (a pre-existing property of this build, not something this
  change introduced). Against the baseline every present target keeps its instruction count
  exactly (owner_thread 69, waiter_thread 895, consumer_thread 177, run_main_route_threads 417,
  do_kernel5_fake_lock_route 174, do_one_write 126); the only differences are rodata label
  annotations shifting (`LAYOUT-SHIFT`). This change is in slot *selection* plus error plumbing,
  not in the attack disassembly.
* Device gate: see *Verification*.

## Verification (2026-10-09, one boot, patched kernel)

Runs back-to-back in a single boot, on exactly the state that was 4/4 fatal before
(`external/port/rate-fix/`):

```
run 1  finished  [+] KernelSU ready   anchor slots: new boot, starting at 0/128     slot 0
run 2  finished  [+] KernelSU ready   anchor slots: 10/128 already spent this boot  slot 10
run 3  finished  [+] KernelSU ready   slots 20…
run 4  finished  [+] KernelSU ready   slots 30…
```

Predictions 1 and 2 hold: the previously-fatal run resumed at slot 10 instead of 0 and completed
the whole chain, and `slot 0` appears only in the boot's first run. Prediction 3 is checked with
the `anch3` probe after the series; prediction 4 needs ~11 runs.

### Residual failure — a *different* bug, previously masked

The fifth run of the series died, and its oops is **not** this one:

```
[215.48] pc : kmem_cache_free+0x3dc      x19=ffffff802a7b0a60 (an image addr)  x8=x9=8f347f75a1045d00
[233.83] pc : rt_mutex_adjust_prio_chain+0x188
         x27: 00004ce200000000            <- waiter->lock = a PID in the high half (0x4ce2)
         x28: ffffffc049b43c30            <- the waiter
```

That is the **stale-waiter lifetime** signature exactly as recorded on 2026-10-09 01:00 (x27 was
`0x4d26…` then, next to the exploit's own PID): a task's `pi_blocked_on` still points at the fake
waiter after that pselect frame has been reused, so a later walk reads `waiter->lock` out of
whatever the reused stack now holds and dereferences it. It never touches `rb_leftmost`, and the
slot it ran on (41) was pristine — so the anchor allocator is not involved.

It was *unreachable* before this fix: every run in the fatal state died at attempt 1, so nothing
ever got to attempt 2. Removing the anchor killer exposed it at roughly 1 run in 5. Its own plan
is `docs/analysis/stale-waiter-lifetime-plan.md` (the P1 build guarded only the consumer's
`FUTEX_LOCK_PI` fallback trigger, which is one of several). The first oops in that same run
(`kmem_cache_free` with a garbage cache pointer, freeing an *image* address) is a separate
collateral class — the exploit's own cred/slab rewrite living on after the run.

### A second residual mode, later in the run

The next boot's second run died with **no oops at all**: the polled sample holds only

```
[197.99] sched: RT throttling activated for cpu 3
[197.99] current gh-watchdog (172) is running for 1135923858 nsec
… eight one-second samples, growing to 7839924556 nsec
```

starting ~27.8 s into the run (the run began at uptime 170.19 s) — i.e. after the chain, around
the handoff. A spin, not a data abort: something is holding a lock that the RT watchdog feeder
then waits on, and the SoC resets. Same downstream mechanism as before, different cause.

So post-fix the deaths are a **mixed bag of lower-rate walk/lifetime failures**, not the one
deterministic anchor fault. Two lessons for the record:

* **The app log's stopping point is not a reliable statement about where a run died.** R3 run 2's
  stream ends at `pselect pre-select attempt=1/4` (T+1.3 s) while the kernel stayed healthy until
  T+27.8 s — the FUSE/MediaProvider log path stalls on its own. For the original bug the
  attempt-1 claim was independently confirmed by the poisoned slot *and* the `+0x3f0` oops, and it
  stands; do not reuse the inference elsewhere.
* Sample size matters: 8 pre-fix runs contained 4 anchor deaths and 0 residual ones, 6 post-fix
  runs contain 2 residual ones. The residual rate needs its own series before it can be quoted.

## Predictions (falsifiable, in order)

1. A run that follows a completed run now **succeeds** (was 4/4 fatal). App log shows
   `[route] anchor slots: N/128 already spent this boot` and the first dance's
   `lock anchor: … slot N` with N ≠ 0.
2. `[route] lock anchor: … slot 0` appears only in the first run after a reboot.
3. The kprobe sample after N runs shows slots `0…N-1` each holding `o08 == o10` (the
   dead waiter) and every *unused* slot still all-zero — i.e. no slot is reused.
4. Run 13 in one boot fails cleanly with the budget message instead of oopsing.

## Series `rate-fix4` (2026-10-09 ~13:40, S1-batch build) — rate re-measured

One fresh boot, 8 runs back-to-back, **zero reboots**, device uptime continuous across the whole
series. Artefacts `external/port/rate-fix4/`; `sh scripts/analyze-rate.sh external/port/rate-fix4`.

| run | slots | outcome |
|---|---|---|
| 1-4 | 0-63 | **complete** (`native exited code=0` / `KernelSU ready`) |
| 5 | 64-95 | W1 landed; W2 failed 15 rounds — victim child oopsed (below) |
| 6 | 96-127 | same, with W1 skipped (`SELinux already permissive`) |
| 7-8 | — | **budget refusal**: `128/128 already spent`, `exit 255`, no crash |

Effective sample 6 runs (7-8 never had a slot left): **4/6 end-to-end, 0 wedges, 0 reboots.** The
comparison that matters is qualitative and it is unambiguous: pre-fix, a run *following a completed
run* was 4/4 fatal — oops in a task holding a kernel lock, `gh-watchdog` starvation, SoC reset. That
same sequence now runs 8 times in one boot with the box never resetting.

**The two failures are one new signature, and it is in the victim, not the route.** Both runs 5 and 6:

```
Comm: ghostleaf_01234        <- the victim child, PID 12452
pc : selinux_file_permission+0x58/0x17c
lr : rw_verify_area+0xa8
Call trace: selinux_file_permission <- rw_verify_area <- vfs_write <- ksys_write <- __arm64_sys_write
x28 = x23 = x22 = ffffff897f3cb780      <- the child's task_struct (== the run's child_task)
x0  = x19 = ffffff887aaa9900            <- a cred whose ->security is NULL; fault reads [NULL+4]
```

i.e. the child's cred write leaves a cred whose SELinux blob is NULL, and the child's own reply
`write()` to the uid pipe then data-aborts. Two consequences, both measured:

* **The verifier is silent, by construction.** `verify_w2_stage` (victim_process.cpp:235) returns 0
  without printing when either the `write(cmd_write, "C")` or the `read(uid_read)` fails, so a dead
  child is indistinguishable from a missed write in the log. Every W2 failure of this class looks
  like "no output between the round headers".
* **The remaining rounds are futile.** The victim is forked **once per run** (one `child_pid=` line
  in both runs), so rounds 2-15 drive a corpse. That is also what eats the boot: a failed W2 spends
  ~30 slots (15 rounds x 2 attempts), which is why runs 7-8 had nothing left. A re-fork on round
  failure would both fix the waste and make the retry meaningful.

Not yet established: *why* the cred is bad, and why only runs 5-6 (attempt 1 of every stage failed
in all 6 runs identically, so the difference is downstream of the route). The `child_task + 0x780`
target is right (`child_task=0xffffff897f3cb780`, `target=0xffffff897f3cbf00`), the route reports
`status=0`, and the child survives long enough to issue a write — so this is a bad *value* or a
partially-applied write, not a missed one. Next target, ahead of any further rate measurement: the
budget is spent long before a series can quote a number.

## Open items

**Status at hand-off (2026-10-09 ~13:30): fix implemented and verified, rate not yet re-measured,
two residual failure modes open.** The work is uncommitted on `document` (belongs on
`port/diting-5.10.236-gfb24cf99ad97`); `GhostLock-R3-anchorpersist.apk` (71086eea…) is installed.

### Step 1 — batched reservation (implemented 2026-10-09 ~13:35)

`select_stack_anchor_slot()` now reserves `kLockAnchorChunk = 8` slots per state-file write instead
of one, so a healthy run (5 stages, 1-2 attempts each ≈ 12 slots) makes **2 writes instead of ~12**,
and the attempts in between do no file I/O at all. The safety property is unchanged: the chunk's
*end* is persisted before any slot in it is handed out, so a later process can never be given a slot
this one used. A process that dies mid-chunk only *skips* the remainder — waste ≤ 7 slots, which is
what pays for the change: per-boot run budget falls from ~13 runs to about **8**.

New log line, one per chunk, is the signature that the batching is live:

```
[route] anchor slots: reserved 12..19 of 128
```

**Confound closed, negatively (measured in run 1 of `rate-fix3`).** The first attempt of every
stage still fails (`post-select … ret=3`) with the batching in place — and it fails on attempts that
did **no** file I/O at all: W2 attempt 1 took slot 2 and W3-0 attempt 1 took slot 4, both inside the
chunk `reserved 0..7` that slot 0 had already persisted. So the per-attempt write was *not* what the
first-attempt failures were about; whatever makes attempt 1 return early is older and structural. The
batching is still worth keeping (2 writes per run instead of ~12, and it is what makes this statement
possible), but step 3's `enter_delay_us` test is now the only live explanation on the table.

Two consequences to keep in mind when reading the next series:

* ~2 such lines per run (the second chunk is usually only partly used) against one
  `lock anchor: … slot N` line per *attempt*;
* the budget now runs out mid-run rather than exactly at a run boundary, so a series long enough to
  exhaust it will show a final run failing with the budget message rather than a crash. That is the
  intended refusal (prediction 4), not a new failure mode.

### Slot lifecycle (measured 2026-10-09, after one healthy run)

```
slot 0 (attempt 1 FAILED):     +0x00 0, +0x08 = +0x10 = 0xffffffc059923c30, +0x18 0
slot 1 (attempt 2 SUCCEEDED):  +0x00 +0x08 +0x10 +0x18 = all 0
slots 0-9 alternate poisoned/clean; slots 10-15 and 100-115 all zero
```

A **failed** attempt poisons its slot (root and leftmost both dangle); a **successful** attempt
leaves the whole object zero — the proper kernel cleanup runs. A healthy run therefore permanently
poisons only ~5 slots, while this allocator conservatively spends ~9-10 (one per attempt) ≈ 13 runs
per boot. Handing successful-attempt slots back would roughly double that.

### Plan, in order

1. ~~**Batch the reservation**~~ — **done 2026-10-09 ~13:35**, see the section above. Removes the
   one un-excluded confound (the per-attempt I/O sat just before the pselect, and post-fix *every*
   stage was failing its first attempt — 5/5 in run 3 — which the pre-fix logs did not show).
2. **Re-measure the rate with the anchor fix alone** — one fresh boot, ~13 runs (the budget),
   including "run after a completed run", then sample slots with the `anch3`/`anch4` probes. Quote
   the residual rate only from that series; 2/7 vs the pre-fix 4/8 is p ≈ 0.6, i.e. nothing yet.
3. **`enter_delay_us` 5000 → 10000** (the earlier session's keeper value, which made W1 land
   first-dance). No failed attempts ⇒ no poisoned slots and no re-park windows; needs a profile
   re-import on the phone.
4. **The real residual fix** — `stale-waiter-lifetime-plan.md`: guarantee that no walk targets a task
   whose `pi_blocked_on` is stale. Observed twice post-fix: an abort (`+0x188`, `x27` = PID-shaped
   `waiter->lock`, with a `kmem_cache_free` oops in the same run) and a late spin/wedge ~T+28 s with
   no oops at all. Working hypothesis: one root cause, the wedge being what a task killed while
   holding a lock looks like.
5. Optional: hand clean (successful-attempt) slots back — see the lifecycle note.
6. Deferred: the region is one page. A larger verified-zero region needs a second profile key, hence
   the Kotlin resolver → `from()` → document → `entries()` chain; `serial8250_ports` (0x6500) is the
   candidate but has *not* been verified dead on-device (kprobe reads would settle it).
