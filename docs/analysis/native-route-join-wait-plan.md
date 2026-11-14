# The native route's per-write waits (the join and the presets) — plan

Level: **L** — the attack path (the native PI race's thread lifetime and timing). Plan and operator
approval before code (`AGENTS.md`). The live item is PORT-PLAN *The native route's per-write waits*.

Status: stage 1 implemented (uncommitted on `document`), host-gated 2026-11-14. The diting select
row is **10/10 at 8.0–8.7 s** (was 16.5 s); the first parallel round exposed a bundle fact drift
(the 6.1.138 select asset lacked the compact waiter, 0/10) and the OnePlus/myron bundles ran their
DirtyFrag stage. The bundle is now fact-synced (check **60/0/0**, live render 57/57 agree, app tests
243+60); the 6.1.138-mi symbol offsets were corrected to the QEMU-witnessed store
values (0x2C0 base), and the fixed 6.1.138 bundle is device-gated **10/10** (native
16.2–18.2 s). The full matrix is measured: every row x/10 (the era row skipped by the
operator).

## The problem

The native PI race is created per write: `waiter_thread`, `owner_thread` and `consumer_thread`
(`src/core/race/threads.cpp`). After `route_done`, `PiRace::request_stop()` sets the stop flags and
`PiRace::join()` joins all three. The owner's stop loop is

```cpp
while (!race->owner_stop.load()) sleep(1);
```

so the join waits out the remainder of the owner's 1 s sleep — up to ~1 s on **every native write**,
eight writes per chain. The AArch32 compat engine already polls the same loop at 1 ms
(`state_poll_us`; `src/core/compat/carrier_engine.cpp:165,448`), so the compat carrier does not pay
it.

Measured first-write cost (native log, `page-free write start` → `PI route done`):

| rig / carrier | first write | full run (r11) |
|---|---|---|
| diting 5.10.236 native select | 1.235 s | 16.5 s |
| myron 6.12.23 native select | 2.204 s | 42.0 s |
| OnePlus 6.6.66 native select | 2.221 s | 24.3 s |
| duchamp 6.1.138 native select (r8) | 2.207 s | 20.8–23.1 s |
| duchamp 6.1.138 compat select | 1.221 s | 14.5–16.9 s |
| era 5.10.81 compat select | 0.258 s | 7.9 s |

The budget fits every row: the waiter's `FUTEX_WAIT_REQUEUE_PI` timeout (`route_wait_ms`: 30 ms
diting / 1000 ms generic) + the pselect timeout (200 ms) + the attempt-1 enter delay (5/50 ms) + the
join (~1 s). The carrier is not the cause: the diting's **native** select (1.235 s) matches the
duchamp's **compat** select (1.221 s). The 6.x native rows are slower because the generic
`route_wait_ms` is 1000 ms and the generic delays are larger — and every native write pays the join.

## Stages

### Stage 1 — the owner join (the code change)

`src/core/race/threads.cpp`, `owner_thread`:

```cpp
while (!race->owner_stop.load()) sleep(1);
```

becomes

```cpp
while (!race->owner_stop.load())
    usleep(session::g_exploit_session.profile.race_state_poll_interval_us());
```

The 1 ms poll is what the compat engine already does; `race_state_poll_interval_us` is 1000 µs on
every sampled profile. Fallback if the 1 ms wakeups perturb the race: a futex/condvar wait woken by
`PiRace::request_stop()` (zero periodic wakeups, a few more lines).

Why it is safe: the loop runs after `owner_chain_done` — the owner holds the chain lock and the
target lock and does nothing else until the stop is read. The change shortens only the stop latency;
it does not touch the race state, the walk, or the locks. The device series is the gate because the
owner's wakeups are scheduling noise while the walk is in flight.

Expected, 8 writes per chain: diting select 16.5→~8.5 s, diting sigreturn 14.0→~6 s, OnePlus
24.3→~16 s, myron 42→~34 s (its ~20 s handoff is separate), duchamp native select 21–23→~13–15 s,
tcp 36.2→~28 s, ksun multicast 46→~38 s.

**Stage 1 implementation status (2026-11-14).** Implemented on `document` (uncommitted): the loop
above, with a one-line comment. Host gates: `make -C src ghostlock` rc 0 with zero warnings;
`make -C src lint-tidy` rc 0; `make -C src native-host-tests` rc 0 (all targets ok).
`tools/cmp_disasm.py` against a worktree build of `f1afa7be`: `owner_thread` 69→70 instructions —
the disassembly is exactly `mov w0,#1; bl sleep` → `ldr w0,[profile+…]; bl usleep`, every other
instruction identical; `waiter_thread` 278, `consumer_thread` 187, `do_kernel5_fake_lock_route` 386
and `do_one_write` 180 are strict-identical; the three MISSING symbols are absent in both binaries
(the known control FAIL, unchanged). APK `GhostLock-v1.2(745)-arm64-v8a-debug.apk` md5
`84f3b370…`; `libghostlock.so` `4b5c0626…`; `libghostlock32.so` `27432520…` (unchanged from build
744 — the compat rows' provenance). The device matrix is pending the diting restore.

### Stage 2 — the park window (config, per device)

The generic `route_wait_ms = 1000` (`app/src/main/assets/kernel_profiles/execution-tuning.conf`) is
the waiter's `FUTEX_WAIT_REQUEUE_PI` timeout. The requeue does not wake the wait in practice (the
compat helper's waiter returns `ETIMEDOUT`), so the value is the park duration; **both carriers pay
it**. The diting's measured preset is `route_wait_ms 30 ms` / `setup_settle_us 10 ms`
(`device_defaults.conf`; the batch C/D/E evidence in the 5.10.236 asset's comments). The generic
settle is 50 ms and the attempt-1 enter delay is 50 ms, so the wait must stay above both.

First candidate, per rig (a `device_defaults` entry, not a global edit): 200 ms wait with the
existing 50 ms settle and 50 ms enter delay. Expected ~0.8 s/write. The diting's 30/10 stays as
measured; no rig gets a preset it has not run.

### Stage 3 (optional) — the enter delay

The generic `enter_delay_us = 50 ms` (`execution-select-stack.conf`) is the attempt-1 walk seed; the
diting's 5 ms came from batch C/E. Per-device tuning, ~45 ms/write. Lower priority.

### Not changed — the pselect timeout

`select_stack.timeout_us = 200 ms` stays. It holds the waiter's syscall frame alive during the
walk; the compat path zeroes it only because the helper's mechanics differ. Tuning it is a separate
strip-window study, not part of this change.

## Gates

Host: `make -C src ghostlock` (zero warnings), `make -C src lint-tidy`,
`make -C src native-host-tests`, `tools/cmp_disasm.py` (read the per-target instruction counts; the
known FAIL is the missing `multicast_*` control). Device: the matrix below, one series per stage.

## Device test matrix — every README row **10/10, no gaps**

**The rule.** Every row of the README success table is exactly **10 counted runs** on the final
build. No row ships as 9/9, 4/4 or 4/5; no row is left partial. The counted-run protocol
(`scripts/series-run.sh`):

- one run per fresh boot; the run store (`files/runs/<stamp>/meta`) is the verdict;
- a run that never starts (no new store / `FAILED-TO-START`) is retried on a fresh boot and does
  **not** count; if three attempts fail the rig is fixed and the row waits, never counted short;
- a started run counts whatever the store says — `completed`, `failed`, `interrupted` (a mid-run
  reboot is a failure);
- an interrupted series resumes on fresh boots to 10; the `after` column below is not written until
  the row is 10.

**The rows.** The profiles and prep are the ones each row was last measured with; the build is the
one carrying the join change. The `after` column is filled by the series; the README table is
regenerated from it, never from a partial row.

| # | rig | kernel | route · carrier | page | profile / prep | n | r11 before | expected (stage 1) | after |
|---|---|---|---|---|---|---|---|---|---|
| 1 | diting | 5.10.236 | `select_stack` · native | page-free | external select profile `5e83cd93…`, `pipeline = "ghostlock"` (the bundle is DirtyFrag-first) | 10 | 10/10, 16.5 s | 10/10, ~8.5 s | **10/10, 8.0–8.7 s** (per-write 0.24 s, was 1.24 s) |
| 2 | diting | 5.10.236 | `sigreturn` · native | page-free | the rendered sigreturn document (`65c4ec8f…`); the first series was all NOT-STARTED (the SAF selection went unreadable; re-selected) | 10 | 6/10, 14.0 s | ~6/10, ~6 s | **4/10**, native 6.8 s (was 14.0); the six deaths at W1/W2/W3-0/W3 (the strip class) |
| 3 | diting | 5.10.236 ksun `-Os` (custom) | `multicast_waiter` · native | page-free | the current extractor render (`6d716bbc…`; the store's 2026-10-22 `profile.conf` is the pre-page-free/no-pipeline cut); `boot_a` flashed to the ksun Image (`f1c82be5…`), restored after | 10 | 4/5, 46 s | ~8/10, ~38 s | **9/10**, native 38.7–39.9 s (was ~46); the one death at W1 |
| 4 | diting | 5.10.81 (era) | `select_stack` · compat | page-free | the era compat select asset; requires the era flash (or keep the r11 10/10 — the helper path is untouched) | 10 | 10/10, 7.9 s | 10/10, 7.9 s | |
| 5 | duchamp | 6.1.138 | `select_stack` · compat | page-free | the external compat select document (`a002dba4…`) | 10 | 4/4, 14.5–16.9 s | 10/10, same | **10/10**, native 16.9 s; `compat carrier: home=0x1e8 dst=0x1f0 offset=0x8 abi=1` |
| 6 | duchamp | 6.1.138 | `multicast_waiter` · compat | page-free | the external compat multicast document (`4bc3f57a…`) | 10 | 10/10, 15.3 s | 10/10, same | **8/10**, native 16.3 s; the deaths at W2 and W3-0 (the strip/W3 class, not the carrier) |
| 7 | OnePlus | 6.6.66 | `select_stack` · native | page-free | the external ghostlock copy (`45e2303b…`): the DirtyFrag-first bundle alone runs the W1-only stage | 10 | 10/10, 24.3 s | 10/10, ~16 s | **10/10**, native 16.6 s (was 24.3), exploit T+15.0 s; per-write 1.2 s (was 2.2) |
| 8 | myron | 6.12.23 | `select_stack` · native | page-free | the external ghostlock copy (`2197802d…`): the DirtyFrag-first bundle alone runs the W1-only stage | 10 | 9/9, 42.0 s | 10/10, ~34 s | **10/10**, native 34.9 s (was 42.0), exploit T+14.3 s; per-write 1.2 s (was 2.2) |
| 9 | duchamp | 6.1.138 | `tcp_zerocopy` · native | page-based | the external page-based tcp document (`6422ba4d…`; the page-free blocks removed — the app refuses them on the tcp route) | 10 | 8/10, 36.2 s | ~8/10, ~28 s | **8/10**, native 30–36 s; the two deaths at the page-W1 acceptance (the even-initialized page) |
| 10 | duchamp | 6.1.138 | `select_stack` · native | page-free | the synced bundle (the `waiter_layout`/`compact_waiter` facts added 2026-11-14) | 10 | 10/10, 20.8–23.1 s (r8) | 10/10, ~13–15 s | **10/10** (was 0/10 before the sync); native span 16.2–18.2 s, exploit T+14.0–15.5 s; per-write 1.2 s (was 2.2 s) |

Rows 1–3 and 7–10 are the native routes the change touches; rows 4–6 are the compat carriers, which
the change cannot affect (verify `libghostlock32.so` is the same md5 as the r11 build; if it is, the
compat rows' execution is unchanged and their re-run is for table provenance, not for the fix).
Row 3's kernel swap and row 4's era flash each need their own in-turn flash approval; row 4 may keep
the r11 10/10 with a provenance note instead.

**Time read.** For every run, the native log's first-write delta (write start → `PI route done`) is
the mechanism check; the app-log span (`starting native` → `native exited`) is the table's time. A
row whose time does not drop while the first-write delta does is a different bottleneck (the handoff
or a stage), not this change.

**Stage 2 matrix.** If stage 2 lands, it repeats every row that pays the preset — all ten — on the
new preset, again 10/10 per row; the stage-1 `after` data stays as the stage-1 record.

## Risks

- **The owner's 1 ms wakeups.** The owner shares a CPU with the race's threads; the wakeups could
  add scheduling noise during the walk. The series is the gate; if the rate drops, the futex/condvar
  wait replaces the poll before anything is shipped.
- **The park window.** Stage 2 shortens the waiter's park; too short and the walk reads the stack
  after the waiter left the syscall. Per-rig, measured, one preset at a time; the 200 ms/50 ms
  candidate stays above the settle + enter delay. The diting's measured 30/10 is not reused blindly.
- **`panic_on_oops`.** The diting's rig has `panic_on_oops=1`; a rate regression is a reboot, not a
  captured oops. The series' store verdict catches it; the capture path is off unless a crash is
  being investigated.
- **Attribution.** No A/B is planned; the time read is direct (the first-write delta), and the rate
  is compared to the r11 rows. A rate change smaller than n=10 can resolve is not detectable — the
  rows' historical bands are the reference, and a drop below them stops the change.

## Evidence

`external/port/ab-drain-2026-11-13/` (the carrier rows and the counted-run protocol),
`external/port/route-carrier-duchamp-2026-11-14/` (the compat select), and
`external/port/pagefree-6x-2026-11-01/` (the duchamp native select). The series dirs will be
created under `external/port/` per the evidence rules when the matrix runs.
