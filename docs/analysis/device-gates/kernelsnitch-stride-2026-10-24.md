# KernelSnitch stride-agnostic scan — device gate (2026-10-24) — PASS (leak), chain partial

Branch `feat/kernelsnitch-stride-fallback`, base `document` @ `32b9ca8` (uncommitted changes; see
`docs/analysis/kernelsnitch-stride-fallback-plan.md`).

## Device and entry

- Redmi K50 Ultra (`diting`), `5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284`, SELinux
  Enforcing, root present from boot.
- APK `GhostLock-v1.2(639)-arm64-v8a-debug.apk`, md5 `a4c28e95e6e005e37527595b2314bb54`.
- Runs driven by `scripts/run-loop.sh 1 <outdir>`; the app was cold-started per run. The driver
  leaves the display asleep after a run, so a follow-up run must wake the screen first (the first
  falsifier attempt failed to start for exactly that reason; it was retried after `KEYEVENT_WAKEUP`
  + swipe and produced no run directory).

## Profiles

- **Control:** the bundled `5.10.236` profile, `kernelsnitch.mm_struct_sz = 960` (no imported
  layer).
- **Falsifier:** a copy of the same profile with `kernelsnitch.mm_struct_sz = 1024`, installed under
  `files/user_profiles/` and selected through `shared_prefs/ghostlock_prefs.xml`. The scan no longer
  reads this field; the value reaches only the spray sizing. The original prefs and profile list
  were restored after the gate.

## Result

- **Control `20261024-024717`:** `state=completed`, last marker `[+] KernelSU ready`; uptime delta
  84 s. Every attempt logged
  `[kernelsnitch] scan inner=32 outer=4096 ranges=14 source=banks canonical=1 tags=0`.
  Leak lines: `[spray] mm_struct leaked=0xffffff897631a940 +4044ms` on the first attempt, then
  0.9–2.2 s on later attempts (14 RAM-bank ranges, 8 CPUs).
- **Falsifier `20261024-025437`:** identical scan line; `[spray] mm_struct
  leaked=0xffffff8933528000 +3493ms`. The run reached `heap spray done`, W1–W3, then failed at
  `SYSCHK(sched_setaffinity(0, sizeof(cpu_set_t), &cpuset)): Invalid argument` during a later
  stage, run-store `state=failed`, `native exited code=255` (uptime delta 61 s). That is the known
  `core_ctl`/CPU-active pin class, not the scan.

## Interpretation

- The leak is independent of the profile stride: both the 960 and 1024 profiles found the mm under
  the S=32 / 4 KiB / bank-filtered grid.
- The falsifier's later failure is the documented pin class. The wrong spray value did not stop the
  leak or W1–W3; whether it changes the completion rate is not measurable from one run.
- The plan's pre-registered 5/5 per cell was not run; this gate establishes the scan change and the
  stride independence. A 5/5 series (with `cpu-active-hold.sh`) remains optional before merging.

## Evidence

`external/port/kn-stride/control-1/run-1/` and `external/port/kn-stride/falsifier-2/run-1/`
(`stream.log`, `dmesg-tail.txt`, `kmsg-polled.txt`, `summary.txt`). The device was left with the
original `shared_prefs` and user-profile list; the gate profile was removed.
