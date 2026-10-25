# vr.ko task-tag clear v3 — user-authoritative, version-assisted (2026-10-25, revised)

Status: **implemented on `experiment/vr-ko` (2026-10-25, v3); host gates pass and the diting smoke
passed.** L-level: W2 attack-path change plus a Native↔Kotlin contract (UI preferences passed to
the native). **No profile-schema change.** The file keeps its historical name for citation
stability; the feature is the task-tag clear, not a general vr.ko countermeasure.

**Scope, stated narrowly.** This option writes two task words so the module's `sys_exit` probe
does not kill the rooted child. It does **not** disable, unload, patch or otherwise neutralize
vr.ko: the module's hooks, mounts, dumps and SELinux write path continue to run. The companion
option — the SELinux enforce-write block — is separately scoped in `module-disarm-plan.md` and
also stops only the `/proc/vrp` 0/1 write.

Superseded drafts:

1. a module-binary classifier with `execution.vr_ko.{mode,tag_b_offset}` in the profile — dropped:
   the 6.x generation is out of scope and the choice belongs to the user, not to profile
   generation;
2. v2's hard `kernel_major >= 6` gate — dropped 2026-10-25 on operator direction: **no
   version-only gate**. Every vr.ko behaviour that changes device state is a UI option; a version
   check (or a runtime probe) may only produce the *recommendation* that **Auto** resolves to, and
   the user's **On/Off** is final.

## What the evidence fixes

`external/github_error_reports/5.10.246-gki-g3e27bf130358/2026-10-25-vr-ko-analysis.md`:

- The reporter's 5.10.246 module is the **legacy generation**: no `commit_creds`/`sys_exit`
  hooks, no per-task tags at `task+0x6`/`task+0x2c`, no panic/signal path. Its hooks are a
  `module_memfree`/`vfree` kprobe and the `initcall_finish` tracepoint; the rest is mount/integrity
  and dump machinery.
- The fork's tag clears are therefore unnecessary on 5.10, and the tag-B write (8 bytes at
  `task+0x28` = `thread_info.scs_sp`, `CONFIG_PANIC_ON_OOPS=y`) is the leading explanation for
  the anchored runs' W2 stop.
- The newer 6.x module (research sample) does use byte tags at `task+0x6`/`task+0x2c` and a
  `sys_exit` probe; there the existing clears are the accepted countermeasure.

## Design

### 0. The rule

The native never overrides the user with a version check. Each vr.ko behaviour that changes
device state is a setting with three values:

| value | meaning |
|---|---|
| **Auto** | resolve the *recommendation* at run time (version + probe) and do that |
| **On** | force the action, whatever the recommendation or probe says |
| **Off** | never perform the action |

A version check or a runtime probe is only a **recommendation input**; it is shown in the UI and
recorded in the run log, but **On/Off is absolute**.

### 1. The options

| option | preference / env | values | default | UI |
|---|---|---|---|---|
| Task-tag clear (W2b) | `vr_ko_tag_clear` / `GHOSTLOCK_VRKO_TAG_CLEAR` | `auto`, `on`, `off` | `auto` | compact spinner row, home control card |
| SELinux enforce block (root script) | `vrko_selinux_block` / `GHOSTLOCK_VRKO_SELINUX_BLOCK` | `auto`, `on`, `off` | `auto` | compact spinner row, home control card |

The second option is defined in `module-disarm-plan.md`; the two share the same tri-state
semantics and the same UI pattern. The file names keep "countermeasure"/"disarm" as historical
identifiers; the user-facing names and log lines state only the actual effect.

The probe and the module capture are **diagnostics, not options**: the probe is a read of
`/proc/modules`, and the capture only copies the detected module into the run folder for export.
Neither changes device state, so neither gets a switch. (If exporting the vendor binary becomes
unwanted, that is a separate opt-out, not a countermeasure choice.)

### 2. Auto resolutions

**Tags:** `recommended = probe_needed && kernel_major >= 6`.

- `probe_needed` is `vr.needed`: a `vr`-prefixed module in `/proc/modules`. Unreadable
  `/proc/modules` keeps the existing "assume loaded" semantics, so Auto on an unreadable 6.x stays
  on; the preceding `vr.ko probe:` line records `readable=0` so the assumption is visible.
- `kernel_major == 0` (no profile) resolves as "not >= 6", i.e. Auto off.

**SELinux enforce block:** `recommended = /proc/vrp present && uname -r starts with 5.10.198`.

- `5.10.198` is the only generation that builds the `0/1 → enforce` path. The 5.10.246 module
  shares `/proc/vrp` but accepts only the ≥ 64 KiB policy form, and the 6.6 module has no
  `/sys/fs` paths at all, so Auto stays **off** on both. Only an explicit **On** reaches them.
- Keying on the kernel release is a heuristic, not a guarantee: a 198-generation module on a
  non-198 kernel is not auto-detected, and a 198 kernel carrying a different generation is
  auto-included. Both are exactly why On/Off exists.
- A behavioural probe ("write the current enforce value and see whether it returns 0 or EINVAL")
  would be stronger, but it is not safe across generations: the 6.6 `/proc/vrp` is a different
  interface, and a test write there can trigger an unknown action. Auto therefore stays
  version-keyed and conservative; On is the escape hatch.

### 3. Effective decision and log

**Task-tag clear (native, W2b):**

```
vr.ko tag clear: mode=<auto|on|off> recommended=<0|1> effective=<0|1> kernel_major=<n> probe=<0|1> reason=<...>
```

`reason` ∈ `auto-recommended`, `auto-no-module`, `auto-kernel-major`, `user-on`, `user-off`.
When `mode=on` and `recommended=0`, one extra warning line states that the user forced the write
and restates the risk (5.x `scs_sp`, or no module detected). The two writes are unchanged:
the `thread_info.flags` word at `task+0x00` and the aligned tag-B word at `(task + 0x2c) & ~7`.

**SELinux enforce block (root script):** `vr.ko selinux block: mode=<...> recommended=<0|1>
effective=<0|1> kernel=<uname -r> node=<present|absent> reason=<...>`; when effective, the existing
pre-log, bind, coverage check, STOP fallback and post-log follow. Emission rules are in
`module-disarm-plan.md` §4.2.

### 4. UI

One **home-view entry** in the control card (with the Shizuku switch and the CPU-pair/safe-mode
controls), titled **vr.ko anti-root countermeasures**; its summary shows the two current modes
(`tags Auto · SELinux Auto`). It opens a dedicated **options screen** containing:

- **vr.ko task-tag clear** — Auto / On / Off, with a one-line summary. Auto clears only when a
  vr.ko module is detected on a 6.x kernel; on 5.x it says it skips and that forcing can panic.
- **vr.ko SELinux enforce block** — Auto / On / Off, with a one-line summary. Auto blocks only the
  `/proc/vrp` enforce write on 5.10.198; on other kernels it says there is nothing to block.
- A scope paragraph: the options only clear the per-task tags and block the `/proc/vrp` 0/1
  enforce write; the module itself stays active.

The detailed warnings (5.x `thread_info.scs_sp`, the exact words written, the mount/STOP fallback)
live in the run log and these docs. The UI cannot show the probe result before a run: the probe
reads `/proc/modules` inside the native at W2, so Auto is a run-time resolution.

### 5. The dangerous directions are allowed, and say so

- **Tags On on 5.x:** the 8-byte aligned write at `task+0x28` is `thread_info.scs_sp` on a
  5.10 `CONFIG_SHADOW_CALL_STACK` kernel; `panic_on_oops=1` turns the fault into a panic. The UI
  warns and the log records `user-on` with `recommended=0`.
- **Tags On with no module:** clears the whole `thread_info.flags` word (not only tag A) and the
  aligned tag-B word on a device the countermeasure was not written for. Logged the same way.
- **SELinux block On outside 5.10.198:** the script attempts the blocked-open and STOP steps on
  whatever `/proc/vrp` exists; `recommended=0` is logged and the home row says it is untested.

### 6. Shizuku entry

The Shizuku UserService AIDL has no field for either option, so that entry runs **Auto** for both
(the safe resolution). Honouring a forced On/Off there needs an AIDL field and a service-side
plumbing change; out of scope for this workstream and called out in the UI copy if the Shizuku
path is active on the device.

## Code map (as reworked)

| file | change |
|---|---|
| `src/core/session/runtime_config.{h,cpp}` | `vrko_tag_clear` as a three-value enum (`auto`/`on`/`off`; default auto), parsed from `GHOSTLOCK_VRKO_TAG_CLEAR` (`1`/`0` accepted as on/off for the old build) |
| `src/core/session/backend/cve_2026_43499_backend.cpp` | W2b: recommendation × mode → effective; refusals and user overrides logged; capture unchanged |
| `app/.../domain/model/GhostlockModels.kt`, `domain/repository/GhostlockRepository.kt` | `VrKoMode` fields + setters (replaces the booleans) |
| `app/.../data/AndroidGhostlockRepository.kt` | `auto|on|off` preferences (migrates the old boolean: `false` → off, anything else → auto), snapshot, `GHOSTLOCK_VRKO_TAG_CLEAR` / `GHOSTLOCK_VRKO_SELINUX_BLOCK` env (direct entry only) |
| `app/.../ui/{GhostlockUI,VrKoUI,GhostlockViewModel,MainActivity}.kt`, `res/values*/strings.xml` | the home entry, the options screen, their en/zh copy and the Auto summaries |
| `docs/analysis/vr-ko-countermeasure-plan.md` | this plan |

No schema, digest, golden, or native-document changes.

## Implementation status (2026-10-25)

- Branch `experiment/vr-ko`, cut from `document` @ `9c96125`; the work is in the worktree,
  uncommitted, for operator review. The v2 hard gate is gone (v2 remains only as the superseded
  draft above).
- Host gates: `make -C src ghostlock` zero warnings; `lint-tidy`; `native-host-tests` all targets
  pass, including the new `runtime_config_test`; Gradle 144 tests with only the known
  `ProfileMigrationEquivalenceTest` fixture failure; `assembleDebug` versionCode 653, final APK md5
  `0135dc7a…`, packaged native `1414f4f8…`. `tools/cmp_disasm.py` against the `document` native:
  every present route target has the same instruction count; the exit 1 is the known
  missing-`multicast_*` control failure (record: `external/port/vr-ko-smoke-2026-10-25/cmp_disasm.txt`).
- Device gate (diting 5.10.236, `external/port/vr-ko-smoke-2026-10-25/run-1g/`): Auto logged
  `vr.ko tag clear: mode=auto recommended=0 effective=0 kernel_major=5 probe=0
  reason=auto-no-module`, wrote no tag words, and the chain completed (`exploit complete` →
  `native exited code=0` → `KernelSU ready`). The home entry opens the options screen; its summary
  updates live. The host driver needed a one-swipe scroll because the added controls can push
  执行 below the fold on this screen.
- Still pending: the reporter's 5.10.246 (Auto should log `reason=auto-kernel-major`, no writes)
  and the 6.x vivo; the forced-On directions are not device-gated.

## Non-goals

- Module-binary fingerprinting or any per-build classification.
- Profile schema / `execution.vr_ko` fields.
- Any claim beyond task-tag clearing: the module is not disabled, unloaded, patched or hidden,
  and its other hooks, mounts, dumps and checks continue to run.
- Forcing tags on 5.x *by default*; the user can force it explicitly, nothing else can.
- Neutralizing vr.ko in memory or hiding the task by SID/comm.
- Shizuku-side option transport (that entry runs Auto).
