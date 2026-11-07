# Native exits → UI prompts — audit (2026-11-07)

**Question.** The 2026-11-07 xaga report on kernel `5.10.198-android12-9-00085-g226a9632f13d-ab11136126`
had six runs on one boot end with `native exited code=255`; the only explanation was a red line
inside the log sheet. Which native exits have the same problem — a failure with no visible,
actionable UI prompt?

**Answer, split by when the app can know.**

- **Class 1 — determinable before the run starts.** The app already holds everything needed to
  predict that the native will refuse (boot state, the state file, the profile, the device's
  clocks). A run must not be spent: gate the button and say what to fix. Today only four such
  gates exist (no profile, Shizuku not ready, invalid fields, unsupported kernel); they are
  profile/Shizuku checks. **The entire anchor/boot-state family — the reported failure — is
  class 1 and is not gated.**
- **Class 2 — known pattern after the run.** The run must be attempted; only its outcome (exit
  code + a signature line, or the run store) tells what happened. The app should map the known
  patterns to a prompt. Today **none** is mapped: every non-zero exit becomes
  `result: exploit failed (exit code=N)` in the log, and the only guided prompt is a next-launch
  notice driven by a stuck step.

## 1. How the app learns a run ended

| channel | what it carries | where |
|---|---|---|
| exit code | `process.exitValue()`; `-1` when the app kills it after the 300 s timeout | `AndroidGhostlockRepository.kt:1694`; timeout at `:1646` |
| native stdout/stderr | every native line, streamed into the log sheet and the run store | `AndroidGhostlockRepository.kt:1144`, `:1085` |
| status record | 7 steps (`w1a..w3c`), `in_progress`/`completed`, persisted by the app | `RunStateCodec.kt:13`; native emitter `src/core/support/run_state.cpp` |
| run store meta | `files/runs/<stamp>/meta`: `running` → `completed`/`failed`/`interrupted` | `RunLogStore.kt:90–100`, `AndroidGhostlockRepository.kt:911` |

The status record is the only structured channel. It is also the precedent for the structured
terminal record in §7.2.

## 2. What the UI shows today

| moment | visible signal | actionable? |
|---|---|---|
| run button blocked | toast: no profile / Shizuku not ready / invalid fields (an unsupported kernel lands on the first) | yes — takes the user to the fix |
| during a run | log sheet (auto-opens, not dismissible) | — |
| run ends, code 0 | log: `result: exploit completed` | — |
| **run ends, code ≠ 0** | **log: `result: exploit failed (exit code=N)` + `exit code=N`** | **no** |
| next app launch, a step left `in_progress` | dialog: "Previous run interrupted … check the device and try again — or export the log" (W3: Shizuku hint) | partially |
| next app launch, nothing stuck | nothing | — |

References: `GhostlockViewModel.kt:1102–1103` (the two result lines), `:1048–1057` (the only
pre-run toasts), `:206–241` (the next-launch notice), `GhostlockUI.kt:545` (the sheet is a bare
`LogPanel`), `:1098` (run button gating), `:224` (the five dialog types).

The next-launch notice reads the **step file**, not the exit code: a fatal exit before `w1a`
(profile load, digest, runtime config) leaves every step `not_start` and produces no notice at all;
so does an exit after `w3c` completed.

## 3. Class 1 — the run will fail before it starts

**Rule.** Class 1 is a failure the app can decide *before launching the native*, from state it
already owns: the boot id, `files/.ghostlock_anchor`, `InstallClock`, the resolved profile and its
validators, and a CPU-affinity probe. The native's own refusals in this group are deterministic, so
a spent run buys nothing.

| # | condition (the native will refuse) | native site(s) | what the app can read before starting | status today |
|---|---|---|---|---|
| 1.1 | anchor state file missing/unusable **and** install postdates the boot | `lock_anchor.cpp:298` | `files/.ghostlock_anchor` + `/proc/sys/kernel/random/boot_id` + `InstallClock.installPredatesBoot()` | **device-verified 2026-11-07 (P5)** — the reported case |
| 1.2 | anchor slot budget spent this boot | `lock_anchor.cpp:382` | the state file's `next`/`slots` vs the profile's anchor grid | **device-verified 2026-11-07 (P5)** |
| 1.3 | state file's grid ≠ this profile's geometry | `lock_anchor.cpp:266` | stored slots vs `lock_anchor_bytes/stride` | **device-verified 2026-11-07 (P5)** |
| 1.4 | state file cannot be created / reservation cannot be written | `lock_anchor.cpp:282`, `:315` | write probe in `filesDir` | not wired |
| 1.5 | anchor geometry invalid (stride < rt_mutex, `bytes % stride != 0`, stride < 0x20) | `lock_anchor.cpp:94`, `:101` | `ProfileResolver.validateLayoutGroups` mirrors 94; `bytes % stride` is not checked | **partly blocked** |
| 1.6 | W1 scratch's collateral window leaves the anchor region | `lock_anchor.cpp:361` | `ProfileResolver.validateStage1Blocks` | **blocked today** |
| 1.7 | W1 scratch has no direct-map alias | `support/util.cpp:495` | compute the alias from `kernel_phys_load/offset` + the scratch image offset (same formula) | not wired |
| 1.8 | page-free write has no value source | `support/util.cpp:1029` | page-free policy + `w1_scratch.image` presence | not wired (the plan flow may already imply it) |
| 1.9 | credential group invalid | `support/util.cpp:320`, `:335`, `:358`, `:364` | `ProfileResolver.validateLayoutGroups` covers copy/usage/uid/security/caps; `ref_count`/ref-offset bounds are **not** mirrored | **mostly blocked** |
| 1.10 | sigreturn geometry unusable | `sigreturn_route.cpp:489` | the same offsets the native checks | not wired |
| 1.11 | profile release ≠ running kernel | `attack/ops.cpp:86`, `:92` | `kernelSupported` + profile resolution by exact `uname -r` | **blocked today** |
| 1.12 | no profile / invalid profile / unsupported kernel / Shizuku not ready | — | existing gates | **blocked today** |
| 1.13 | the chosen CPU pair refuses `sched_setaffinity` (core_ctl / cpuset) | `SYSCHK(sched_setaffinity)` → `pin_to_core`, `utils.h:144` | probe the pair on a throwaway thread before starting | gate implemented 2026-11-07 (P6, best-effort) |
| 1.14 | no late-load-capable root manager (`ksud`) | not a native exit: `stageKsud` returns 1 before the native (`AndroidGhostlockRepository.kt:1607`); the Shizuku service refuses at `GhostlockUserService.kt:64–67` | the same `ManagerScanner.scan()`/`resolve()` the Advanced picker runs | **gate implemented 2026-11-07 (P7)**; the picker's empty state is now a toast |

Notes:

- What the app gates today: profile presence / Shizuku / unsupported kernel (1.11/1.12) and the
  profile validators (1.5 partially, 1.6, 1.9 mostly). What it does not: 1.1–1.4, 1.7, 1.8, 1.10,
  1.13, and 1.14's run path.
- The manager warning **already exists as a dialog** — `manager_picker_title` + `manager_picker_empty`
  in a `DialogType.NOTICE` (`GhostlockViewModel.kt:1217–1229`) — but only when the user opens
  Advanced → root manager. The Run path never calls it: `stageKsud` logs
  `<k> error: no suitable ksud found; refusing to start the exploit` and returns 1, and the run
  store has already opened, so the refusal is recorded as a failed run with no native start.
- The **anchor boot-state family (1.1–1.4) is the reported failure** and is fully determinable
  offline — the state file plus the boot id plus `InstallClock` answer it exactly as the native
  does.
- Keeping the native's refusal for every one of these is still correct; the app gate is an
  optimization and a better message, not a replacement.
- A class-1 item that slips through (file changed between the check and the run, I/O failure)
  falls back to its class-2 signature — keep both.

## 4. Class 2 — known pattern after the run

**Rule.** Class 2 can only be observed *after* an attempted run. Each known pattern is a pair of
(exit code, signature line / run-store state); the app maps it to one prompt. Prose matching is
brittle and localized — the durable form is the structured terminal record in §7.2 — but the
pattern set is small and already stable in the logs.

| # | signature | native site(s) / origin | meaning | prompt / action |
|---|---|---|---|---|
| 2.1 | exit **70** + `terminal dirty race: <reason> errno=N` | `support/util.cpp:51` (`fail_stop_dirty_race`) | PI state dirty; the process deliberately stopped without unwinding | **reboot before any retry**; block Run until a new boot id |
| 2.2 | exit 255 + `anchor slot state …` / `anchor slot budget …` | `lock_anchor.cpp:266/282/298/315/382` | a class-1 miss | reboot, then run |
| 2.3 | exit 255 + `SYSCHK(sched_setaffinity…)` / `sched_setattr(` / `waiter lock chain` / `owner lock target` / `pthread_create` | `utils.h:144`, `util.cpp:297`, `threads.cpp:25/80`, `kernelsnitch.h:163/166` | device/CPU environment | switch CPU pair, or reboot |
| 2.4 | exit 255 + `w2 never rooted a child` | `root_child_frontend.cpp:49` | probabilistic W2 cred miss across all chain rounds | retry |
| 2.5 | exit 255 + `credential copy profile` / `anchor geometry` / `sigreturn geometry` / `page-free write has no value source` / `digest mismatch` / `cannot load profile` / `unsupported component selection` | `util.cpp:320/335/358/364/495/1029`, `lock_anchor.cpp:94/101/361`, `sigreturn_route.cpp:489`, `main.cpp:101/107/162/173` | profile or build is wrong | do not blind-retry; export and report |
| 2.6 | exit 255 + `pselect consumer still inflight` | `select_stack_route.cpp:814` | dirty route | reboot |
| 2.7 | exit **1** + stage lines (`+0x188`, `clean but the write did not verify`, `perf leak did not reproduce`, no route line) | normal chain failure | transient race miss | retry; export if it repeats |
| 2.8 | exit **137** | Android phantom-process trimmer (untracked native child) | system kill, not the exploit | device setting hint (device-specific), retry |
| 2.9 | exit **-1** | `runProcess` 300 s timeout (`AndroidGhostlockRepository.kt:1694`) | the app killed it; outcome unknown | check device, export |
| 2.10 | exit 139 / 134 / 143, or `native exited` missing | crash / external kill | unknown failure | export and report |
| 2.11 | exit 0 + `KernelSU already has root; skipping exploit` | backend `run_setup` | nothing was done (objective already met) | say "already rooted / skipped", not "completed" |
| 2.12 | exit 0 (normal) | — | completed | completed — with the caveat that exit 0 is not evidence by itself (§6 gap 8; the port project's "evidence-only run success" item) |
| 2.13 | run store `state=interrupted` (no terminal write) | device died mid-run | kernel panic / reset | existing next-launch notice (already implemented, generic) |
| 2.14 | no `[!]` line at all | `FatalError` paths (`ops.cpp:70/82/102`, `main.cpp:181`) | internal | export and report; the structured record makes this unambiguous |

Notes:

- The status record already gives the step for 2.4/2.6/2.7; combining it with the signature makes
  the prompt specific ("W2 missed; retry" vs "route dirty; reboot").
- 2.3's `SYSCHK(sched_setaffinity...)` and 1.13 are the same failure seen from both sides: the
  probe makes it class 1, the pattern is the fallback.
- The native's `pr_error` is "log and abort" (`utils.h:117–120`), so every pattern in this table
  can appear from any thread and still ends the process; the exit code is the only machine-readable
  half.

## 5. Residual — neither class (internal, programming, or unreachable)

| group | sites | why neither |
|---|---|---|
| CLI misuse | `main.cpp:67/74/78/94` | unreachable from the app |
| internal I/O / parse | `kernelsnitch/utils.h:187/223/230` | programming/IO error, no user state |
| unexpected syscall failures | `SYSCHK(...)` (44 sites) | internal; only `sched_setaffinity` is user-relevant (2.3/1.13) |
| armv7 compat carrier | `compat_carrier.cpp` (7 sites, one exits 70) | route not shipped on supported devices |
| anchor geometry changed mid-process | `lock_anchor.cpp:214` | one profile per process; internal invariant |

These still end the run with `pr_error`'s 255 and no prompt; the generic class-2 fallback (2.5/2.14)
covers them as "export and report".

## 6. Gaps, by class

**Class 1**

1. The anchor boot-state family (1.1–1.4) is determinable and **not gated** — six wasted runs in
   the 2026-11-07 report; the same refusal has been on record since 2026-10-22 (vivo PD2354) and in
   the 2026-10 phase8 runs.
2. The app's validators cover some but not all native checks: `bytes % stride`, `ref_count`/ref
   offsets, `sigreturn` geometry, the W1 scratch alias, and the page-free value source are only
   found after starting (1.5/1.7/1.8/1.9/1.10).
3. No CPU-pair probe (1.13) even though the pair selector exists and the class costs runs.
4. The no-manager gate (1.14) has a warning dialog already but it is picker-only: Run still opens
   the run store and records a failed run before the native is refused.

**Class 2**

4. **No pattern is mapped at all** — all of §4 collapses to `result: exploit failed (exit code=N)`.
5. **The dirty-race exit (70) is a safety stop that is not enforced**: nothing records "must
   reboot", nothing blocks the next tap, although the process exits without unwinding for exactly
   that reason.
6. The next-launch notice is narrow: start-up only, step-driven (pre-`w1a` and post-`w3c` exits are
   invisible), generic text, no class.
7. `137` and `-1` print as bare numbers; the phantom-trimmer lever is device-specific but real
   (40 % of runs on the 6.1 POCO, ~2/170 on the diting).
8. The success side is exit-code-only too (2.11/2.12): `DiagnosticStop` prints `exploit completed`.
9. The Shizuku path returns the same Int to the same UI (`GhostlockUserService.kt:146`) — every gap
   above applies there as well.

## 7. Recommended shape

### 7.1 Class 1 gates (app-only; no native change, checked before the native starts)

1. **Anchor pre-flight** — replicate the native's decision from `files/.ghostlock_anchor`,
   `/proc/sys/kernel/random/boot_id`, `InstallClock.installPredatesBoot()` and the profile's anchor
   geometry. If the native would refuse (`missing/unusable`, `budget spent`, `grid mismatch`),
   block Run with "需要重启手机后再运行" / "Reboot the phone, then run" (and, for the fresh-install
   case, say why: "this install postdates the current boot"). Do not start the native.
2. **CPU-pair probe** — attempt the pair's `sched_setaffinity` on a throwaway thread; on failure
   offer the pair selector instead of a run.
3. **Manager pre-flight** — run the same `ManagerScanner.scan()`/`resolve()` **before**
   `beginOperation()`; on no suitable candidate show the existing
   `manager_picker_title`/`manager_picker_empty` NOTICE and do not create a run entry. Hoist the
   scan so `stageKsud` reuses its result instead of scanning twice.
4. **Finish the validator mirror** — the cheap equalities (`bytes % stride`, ref bounds, sigreturn
   geometry) belong in `ProfileResolver`, so they render as red fields, not as a failed run.

**Reuse.** All of these (and the class-2 dialog later) are the **same `DialogType.NOTICE`
surface** the manager warning already uses (`GhostlockViewModel.kt:1217–1229`): title + message,
one dismiss, no confirm action, no log export (no run happened). Factor the repeated
`mutableState.update { copy(dialogVisible = true, dialogType = NOTICE, …) }` block into one
`showNotice(@StringRes title, @StringRes message)` helper so the manager warning, the anchor gate
and the future outcome dialog cannot drift in layout or dismissal behaviour. New strings are
needed only for the anchor messages (`manager_picker_empty` already exists and should be reused
verbatim for 1.14).

**Anchor pre-flight, concretely (class 1 #1/#2).** One decision function mirrors
`lock_anchor.cpp:232–302` and `:382`; the app reads four inputs and never guesses:

| input | source |
|---|---|
| current boot id | `/proc/sys/kernel/random/boot_id` (the file the native reads) |
| state text | `File(filesDir, ".ghostlock_anchor")` — `<boot-id> <next> <slots>\n` (`write_anchor_state`; `runtime_paths.h:51`) |
| slots | `route.<active>.lock_anchor_bytes / lock_anchor_stride` from the **same resolved document** the native will receive (`profileController.load`, not the raw bundle) |
| `anchor_trusted` | `InstallClock.installPredatesBoot()` — the same value passed as `GHOSTLOCK_ANCHOR_TRUSTED` (`AndroidGhostlockRepository.kt:1129`) |

The branch table (native → app verdict):

| native branch (`allocate_slot`) | app verdict | action |
|---|---|---|
| file parses, same boot, grid matches, `next < slots` | allow | — |
| file parses, **different** boot | allow (reboot already re-zeroed the region) | — |
| file parses, same boot, grid mismatch or `next > slots` | refuse — grid | reboot (class 1 #3, free) |
| no parsable file, `anchor_trusted` | allow (the native creates it at 0) | — |
| no parsable file, **not** trusted | **refuse — #1** | reboot |
| allocated and `next >= slots` | **refuse — #2** | reboot |
| route has no `lock_anchor_image` | not applicable | — |

Exit with a NOTICE dialog before `beginOperation()` (so no run store, no native spawn) in the
**direct** path, where the native's home is `filesDir` — the reported case. The **Shizuku** service
runs with home `/data/local/tmp/ghostlock-app` (`GhostlockUserService.kt:61,107`), outside the app
sandbox, so its gate belongs inside the service (it runs as shell and already receives
`anchorTrusted`) or defers to the class-2 mapping. The native keeps its own refusal as the
authority; the gate is advisory. Unit tests cover every row; the diting check seeds a foreign-boot
state file (allow), then removes the file and updates the APK after a boot (the report's exact
state → block), then a normal fresh boot (allow, run reaches W1).

### 7.1.1 Run-start orchestration — one ordered pre-flight

`runExploit()` calls one `preflight()` before `beginOperation()`; the **first failure wins**: it
shows the NOTICE dialog and returns, so no log sheet opens, no run-store entry is written and no
native starts. Order is cheap → expensive and fix-the-device-state before fix-the-app:

| # | check (pass condition) | evidence the app reads | failure message (zh / en) |
|---|---|---|---|
| P0 | internal invariants: native binary present, profile blob encodable, run dir writable | `nativeLibraryDir`, `nativeDocument`, `filesDir` | "安装不完整，请重新安装应用。" / "The installation is incomplete; reinstall the app." |
| P1 | a profile matches this exact `uname -r` | resolution / `kernelSupported` | existing `run_blocked_no_profile` |
| P1b | the device's physical layout is known (`kernel_phys_load/offset` present) | `devicePairMissing` | "本机固件的物理布局未知。请附加 vendor_boot/dtbo（联发科）或 xbl_config/uefi（高通）后重新解析。" / "The device's physical layout is unknown. Attach vendor_boot/dtbo (MediaTek) or xbl_config/uefi (Qualcomm) and re-parse." |
| P2 | the profile passes every validator, incl. the native mirrors (`bytes % stride`, cred ref bounds, sigreturn geometry, page-free value source) | `ProfileResolver` / `config.invalidPaths` | existing `profile_invalid`, plus the first path: "配置参数不合法：%1$s" / "Invalid profile field: %1$s" |
| P3 | page-free only: the W1 scratch has a direct-map alias | alias from `kernel_phys_load/offset` + scratch image | "W1 写值区域无法映射到内核直接映射区（物理布局与配置不一致）。请重新解析或重新生成配置。" / "The W1 scratch has no direct-map alias (physical layout mismatch). Re-parse or regenerate the profile." |
| P4 | Shizuku is ready (only when enabled) | `shizukuStatus` | existing `run_blocked_shizuku` |
| P5 | anchor slots usable (only when the route carries `lock_anchor_image`) — state file + boot id + `InstallClock` + grid (branch table above) | `files/.ghostlock_anchor`, `/proc/sys/kernel/random/boot_id` | see P5a–P5d below |
| P6 | the selected CPU pair accepts `sched_setaffinity` | probe on a throwaway thread | "所选 CPU 组合当前不可用（系统可能暂停了该核心）。请换一组 CPU，或重启手机后再试。" / "The selected CPU pair is currently unavailable (the system may have paused one of its cores). Choose another pair, or reboot and try again." |
| P7 | a late-load-capable root manager exists | `ManagerScanner.scan()` + `resolve()` | existing `manager_picker_empty` — **moved here from the picker**; the picker keeps listing/selection |

P5 messages:

| # | condition | message (zh / en) |
|---|---|---|
| P5a | no parsable state file, install postdates the boot | "本应用是在本次开机后安装或更新的，无法确认本次开机已用过的锚点槽位。请重启手机后再运行。" / "This app was installed or updated after this boot, so the anchor slots already used cannot be confirmed. Reboot the phone, then run." |
| P5b | `next >= slots` this boot | "本次开机的锚点槽位已用尽，继续运行可能破坏内核数据。请重启手机后再运行。" / "This boot's anchor slot budget is spent; continuing could corrupt kernel data. Reboot the phone, then run." |
| P5c | grid mismatch, or `next > slots` | "锚点状态文件与当前配置的槽位网格不一致。请重启手机后再运行。" / "The anchor state file does not match this profile's slot grid. Reboot the phone, then run." |
| P5d | state file cannot be written (optional probe) | "无法写入锚点状态文件。请检查存储空间或应用数据权限后重试。" / "Cannot write the anchor state file. Check free storage or app data permissions and try again." |

Notes:

- **P7 is the correction to the current UI**: `manager_picker_empty` is today displayed only from
  Advanced → root manager. At run start it becomes a blocker; the picker keeps its candidate list
  and selection role.
- P5 and P6 are best-effort: the app's own `sched_setaffinity` can differ from the native child's
  final cgroup (Android assigns the child), and the anchor file can change under a running native.
  Both keep their class-2 signatures as the authority.
- P7 is the expensive check (package enumeration + ELF probes); P5/P6 are file read / one syscall,
  so they come first and save the scan.
- Not in this list by nature: class-2 patterns (dirty race 70, chain failures, 137, timeout) and the
  success acceptance — they can only be known after a run.

**Implementation status (2026-11-07).** P5, P6 and P7 are implemented in the fork's working tree
(uncommitted): `AnchorSlotState.kt` (pure native mirror + 11 unit tests), `CpuPairProbe.kt`,
`domain/model/Preflight.kt`, `AndroidGhostlockRepository.preflight()` and the ViewModel gate
(`showNotice` helper; the picker's empty state is now a toast). P5/P6 run on the direct path only —
the Shizuku service owns them (its home is `/data/local/tmp/ghostlock-app`) — and P7 runs on both.
Gates: app tests 209/209, profile-core 56/56 (1 skipped), `:app:assembleDebug` → APK 696.
**Device gate passed (diting, 2026-11-07)**: a same-boot state file (32/128) was allowed and the
run completed; a missing state file with an install that postdates the boot was blocked with the
P5a NOTICE and no run-store entry or native; a fresh boot (trusted install, no state file) was
allowed and the native created the state at slot 0 (`reserved 0..7`). A 1-slot profile variant
consumed its slot naturally (`state … 1 1`) and the next tap was refused with the budget-spent
NOTICE and no run; a same-boot state file declaring another grid was refused with the
grid-mismatch NOTICE and no run. P7's block branch was exercised: with both late-load-capable
managers uninstalled (only `com.sukisu.ultra`, not suitable, remained) the run attempt showed the
`manager_picker_empty` NOTICE and created no run; reinstalling them restored the pass path. P6
passed on every tap; its block branch is **not** reachable by the cpuset injector: with the app
moved to `background`, the probe still read a restored (top-app) cgroup and passed, and the native
then hit the class-2 `SYSCHK(sched_setaffinity…)` failure later in the run — the probe cannot
predict a mid-run cgroup move, which is why the class-2 pattern stays the authority.

### 7.2 Class 2 mapping (after the run)

1. **Dirty-race latch** — persist a `must_reboot` flag when a run exits 70 (and for any future
   dirty-terminal class), and block Run until a new boot id is observed. This is the one post-run
   response that must survive an app restart and must not offer "retry".
2. **Outcome dialog** — one dialog after a non-zero exit, with the log export attached, driven by
   §4's table. The preferred source is a **structured terminal record** on the existing status
   channel — `\x1eGLK_RESULT class=<id> step=<id> errno=<n>` emitted immediately before every
   fatal exit — so the app does not parse prose. That is a Native↔Kotlin contract change (L-level
   under `AGENTS.md`), so it needs a short plan and operator approval; a prose-matching interim
   dialog does not.

### 7.3 Native hygiene (separate, non-UI)

`pr_error` is "log and abort", but several call sites are followed by `return false/0` and a caller
written to recover (`support/util.cpp:297` → the consumer's futex fallback in
`race/threads.cpp:145–155`; `sigreturn_route.cpp:397/489`; `compat_carrier.cpp:193/279/292/353`;
`support/util.cpp:320/335/358/364`). The `SYSCHK` comment at `utils.h:140` still says
"log-and-continue" while the macro is fatal. Decide per site: terminal (`pr_error`, drop the dead
return) or recoverable (`pr_warning` + return).

## 8. Evidence

- 2026-11-07 xaga report (kernel `5.10.198-android12-9-00085-g226a9632f13d-ab11136126`): six runs,
  one boot (`boot_ms` 14.23M…14.80M; boot instant 06:57:34.7 ± 0.4 s), all six refused at the
  lock-anchor check with 255; the log-only surface is the motivating case.
- A known-good run prints `[route] anchor slots: new boot, region zeroed again; starting at 0/128`
  immediately after the (normal) `CMP_REQUEUE_PI ret=-1 errno=35` line — e.g. the 2026-10-25
  select-route smoke series on the diting.
- The same anchor refusal, with the same "reboot the device and run again" text, is on record from
  2026-10-22 on a vivo PD2354 (install postdated the boot; exit 255 at the slot check, before any
  stamp) and in the 2026-10 phase8 runs — the class is not new; only the gates/prompts are missing.
- The reverse gap — exit 0 accepted as success without independent facts — is already a tracked
  item in the port project's plan ("evidence-only run success").

## 9. Open questions

- Should a class-2 failure *auto-export* the run log (save-as prompt) instead of only offering it in
  a dialog? The interrupted notice already offers export; the normal failure path does not.
- The run store meta records `failed` but not the exit code or class; storing them would let the
  next launch (and the run list) show the same prompt without prose matching.
- Should the class-1 gates also *pre-write* the anchor state file when they conclude it is safe
  (trusted, no file), so the native's first check never has to create it? It would remove the 1.4
  write-failure residue.
- The status record covers only the 7 attack steps; extending it to the pre-attack phases would let
  the next-launch notice cover the pre-`w1a` class-2 exits too.
