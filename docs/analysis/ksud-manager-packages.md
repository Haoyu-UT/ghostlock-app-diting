# KSU manager packages: BakaSU audit and KernelSU-Next support — 2026-11-06

## Question

Upstream commit `d66b64c6` ("feat(manager): add BakaSU support (#415)") adds a fourth/fifth root
manager to the `ksud` provisioning. Our `document` line carries the shell half of BakaSU but not
the rest. The second question: can the same mechanism support **KernelSU-Next**
(`KernelSU-Next/KernelSU-Next`)?

## What upstream `d66b64c6` changes

Three sites, plus the README:

1. `app/src/main/AndroidManifest.xml` — `<queries>` package `org.bakasu.bakasu`.
2. `AndroidGhostlockRepository.prepareKsud()` — the installed-manager list that copies
   `nativeLibraryDir/libksud.so` to `filesDir/ksud`.
3. `src/core/attack/ops.cpp` — the root script's `/data/app` `libksud.so` fallback chain.

Our tree already had (3) from `44fe05f8` (the clean-line protocol adoption brought the BakaSU
path), but not (1) or (2). So on a BakaSU-only device the primary `prepareKsud` path missed and
only the root-script `find` recovered. This change completes it, matching upstream.

## KernelSU-Next: measured compatibility

| fact | evidence |
|---|---|
| manager package id | `com.rifsxd.ksunext` — `aapt2 dump badging` of the v3.4.2 release APK (`KernelSU_Next_v3.4.2_33355-release.apk`, versionCode 33355) |
| it ships a `ksud` | `lib/arm64-v8a/libksud.so`, 7,059,584 bytes, in that APK; its manager build sets `useLegacyPackaging = true`, so `ApplicationInfo.nativeLibraryDir/libksud.so` exists after install — exactly what `prepareKsud` copies |
| `ksud late-load` exists | tag `v3.4.2`, `userspace/ksud/src/cli.rs` — `LateLoad { allow_shell, kmi, package_name }` |
| call shape matches ours | `--package-name` defaults to `com.rifsxd.ksunext` (so our call needs no package argument); `late_load.rs` loads `{kmi}_kernelsu.ko` embedded in ksud with `allow_shell=1` |
| KMI spelling matches | our script builds `KMI="${AVER}-${KVER}"` from `uname -r` (e.g. `android12-5.10`); that is the exact `{kmi}_kernelsu.ko` naming. The v3.4.2 release ships modules `android12-5.10` … `android17-6.18` |
| vermagic is adapted at load | `userspace/ksuinit/src/lib.rs` (v3.4.2) extracts the kernel-required vermagic from the load error and rewrites the embedded module's `vermagic=` before `init_module`, so the `5.10.252-dirty`-built ko loads on another 5.10 GKI |
| module name is `kernelsu` | `name=kernelsu` in the released `aarch64_android12-5.10_kernelsu.ko`, so the handoff probe's `/proc/modules` check sees it |
| late-load is a supported mode | the loader comment: "bundled flag is meaningless in jailbreak mode since we can't flash boot to update it" |

Our root script calls `"$KSUD" late-load --kmi "$KMI" --allow-shell`, which is precisely the
v3.4.2 CLI contract. No script change beyond finding the binary is needed.

## Change

Package order is identical in the Kotlin list and the shell fallback (so the primary and fallback
paths agree):

```
me.weishu.kernelsu.pr
me.weishu.kernelsu
com.rifsxd.ksunext        <- new
com.resukisu.resukisu
org.bakasu.bakasu         <- manifest + Kotlin now match the shell path
com.kowx712.supermanager
/data/local/tmp/ksud
/data/adb/ksu/bin/ksud
```

`prepareKsud`'s failure log now names KernelSU-Next and BakaSU.

## Gates

- `make -C src ghostlock`: zero warnings; `make -C src lint-tidy`: rc=0 (43 warnings suppressed in
  non-user code); `make -C src native-host-tests`: all pass.
- `tools/cmp_disasm.py` (pre-change native vs new): every target has the **same instruction count**
  (`owner_thread` 69, `waiter_thread` 278, `consumer_thread` 187, `run_main_route_threads` 417,
  `do_kernel5_fake_lock_route` 386, `do_one_write` 180); the FAIL is the documented
  baseline-vs-itself control (`multicast_*` absent from both).
- `:app:assembleDebug` + `:app:testDebugUnitTest`: pass (188 tests).
- Packaged checks: the APK manifest `<queries>` carries all six packages; the arm64 native carries
  `com.rifsxd.ksunext` and `org.bakasu.bakasu` in the root script.

## Limits

- **Not device-tested.** No phone with a KernelSU-Next manager was available. The invocation and
  the embedded KMI module make it the same late-load path as KernelSU/ReSukiSU, but a device run
  is the gate. A KernelSU-Next v3.4.2+ device whose `uname -r` KMI is in their release set
  (`android12-5.10`, `android13-5.15`, `android14-5.15`, `android14-6.1`, `android15-6.6`,
  `android16-6.12`, `android17-6.18`) is the right test.
- The loaded module is the installed manager's own, so the manager's userspace matches it by
  construction.

## Implemented in the app (2026-11-06)

- `data/ManagerScanner.kt` runs the pipeline: enumerate user apps plus the built-in managers
  (system-installed builtins included), keep executable-shaped aarch64 ELFs (ET_DYN + PT_INTERP,
  or ET_EXEC), token-scan those (`late-load`, `allow_shell`/`--allow-shell`, `KSULKM1`,
  `ksu_bootstrap`, `kernelsu.ko`, `KernelSU`), then probe `--version` and, for ksud, 
  `late-load --help` requiring `--allow-shell` and `--kmi`. A probe that cannot run (SELinux,
  timeout) leaves `identity`/`interfaceOk` null and suitability falls back to the static tokens.
- `AndroidGhostlockRepository.stageKsud()` scans at every run start, logs all candidates and the
  chosen one, stages it to `filesDir/ksud`, and returns false when nothing suitable exists;
  `runExploitBinary` then returns before starting the native. The Shizuku UserService performs the
  same scan as shell (the app passes the selected package through the AIDL) and refuses the same way.
- Advanced → Root manager lists the suitable candidates (plain labels) and an Auto row; the choice is a preference
  in `ghostlock_prefs` (`manager_package`). There is no persistent scan cache: every open and every
  run re-scans (~0.2 s warm / ~0.5 s cold on myron; PoC record in
  `external/port/ksud-judge-poc-2026-11-06/`).
- `QUERY_ALL_PACKAGES` is declared so the scan can see arbitrary managers. That is a
  Play-policy-restricted permission; the app is sideloaded.
- Tests: `ManagerScannerTest` (suitability/resolve) and `ManagerScannerScanTest` (enumeration,
  self/system filters, tokens, probe-unavailable fallback).

## PORT-PLAN closure (2026-11-07)

The PORT-PLAN item "Find the root helper automatically (`ManagerScanner`, upstream/main `d2ab286e`)"
is closed. It is implemented as above — with a capability probe, the user picker, the run-start
refusal and the Shizuku parity, which upstream's version does not have. Device check on the K90 Pro
Max (`myron`): the Advanced → root管理器 picker lists SukiSU Ultra v4.2.1 as a confirmed late-load
candidate, the selection persists, and Auto restores. The run-start layout is device-verified on the diting as well (run
`20261107-001936`: ReSukiSU confirmed and selected, staged copy used, `exploit complete` →
`KernelSU ready`, `state=completed`). The no-suitable refusal is device-verified too (2026-11-07,
diting: ReSukiSU uninstalled → picker notice, scan `1 candidate(s), 0 suitable`, `state=failed`
with `refusing to start the exploit`, no native; reinstalled → `state=completed`; record in
`external/port/ksud-no-suitable-2026-11-07/`). The Shizuku service path remains code-reviewed
(Shizuku not running on either test phone).
