# Static route geometry for 5.10 GKI images

**Level:** L (extractor derivation path, and the route a generated profile selects).

**Status:** proposed 2026-10-20; extractor, app and per-field derivation implemented
2026-10-21 on `feat/extractor-5x-geometry`. The extractor is committed (`9c899d6`, based on
`document` @ `32b9ca8`): steps 1–3, 5, 6 and the sigreturn derivation. The app half is
committed (`4baee6b`): the two-pass ambiguity picker (design 9), the anchor line in the parse
log (design 7), the diting timing preset (design 8) and the persisted generation log/meta
(design 10). Step 4 is implemented but uncommitted: `init_task` and `copy_process` anchors
recover 13 of the 15 `task_struct` fields (`seccomp` and `atomic_flags` have no stable single
anchor), and `init_cred` gives the caps and reference offsets; per-field sources are logged
as `field_source` lines and copied into the app's generation meta. The 14-image
`structs_ondevice` test and the full integration test pass; the derivation values equal the
measured series on every image, and the derived credential equals the device-verified
5.10 block. Host tests: 64 extractor unit tests, 115 app unit tests with only the pre-existing
`ProfileMigrationEquivalenceTest` failure, and APK 641 built. The packaged ARM extractor was
run on the diting against the 236 image: the first pass exits 7 with both routes Feasible, and
`--route select_stack` / `--route sigreturn` both exit 0 with the expected geometry and anchor;
the outputs match the host ground truths except `kernel_phys_offset`, which the device fills
from its own `/proc/iomem`. QEMU regression re-run 2026-10-22 with the new binary: the
generated profiles for 43/81/101 (three builds)/136 (two)/177/198/246 are **ten-exact**
against their runtime dumps, the 246 profile is byte-identical to the independently recreated
ground truth, and the approved A-mechanism anchor (`+0x2ec7bd8`) is exact; anchors are exact
wherever the dump carries `dump_skip.zeroes` (the older dumps do not). The `nf_logger` no-BTF
path is done (2026-10-23): `type` is the second field at offset **8** (the older plan's
constant 0 was wrong), the enum constants are ULOG=1/MAX=2/NFPROTO_UNSPEC=0, and the profile
anchor remains the measured `loggers+0x10` (not the ULOG slot at +8). All 14 images derive it
and match their profiles. The custom LTO/`-Os` 5.10.236 image closes only 6 `task_struct`
fields (its `copy_process` patterns differ); the series template fills the rest, so its
profile is still correct. Remaining: the `seccomp`/`atomic_flags`/`page`/`slab`/`mm_struct`
fields, the BTF-hidden field-layout diff (QEMU cannot supply field names; blocked on a
BTF-bearing 5.10 image), the UI end-to-end picker run, and the release.

**Revision 2026-10-20:** the series predicate is the embedded-IKCONFIG fingerprint; the
patch-precise range is the lowest-priority source, used only when IKCONFIG is absent or
unparseable, and every value taken from a heuristic tier is recorded in the generation log.

**Revision 2026-10-21:** sigreturn offsets are derived per image (the `rt_sigreturn` fpsimd
copy chain plus the futex strip home), not carried as family constants. On the diting 5.10
line this makes 136+ have two Feasible routes (`select_stack` and `sigreturn`), so the
ambiguity picker is a real path; 43/81/101 get a derived `sigreturn` instead of a frame-rule
guess; 246's sigreturn is Infeasible (its strip home is below the copy destination). The
family constants remain only as a labelled fallback when the derivation fails.

## Question

Can the extractor produce a runnable candidate for a 5.10 GKI image that has **no BTF** and a
`-gki-` release string — choosing the route from that image's own stack geometry and deriving the
shared struct/cred values from the image, rather than carrying a family constant measured on
another build?

## Why the route must be decided at generation

The app runs

```
libextract.so <image> [sidecars] --format conf --anchor --out <cache> --feasible-out <report> --work-dir <filesDir>
```

and stores the document as generated. The route in that document is the extractor's decision — the
only app-supplied `--route` is the user's pick from the ambiguous set (design 9). The
profile editor's Route selector (`AndroidProfileConfigController.updateRoute`) can only replace it
with a branch whose fields are all `null` (`routeBranchTemplate`), for the user to fill by hand; it
does not re-derive geometry. A route the extractor did not derive cannot be corrected in the app;
the picker added below only chooses among candidates it did derive.

## Findings (image `5.10.246-gki-g3e27bf130358`, 2026-10-20)

- `boot.img` md5 `a8f6d0d7cb98194b6914c2f7c0c88d67`; kernel `Image` md5
  `f0d927287c652991895686b328e4b0bc` at offset 4096. The image, the boot image, both embedded
  configs and the r7/derived outputs are archived with the session; the archive's `meta.txt`
  carries the provenance.
- Embedded config: `# CONFIG_DEBUG_INFO_BTF is not set`; `CONFIG_LOCALVERSION="-gki"`.
- QEMU (`nokaslr`, `_text=0xffffffc008000000`, `_stext=0xffffffc008010000`): all ten `offset.*`
  **exact**; `/proc/slabinfo` reports `mm_struct` **960** and `cred_jar` **192**.
- The r7 extractor's output for this image: `multicast_waiter` with `task_offset`/`lock_offset`
  null, `task_struct.*`/`cred.*` null, `mm_struct_sz = 1024`, a partial route geometry.
- **The reported candidate is not this image's.** `reported.conf` carries the 5.10.209 cred refs
  (`-272688810400 / -272688810248 / -272688804984`), `mm_struct_sz = 1024` and null multicast
  task/lock. The 246 image's `init_cred` yields `-272685269312 / -272685269904 / -272685264480`
  (the Expected result below), so the reported file would point the credential at another build's
  addresses even if the app accepted it.
- `family::matches()` requires `-android12-9-`; this release says `-gki-`, so the entire 5.10
  template is skipped. That is the whole reason for the nulls and the 1024 default — not a
  generation failure (the conf is still written, exit 0).
- The two kernels' configs differ in 903 options, mostly drivers. Every layout-relevant option
  checked is **identical**: `SECCOMP(_FILTER)`, `CGROUPS`, `CGROUP_SCHED`, `FAIR_GROUP_SCHED`,
  `KEYS`, `AUDIT(SYSCALL)`, `PSI`, `SCHED_INFO`, `TASK_{DELAY,X}ACCT`, `TASKSTATS`, `IO_URING`,
  `FUTEX_PI`, `SECURITY`/`SELINUX`, `RT_MUTEXES` (`DEBUG_RT_MUTEXES` off), `PREEMPT(_RCU/COUNT)`,
  `SMP`, `MEMCG`, `BLK_CGROUP`, `CGROUP_BPF`, `BPF_SYSCALL`, `PERF_EVENTS`, `UPROBES`, `TRACING`,
  `STACKTRACE`, `CPUSETS`, `PREEMPT_NOTIFIERS`, `LOCKDEP`/`DEBUG_LOCK_ALLOC` (off),
  `DEBUG_MUTEXES`/`SPINLOCK` (off), `RANDSTRUCT` (absent), `KASAN_HW_TAGS`, `CFI_CLANG`,
  `SHADOW_CALL_STACK`, `HZ=250`, `ARM64_VA_BITS=39`. The one apparent difference,
  `CONFIG_SCHED_WALT=m` here vs absent on the diting, is not a layout difference: the vendor WALT
  code stores per-task state in `p->android_vendor_data1` (`include/linux/sched/walt.h`), not in a
  new `task_struct` field.
- **That option list is evidence, not a series test.** It is not exhaustive: `CONFIG_UCLAMP_TASK`
  is on in the diting's own `external/config.gz` and its `uclamp_req`/`uclamp` fields sit in
  `task_struct` before `sched_task_group`/`pi_lock` (off would shift every later template field by
  0x10), and `CONFIG_PREEMPT_RT` changes the `rt_mutex`/anchor shapes. Neither is on the list, so
  the series predicate must be a config fingerprint (with a patch-precise range only as the
  lowest-priority fallback), not a hand-picked option list and not the release suffix.
- **Route geometry is the value that does not port.** With the 5.10 waiter layout supplied
  (`pi_tree_entry = 0x18`; no `wake_state`), `derive_pselect_layout()` disassembles this image and
  computes:
  - pselect chain `0xa0 + 0x1c0 = 0x260`, fd_set buffer at `+0x50` → `pselect_word0 = -0x210`;
  - futex chain `0xe0 + 0xc0 + 0x1b0 = 0x350`, waiter at `+0x20` → `futex_waiter = -0x330`;
  - `delta = -0x120 = -288 bytes`.
  The futex waiter sits 0x120 bytes **below** the fd_set buffer; the copy can never reach it.
  `select_stack` is geometrically impossible on this image. The diting's `waiter_shift = -2`
  corresponds to `delta = 0` on frames `0x90 + 0x70 + 0x1a0`; the family constant is a property of
  that build's code, not of the 5.10 train.
- **Softening `family::matches()` alone is the wrong fix.** It makes `route_hint` pick
  `select_stack` (do_futex frame `0xc0 > 0x20`) and emits `waiter_shift = -2` plus an anchor at
  `dump_skip.zeroes +0x2ec7bd8`, 0x440 bytes, **verdict unsafe**. The app would accept that
  profile; the route would be wrong.
- The **multicast** derivation already runs on this image and is static:
  `waiter_off = 0x30` (`ip_setsockopt` copy depth 0x360 − futex depth 0x330). Supplying the 5.10
  waiter offsets (`task 0x30`, `lock 0x38`) yields a complete, zero-null candidate; the app's
  validator accepts it (`48 + 56 + 8 <= 264`). That arithmetic *is* the feasibility test — a
  successful `multicast_waiter_off()` is not one by itself.
- **Feasibility is a copy-window fact, and the diting is the control that proves it.** On the
  diting line `multicast_waiter` is also infeasible: on 5.10.236 its copy window ends **0x48**
  short of the waiter slot, and on 5.10.81 **0x98** short (both recorded in the bundled profiles;
  the 5.10.81 header calls sigreturn "the only delivery"). `multicast_waiter_off()` still returns a
  number in that case, so the window rule (`waiter_off + lock_offset + 8 <= buffer_size`) must be
  part of the extractor's verdict, not only the app's validator. The 5.10.246 image is the mirror
  case: `select_stack`'s waiter sits 0x120 below the fd_set buffer, and multicast is the only route
  whose copy window reaches the waiter.

## Generation log today

The extractor's stderr — route decision, family/BTF warnings, anchor verdict, missing fields — is
streamed by the app into the in-memory log sheet (`redirectErrorStream(true)` → `onLog` →
`appendLog`), and the sheet's copy action is the only way out. Nothing writes it to disk: the
run-log store (`RunLogStore`/`DebugAttackLog`) is opened only for exploit runs, and the log sheet is
process-local. The generated document is stored verbatim in the user-profile store, but the app's
exports re-render it (`UserProfileStore.exportHocon`, `persistSnapshot`, `renderResolved`), so
comments are dropped — the reported file lacks the extractor's own
`# GhostLock kernel profile:` header. A generation decision is lost when the app process ends.

## The four kinds of value

The 5.10 template currently treats all of them as one family constant. They must be separated:

| kind | examples | rule |
|---|---|---|
| per-image | ten `offset.*`, `cred.ref*_image`, `multicast_waiter.waiter_off`, `lock_anchor_image`, phys pair | derive/read from the image every time |
| train/config-stable | `task_struct.*`, `cred` field layout, `mm_struct_sz=960`, waiter `task/lock`, `compact_waiter` | derive per image where possible; the measured-series template fills only the remainder, only on an IKCONFIG fingerprint match; a patch-range match is the lowest-priority fallback, marks every value it fills `heuristic`, and is recorded in the log |
| codegen-specific | pselect `waiter_shift`, sigreturn `off_sve/plain`, anchor suitability | derive from the image; never carry across builds |
| device/runtime | `selected_cpus`, `route_wait_ms`, `setup_settle_us`, route timing | never emitted by the extractor; the app supplies the device pair and its tuning presets |

Source priority for every shared field: per-image derivation → template under an IKCONFIG
fingerprint match → template under a patch-range match (**heuristic**, logged) → family constant
(**heuristic**, logged) → null. A higher tier never loses to a lower one; a disagreement is logged
and reviewed. Every value taken below the fingerprint tier carries its source and a `heuristic`
flag in the generation log, so a profile is never a silent mix.

`SELECT_WAITER_SHIFT` belongs to the third row: it is the derivation's frozen result for the
diting's `delta = 0`, not a separate train constant.

## Design

1. **Series match, not suffix match — the series is the config, not the version.** The shared
   template is frozen data for fields that are not derived, so its scope must be the series that
   produced the measurement. The series is decided from the image itself, in priority order:

   - **the embedded IKCONFIG's layout fingerprint** — authoritative;
   - **a patch-precise range of the measured line** — the lowest-priority source, used only when
     IKCONFIG is absent or unparseable; every value it admits is marked `heuristic` in the
     generation log, with the range that matched;
   - the release suffix and `5.10.*` alone are not series sources: the suffix ignores the patch
     level (5.10.43 and 5.10.236 are different builds) and `-gki-` is `CONFIG_LOCALVERSION`, not
     a layout guard.

   A fingerprint mismatch is final: the template does not fill and the range must not override it.
   Outside the series the fields stay null and the log names the reason.
2. **Derive first; the template fills only the remainder, inside the measured series.** Attempt
   the per-field derivation before the template (the older plan's phases 2–3, plus its phase-1
   `nf_logger` path): the image-visible values first — `mm_struct_sz` from `proc_caches_init`'s
   `kmem_cache_create_usercopy("mm_struct", …)`, the `cred` layout from `init_cred`/`commit_creds`,
   the waiter `task`/`lock` anchors, the no-BTF `nf_logger` path — then the `task_struct` anchor
   table. A derived field wins over a template value, and the log records the source per field.
   `cred.ref*_image` continue to be read from `init_cred` (`family::cred_from_image`, already
   implemented). Only fields the derivation did not produce fall back to the measured-series
   template, and only under design 1's series match; `mm_struct_sz` falls back to 960 inside the
   series and 1024 only as the non-series seed. A template fill under a range-backed series and
   the 1024 seed are heuristic values: both are marked in the log.
3. **The pselect derivation runs without BTF.** Change `derive_pselect_layout` to take
   `Option<&Btf>` and use the 5.10 waiter layout when it is absent: `pi_tree_entry = 0x18`, and no
   `wake_state` (a 5.15/6.x field; on 5.10 its store cross-check does not apply). Call it from both
   the `--analysis` path and the `--format conf` path whenever disassembly is enabled.
4. **A negative or misaligned overlap is `Infeasible`, not a generic error.** Today
   `delta < 0` returns a plain error, so the family hint's `select_stack` survives and the conf
   can still be written with `-2`. It must set `pselect_infeasible` with the full numbers
   (`pselect_word0`, `futex_waiter`, `buffer`, `waiter_local`, `delta`) so the route selection
   falls back. The upper bound is derived from the route's own word table — `PSELECT_ROUTE_NFDS`
   (15 words per three-set window) and the compact waiter's last table word (12) — not the
   hardcoded `>3`: max `delta/8 = 4`, i.e. the documented emitted band `[-2, +2]`.
5. **Every route gets a verdict before any route is selected.** Derivation runs for every route
   that has one, independently of any heuristic:
   - `select_stack`: pselect/futex stack geometry — the fd_set threshold and `delta` in band;
   - `multicast_waiter`: the setsockopt/futex copy window, with the same arithmetic the app's
     validator applies: `waiter_off + lock_offset + 8 <= buffer_size`. A successful
     `multicast_waiter_off()` is not a feasibility proof — on the diting it returns a number while
     the window ends 0x48 (5.10.236) / 0x98 (5.10.81) short;
   - `sigreturn`: derive the fpsimd stamp geometry from the image — the
     `__arm64_sys_rt_sigreturn → restore_sigframe → restore_{sve_,}fpsimd_context`
     chain sums, each helper's copy destination (`sp+0x10` SVE / `sp+0x00` plain,
     located by the `mov w2, #0x200` + destination-register pair), the 0x200-byte
     copy size, and the futex strip home (`Σ_futex − waiter_local`, the same
     quantity `derive_pselect_layout` computes before its delta check). The route
     is Feasible iff both `off = copy_dst − strip_home` are positive, 8-aligned
     and `off + 0x58 <= 0x200`; a non-positive or over-window offset is
     **Infeasible**; a missing symbol, a non-unique copy marker or an unproven
     call chain is **Unknown**. Numbers: on 5.10.236 the strip home is 0x210 and
     the copy destinations are 0x300/0x310, giving 240/256; on 5.10.81/101 the
     strip home is 0x1c0, giving 320/336; on 5.10.246 the strip home is 0x330,
     below the copy destination, so sigreturn is Infeasible. This makes 136+
     ambiguous (`select_stack` + `sigreturn`) and gives 43/81/101 a derived
     sigreturn route rather than a frame-rule guess. The family constants
     (`0x150/0x140`) are used only when the derivation fails and the route is
     forced, labelled heuristic.
   - `tcp_zerocopy`: no 5.10 derivation, so **Unknown**.

   A derivation that *fails* (missing symbol, non-unique waiter, unproven threshold) is also
   **Unknown**, not **Infeasible**: the route is not proven impossible, but it is not proven
   reachable either. It is never auto-selected while another route is Feasible, and only the
   zero-Feasible fallback below (labelled) or `--route` may choose it.

   Each route is therefore **Feasible**, **Infeasible** or **Unknown**, with the numbers that
   decided it. Selection:
   - **exactly one Feasible** → emit it with the image-derived values; Unknown routes are not
     consulted;
   - **more than one Feasible** → do not choose. Report the feasible set and require an explicit
     choice (the CLI errors without `--route`; the app uses the two-pass picker in design 9). No
     build-history or version-number preference may break the tie;
   - **zero Feasible** → the `do_futex` frame rule may nominate a route, but only if that route is
     **Unknown** — never if it is Infeasible. It is the fallback of last resort, labelled as a
     heuristic; with the sigreturn derivation it no longer selects 43/81/101 (their sigreturn is
     Feasible), so it applies only when every route is Unknown or the derivation fails. If it
     nominates nothing, emit no route branch and report the reasons.

   The frame rule is therefore not a first discriminator: it cannot pre-empt the derivation of a
   route it did not guess, and it cannot override a proven-infeasible layout. `--route` forced by
   the user stays a hard error when the named route is Infeasible (exit 3); a forced Unknown route
   is emitted as the unverified candidate it is.

   The emitted values follow the verdict. A Feasible `select_stack` writes the derived
   `pselect_shift` (`layout.shift - 2`); the family `SELECT_WAITER_SHIFT` is used only for
   `sigreturn` and a zero-Feasible Unknown fallback. If the derived shift differs
   from the constant, the extractor logs both and the difference is a review signal — the constant
   is the derivation's frozen result for the diting's `delta = 0`, not a second measurement of this
   image. The log records the route-choice basis (`derivation`, `frame-rule-fallback` —
   heuristic, or `forced`) and marks a zero-Feasible fallback as heuristic.

   `--no-disasm` cannot bypass this. With `--format conf` it is a hard error unless `--route` is
   given: skipping the derivation must not silently promote the family constant to a route. The
   flag remains valid for `--analysis`/text/json, where it only suppresses the derivation and
   reports "not attempted".
6. **Multicast gets its waiter offsets from the 5.10 layout.** `multicast_waiter_field_offsets`
   falls back to `task = 0x30`, `lock = 0x38` when BTF is absent (the same numbers are already
   documented in `memory/payload_builder.h` for the 5.10 compact waiter). `waiter_off` stays
   image-derived (already). The fallback's source is recorded with the other per-field sources,
   and it is marked `heuristic` when the series is not fingerprint-confirmed.
7. **The anchor scan runs for the series and respects its verdict.** Run `--anchor` on the series
   match. Emit `safe` and `needs-review` — every existing diting and qemu-cross anchor is
   `needs-review` (a live read, no live write), so refusing it would remove the shipped anchors.
   Refuse `unsafe`: omit the triple and say why; the named `dump_skip.zeroes` preference must go
   through the same filter as the ranked path (today it bypasses it). The verdict and its reason
   are logged and surfaced in the app (profile/import view and generation log), so the user sees
   which anchor a profile carries. On the 5.10.246 image the scan yields
   `dump_skip.zeroes +0x2ec7bd8`, 0x440 bytes, **unsafe** — it must be omitted.
8. **The extractor does not emit execution tuning; the app owns it.** `selected_cpus`, the race
   knobs and the route timing are device/runtime values measured on the diting, not image
   properties. The conf renderer omits the `execution` block entirely (keys omitted, never `null`:
   the app's merge skips a null into an existing map, but a null inside a new route group survives
   and blocks `fillRouteExecutionDefaults`). The app fills it from `execution-tuning.conf`, the
   selected route's `execution-<route>.conf` and the device pair, with a diting/device preset so a
   generated diting-line profile keeps the measured 30/10000/5000 values rather than the common
   1000/50000/50000 defaults.
9. **The ambiguous case is a user choice, not a generator preference.** The app gets a two-pass
   extraction flow. The first pass runs with `--feasible-out <path>`; the extractor writes the
   per-route verdicts (route, verdict, numbers, chosen route) as JSON before exiting. If more than
   one route is **Feasible**, it exits **7**. `GhostlockRepository.parseSource` gains
   `route: String? = null`, and `ParseResult` gains `Ambiguous(routes, verdicts)`; the ViewModel
   reads the report, shows the route picker and calls the same use case again with the chosen
   route. Exit 3 stays "forced route Infeasible"; 0 is a complete profile. Exactly one Feasible is
   emitted without a prompt; Unknown routes never trigger the picker. The profile schema, the
   one-branch output and the layer policy are unchanged; the picker chooses which single profile
   is generated, it does not create a multi-route document.
10. **The generation log lives in app data, not in the config.** Wrap the extraction in the
    run-log writer (`RunLogStore`/`DebugAttackLog`, entry kind `parse`), so the extractor's stderr,
    the app's parse lines and a `meta` record (release, input hash, series basis — `ikconfig:<hash>`
    or `patch-range:<range>` or none — per-field sources, the fields whose values are heuristic,
    feasible routes with verdicts, the route-choice basis, chosen route, anchor verdict, state) are
    written to app-private, crash-safe storage. Extend the existing export
    flow (or add "Export generation log") to include that entry. The raw log is not appended to the
    profile config: the app's exporters re-render the document and drop comments, so a comment
    block would not reach the file users share. A short curated provenance header is deferred until
    the exporters can preserve or re-emit it.

## Changes by file

| file | change |
|---|---|
| `tools/extract_rs/src/family.rs` | replace the suffix predicate with the measured-series predicate: IKCONFIG layout fingerprint first; patch-precise range only as the lowest-priority fallback when the blob is absent, never overriding a mismatch; expose the series basis and the 5.10 waiter layout (`pi_tree_entry`, `task`, `lock`, no `wake_state`); keep the template as the fallback for underived fields |
| `tools/extract_rs/src/derive.rs` | `derive_pselect_layout(..., btf: Option<&Btf>)` with the 5.10 defaults; `delta < 0`/misalignment → `Infeasible` with the numbers; the shift bound is derived from `PSELECT_ROUTE_NFDS` and the waiter word table (max `delta/8 = 4`), not hardcoded; multicast field-offset fallback; `multicast_waiter_off` applies the copy-window rule (`waiter_off + lock_offset + 8 <= buffer_size`) and classifies a short window as `Infeasible`, not as a candidate; `derive_sigreturn_layout` (the `rt_sigreturn` chain sums, the helper copy destinations, the 0x200 copy and the futex strip home) with the same three-valued classification; the image-visible shared values (`mm_struct_sz` from `proc_caches_init`, the no-BTF `nf_logger` path, waiter `task`/`lock`) |
| `tools/extract_rs/src/structs.rs` (new) | `derive_task_struct`/`derive_cred_layout` per-field anchors (the older plan's phases 2–3); every field returns `Option`, and a miss stays null |
| `tools/extract_rs/src/symbols.rs` | when BTF is absent, `resolve_structs` merges derived → fingerprint-tier template → range-tier template (heuristic) → family constant (heuristic) → null, and records the source and heuristic flag of each field for the log |
| `tools/extract_rs/src/analysis.rs` | derive the pselect and sigreturn outcomes when BTF is absent; report the per-route verdicts; `suggest_route` consumes the verdict set rather than a pselect boolean |
| `tools/extract_rs/src/main.rs` | run the derivation whenever disasm is enabled; compute every route's verdict before selecting (design 5); a derivation failure is Unknown (never a constant-driven auto-selection); `--no-disasm --format conf` without `--route` is a hard error; the frame rule only in the zero-feasible fallback; `--feasible-out` writes the verdict JSON and exit 7 signals ambiguity (3 stays forced-infeasible); forced-route semantics; `--anchor` on the series match + verdict gate; the series basis, route-choice basis and heuristic flags are carried into the generation meta |
| `tools/extract_rs/src/report.rs` | `mm_struct_sz` fallback (960 inside the measured series, 1024 as the non-series seed — heuristic and logged); omit the `execution` block (device/runtime tuning is app-supplied); `conf_route_geometry` prefers the derived `pselect_shift` for a Feasible `select_stack` and the derived `off_sve`/`off_plain` for a Feasible `sigreturn`; the family constants remain only for a forced Unknown route; log both values when they differ |
| tests | unit tests for the predicate, the waiter layout, the no-BTF pselect and sigreturn derivations, `Infeasible` classification, multicast fallbacks and route selection; the exit-7/JSON contract; the eight-image integration test, which now expects ambiguity on 136+ |
| `app/…/domain/model/GhostlockModels.kt` | `ParseResult.Ambiguous(routes, verdicts)`; `RunLogEntry` gains the generation meta (release, input hash, verdicts, chosen route, anchor verdict) |
| `app/…/domain/repository/GhostlockRepository.kt` | `parseSource(..., route: String? = null)`; the result carries `Ambiguous` on exit 7 |
| `app/…/domain/usecase/GhostlockUseCases.kt` | `ParseSourceUseCase` passes `route` through |
| `app/…/data/AndroidGhostlockRepository.kt` | pass `--feasible-out`; map exit 7 to `ParseResult.Ambiguous`; add `--route` on the second pass; one profile is saved; wrap the extractor run in the generation-log writer |
| `app/…/ui/GhostlockViewModel.kt` | handle `Ambiguous`: show the route picker, re-run the use case with the chosen route; no picker when exactly one route is Feasible; expose the anchor verdict |
| `app/…/data/AndroidProfileConfigController.kt`, `profile-core/…/data/profile/ProfileMerger.kt` | execution tuning is app-supplied: common tuning + selected-route preset + a diting/device preset (30/10000/5000); a generated document carries no `execution` block |
| `app/src/main/assets/kernel_profiles/execution-*.conf` | add the diting/device tuning preset alongside the common presets |
| `app/…/ui` (import flow) | route picker dialog for the ambiguous case; no picker when exactly one route is feasible; show the anchor verdict and reason (safe/needs-review) in the profile/import view — an unsafe anchor never reaches a profile |
| `app/…/data/RunLogStore.kt`, `DebugAttackLog.kt` | extend `writeMeta`/`readMeta` to carry the generation record (entry, state, release, input hash, series basis, per-field sources, heuristic fields, verdicts, route-choice basis, chosen route, anchor verdict); entry kind/label for profile generation; reuse the writer, rotation and crash-safe app-private storage |
| `app/…/ui` (log export) | include the generation entry, or add "Export generation log"; show the feasible set, the chosen route and the anchor verdict in the log |

The field-derivation half is designed in
[`extractor-no-btf-struct-derivation-plan.md`](extractor-no-btf-struct-derivation-plan.md); it is
implemented in the same batch as this plan, which owns the route/verdict half.

No native, wire-format or profile-schema change. The output is the same HOCON profile minus the
app-supplied `execution` block; the app consumes it as before. The Kotlin change is the two-pass
ambiguity flow (design 9, including the optional `route` parameter and `ParseResult.Ambiguous`),
the anchor-verdict display (design 7), the device-tuning preset (design 8) and the generation-log
persistence/export (design 10): the extractor's one-branch document is unchanged.

## Gates

1. `cargo test` (host) including the anchor scan.
2. `GHOSTLOCK_IMAGE_DIR` integration test: the eight diting images must still reproduce their
   bundled profiles **with the verdicts computed**, using `--route` for the ambiguous ones.
   Expected: on 136/177/198/209/226/236 `select_stack` Feasible (`delta = 0`, derived shift -2)
   and `sigreturn` Feasible (240/256), so the image is **ambiguous** and exits 7 without
   `--route`; with `--route select_stack` it reproduces the bundled select_stack profile. On
   43/81/101 `select_stack` and `multicast_waiter` are Infeasible and `sigreturn` is Feasible
   (320/336), so exactly one Feasible is emitted without a prompt. Every Feasible route is then
   rendered with `--route` and compared to its own ground truth (`profile-<route>.conf` in the
   test-kernel directory; the bundled asset is preferred where it carries that route), so an
   ambiguous image is checked twice, not once. Assert the verdict lines and
   the numbers, not only the emitted profile, and assert that the emitted `waiter_shift` and
   sigreturn offsets are the derived values: a fixture whose derivation yields `delta = 8`
   (layout shift 1) must emit `-1`, not the family `-2`; a `delta = 32` fixture (layout shift 4)
   is Feasible with `+2`, and layout shift 5 is Infeasible. A fixture where the derivation fails
   (missing symbol or non-unique waiter/copy marker) must leave the route Unknown and not
   auto-select it. The comparison covers the image-derived blocks (route, `task_struct`, `cred`,
   `kernelsnitch`, `offset`); `execution` is app-supplied and the generated document omits it.
3. The six `qemu-cross` images (5.10.43–177): verdicts are computed and recorded per image before
   the route comparison. 43/81/101 must have `sigreturn` Feasible (derived 320/336) and no
   `select_stack`/`multicast_waiter`; 136/177 must be **ambiguous** (`select_stack` Feasible,
   `sigreturn` Feasible 240/256), so the route comparison uses `--route select_stack`. A verdict
   that would switch a route, or a derived sigreturn offset that differs from 320/336 vs
   240/256, is a stop-and-review signal, not an accepted diff.
4. QEMU on the 5.10.246 image: ten offsets exact, `mm_struct` 960; verdicts `select_stack`
   Infeasible (`delta = -0x120`), `multicast_waiter` Feasible (`48 + 56 + 8 <= 264`) and
   `sigreturn` Infeasible (strip home 0x330, copy destination 0x300, so `off_plain = -0x30`);
   multicast geometry complete (`waiter_off` 0x30, `buffer_size` 264, `task` 0x30,
   `lock` 0x38).
5. The diting 5.10.236 image as the control: verdicts `select_stack` Feasible (`delta = 0`),
   `multicast_waiter` Infeasible (window 0x48 short) and `sigreturn` Feasible (240/256) →
   ambiguous; `--route select_stack` emits `waiter_shift = -2`, `--route sigreturn` emits
   `waiter_off_plain = 240`, `waiter_off_sve = 256`.
6. Field derivation and series scope: validate the anchors on a BTF-bearing image by hiding its
   BTF and comparing the derived `task_struct`/`cred`/`mm_struct` values to BTF ground truth field
   by field (the older plan's validation matrix); any mismatch is a stop. The 5.10 images have no
   BTF ground truth, so the diting's device-verified block is the control there and the target
   image's underived fields are labelled as template-sourced. The series decision is itself
   tested: a fingerprint match fills; a fingerprint mismatch must not fill even when the patch
   range would match; an absent IKCONFIG falls back to the range and every field it fills is
   logged as `heuristic` with the range named; an image matching neither source must not receive
   the template — the fields stay null and the reason is logged. A fixture where a derived value
   differs from the template must emit the derived value. Assert the per-field source and
   heuristic flags, not only the values.
7. Device: any profile used on hardware still needs a device gate. Static derivation does not mark
   a profile supported; the unverified-candidate warning stays.
8. Ambiguity flow: ambiguity means two **Feasible** routes (one Feasible plus Unknowns is not
   ambiguous). 136/177/198/209/226/236 are the real two-Feasible images: they must exit 7
   without `--route` and write the verdict JSON via `--feasible-out`; with `--route
   select_stack` or `--route sigreturn` they must exit 0. 43/81/101 (sigreturn only) and 246
   (multicast only) are one-Feasible and must not prompt. The app must read the file, show the
   picker and save exactly one profile with the chosen route. The app must map exit 7 to
   `ParseResult.Ambiguous` and re-invoke `parseSource(route = …)`, not `Failed(7)`. Also assert
   that `--no-disasm --format conf` without `--route` fails instead of emitting a route.
9. Generation log: the extractor stderr and the feasible set/choice survive an app process restart
   (present in app-private storage), and the export includes the generation entry. The log also
   carries the series basis and every heuristic-valued field, so a range-backed profile is
   identifiable as such after a restart and in the export. The app's profile/import view states
   the anchor verdict (safe/needs-review) and its reason; an unsafe anchor is absent from the
   profile. The profile config itself does not carry the raw log.

## Risks and open questions

- **Series detection.** `-gki-` is `CONFIG_LOCALVERSION` and the release suffix ignores the patch
  level; neither is a layout guard. The authoritative source is the embedded IKCONFIG (all 14
  images in the test-kernel corpus embed it), and the patch-precise range is the lowest-priority
  fallback for a blob-less image, not an equal alternative. A range match is a heuristic: every
  value it admits is marked and logged. A fingerprint mismatch is final. This is in this batch,
  not optional: the template is now only a fallback for underived fields.
- **Struct-template portability.** The template is now the fallback, not the source: derivation
  wins, and the series predicate decides where the template may fill. The remaining assumption is
  the same — stable drift between 5.10.236 and 5.10.246 is not excluded — but its blast radius is
  only the underived fields inside the measured series. The `offsetof` proof (compile the source
  with the embedded config) remains the strongest check and is still out of scope.
- **Derivation coverage.** Some fields (`atomic_flags`, parts of the `cred` layout) may not anchor
  uniquely; they stay null or fall back to the template. The log must say which, per field, so a
  profile is never a silent mix.
- **Word-table drift.** The derived shift bound uses `PSELECT_ROUTE_NFDS` (15 words) and the
  compact waiter's last table word (12); the native's `select_stack_route.cpp` holds the same
  table. A test pins the extractor's numbers to those values, and a change to either side must
  update both.
- **The six qemu-cross controls** are all `-android12-9-`; enabling the derivation for them
  changes their output by design: 43/81/101 become derived sigreturn, 136/177 become ambiguous.
  Gate 3 records the expected numbers and treats any other verdict as a stop-and-review signal.
- **Anchor verdict semantics.** Decided: emit `safe` and `needs-review` (all existing anchors are
  needs-review), refuse `unsafe`, and state the verdict and reason in the app (profile/import and
  generation log). The named `dump_skip.zeroes` path must share the ranked path's filter.
- **Feasibility is three-valued.** Unknown is not Infeasible: a route with no derivation may still
  be the only delivery (the diting 5.10.81/101 sigreturn case), so the zero-Feasible fallback must
  be allowed to choose it, labelled. Conversely, a successful derivation is not Feasible unless the
  window rule passes; a derivation *failure* is Unknown, not Infeasible, and is never auto-selected
  while a Feasible route exists. The failure directions must not collapse.
- **Family constant vs derived value.** `SELECT_WAITER_SHIFT = -2` is the derivation's result for
  `delta = 0` on the diting, frozen; it is not independent evidence about another image. The
  per-image derivation wins wherever it exists, and a disagreement on the train is a
  stop-and-review. The constant remains only as the labelled fallback for Unknown routes.
- **`--no-disasm` is diagnostic only.** For `--format conf` it is a hard error unless `--route` is
  given: skipping the derivation must not promote the family constant to a route. The flag stays
  valid for `--analysis`/text/json.
- **Device tuning is app-owned.** The common defaults (`route_wait_ms` 1000, `setup_settle_us`
  50000, select `enter_delay_us` 50000) differ from the diting's measured 30/10000/5000. The app
  must apply a diting/device preset, or a generated diting profile regresses to the common timing.
  The generated document omits the block; a `null` inside a new route group survives the merge and
  blocks the preset, so omission is the contract.
- **Sigreturn geometry** is derived per image (the `rt_sigreturn` chain sums, the helper copy
  destinations, the futex strip home); a derivation failure is Unknown and the family constants
  are a labelled fallback only. The route's device-level exposure (the EL0 re-stamp loop) is a
  rate property measured on hardware, not a feasibility property: the static verdict says the
  copy reaches the strip, not that the race lands.
- **Log/profile separation.** A generation log lives in app data, so a shared `.conf` does not carry
  it; the deferred curated header is the mitigation if that matters. The link is the `meta` record
  and the profile name/stamp. Because heuristic use is deliberately recorded only there, a shared
  `.conf` cannot show that a value was range-backed or constant-backed; the `meta` record and the
  unverified-candidate banner are the mitigation, and the curated header remains the fix when the
  exporters can carry it.
- **Privacy.** The raw log can contain the input URI/path and phone environment; it stays
  app-private until the user exports it. Redaction is a review item.
- **Entry kinds in `RunLogStore`.** `parse` entries must be labelled in the UI and the export so
  they are not mistaken for runs; the existing rotation (`Keep = 10`) and `meta` state apply to
  them too.

## Non-goals

- Marking any generated profile supported without a device run.
- Deriving tcp layouts or the anchor stride. (Sigreturn offsets moved into scope on
  2026-10-21; see design 5.) The shared struct/cred field derivation is in scope; it is the
  older plan's phases 2–3 plus its `nf_logger` path, implemented in this batch.
- Writing the raw generation log into the profile config. The app's exporters drop comments and the
  log is not a profile value; a curated summary header is deferred to an exporter change.
- Multi-route profiles or a fallback chain: one route branch per profile; the native's fallback is
  honored only by `TcpPolicy` and the generator keeps `fallback.to = none`. The ambiguity picker
  chooses one resulting profile; it does not put several branches in one document.
- A general app/UI redesign. The app changes are the ambiguity picker + second extraction pass
  (design 9), the anchor-verdict display (design 7), the device-tuning preset (design 8) and the
  generation log/export (design 10); the editor's route selector remains a manual null-branch
  override.

## Expected result for the 5.10.246 image

`select_stack` Infeasible (`delta = -0x120`); `multicast_waiter` Feasible with `waiter_off = 48`,
`buffer_size = 264`, `task_offset = 48`, `lock_offset = 56`, `compact_waiter = 1`; `sigreturn`
Infeasible (strip home 0x330, copy destination 0x300, `off_plain = -0x30`); `task_struct.*` filled field by field — derived where the anchors hit, the measured-series
template for the rest, each field's source in the log; `cred` refs
`-272685269312 / -272685269904 / -272685264480` (read from `init_cred`); `mm_struct_sz = 960`
(derived from `proc_caches_init` when possible); zero nulls. The series is decided by the embedded
IKCONFIG fingerprint (`ikconfig:<hash>`), so the template fills are not heuristic and the log
records no heuristic values for this image; had the blob been absent, the same fill under the
patch-range fallback would have been marked heuristic. The generated document carries no
`execution` block; the app fills it from the device tuning. The profile keeps the
unverified-candidate banner, and its route still needs a device gate — the geometry derivation
proves the copy can reach the waiter, not that the race lands. Exactly one route is Feasible on
this image, so the ambiguity picker does not appear and the extraction stays a single pass; the
Unknown sigreturn route is not consulted. The generation log records the verdicts, that route and its derivation lines and is
exportable from app data after the fact.

## Implementation status and remaining work (2026-10-23)

**2026-10-24 update — the stride is the regression; the live plan is the PORT-PLAN storage and
measurement model.**

`document` is `fbf6ed0` (`7f859eb` KernelSnitch scan + the `experiment/multicast-anchor` merge).
`feat/extractor-5x-geometry` now ends at `e510ea9`, five commits on top of `document`: the geometry
commit, the app picker commit, the no-BTF derivation (`c3aeb69`), the stride-field removal
(`95016e9`), and the zeroed-iomem fix (`e510ea9`). The profile no longer carries
`kernelsnitch.mm_struct_sz`; the extractor emits only `collisions`, the native spray uses the
compiled `MM_STRUCT_SZ` (0x500), legacy import drops the old flat key, and a zeroed `/proc/iomem`
is rejected (a fresh device leaves the phys pair null and the native's compiled defaults apply).

**Priority 1 (2026-10-24, revised) — the stride is measured; the live plan is the profile storage
and measurement model (`PORT-PLAN.md` Priority 1).** The clean-line 5/5 was re-confirmed on the same
rig/day (`external/port/cleanline-recheck/`: S1 5/5, native logs 15–18 KB). The port of the clean
line's attack protocol was attempted and **reverted**: on fresh boots the pre-port build completed
(1/1 control, plus the prior 2/5) while the ported build wedged in all three route-reaching runs at
the new `wait_consumer_idle` (`drain=-1ms`, at 1 s and at 3 s; `pselect consumer still inflight`),
so the disarm/drain is not independently transplantable. The patches are saved in
`external/port/extractor-5x-port/`. The stride was then isolated: the document line's
`MM_STRUCT_SZ=0x500` (25 objects/slab, from `95016e9`) gave **2/5** with 0–1 accepted pages on the
failed boots, while forcing 960 (34/slab) gave **4/5** with 8–14 accepted pages
(`external/port/stride960-recheck/`). The clean line's 5/5 is the 960 build. The value is measured
(the leak-offset probe; the QEMU `/proc/slabinfo` read), never guessed; the app-side application is
the PORT-PLAN model — a per-kernel read-only measured DB, a home-view merge that exports a new
profile, the editor replacing the override, profiles only on sdcard or bundled, and the legacy
cleanup. The earlier cache/override draft in item 2 is superseded; `port/diting-5.10` remains the
curated dev line and receives nothing.

Verified on the current (document-based) branch: 67 extractor unit tests plus all image-backed
integration tests (14-image `structs_ondevice` and `ondevice_profile`, 4-image masked-BTF truth, 3
codegen variants, 6.1/6.12 cross-family); native `ghostlock` zero warnings and `lint-tidy`;
`profile_test` and `profile_binary_test`; `profile-core` tests; the app suite with only the known
`ProfileMigrationEquivalenceTest` failure; APK 647 (clean `e510ea9`); the on-device UI parse passed
(two-pass picker, forced `select_stack`, overwrite, auto-load; the parsed profile has null phys and
only `collisions`); the no-cache span smoke completed to `KernelSU ready`. The cross-language schema
digest and native-document golden were re-frozen.

Remaining, in order:

1. **Implement the measured stride path** (item 2 of *Remaining work*): the candidate set and the
   leak-offset probe (at generation and as the runtime validator), the generated-profile field
   restored from the verified value (schema digest and golden re-frozen), the object-aligned first
   scan pass with the full grid fallback, and the per-kernel measured DB + merge/export flow
   recorded in `PORT-PLAN.md` Priority 1. The forced-960 series (4/5) is the target; the first run
   on a kernel without a measured value is the fallback-rate run and re-measures.
2. Rebuild + host gates; on-device UI parse (unchanged); then the 5-run fresh-boot completion
   series on the cached path (`cpu-active-hold.sh`), compared with the clean line's 5/5 and the
   forced-960 4/5; archive the gate record.
3. Tag `diting-5.10-r8` from the working branch, cut `pr/extractor-5x-geometry` as a curated branch
   per BRANCH-POLICY, reconcile `port/diting-5.10`; the clean line itself is not rewritten.
4. Optional: a later, separately designed attempt at `9bacaf6`'s per-attempt disarm/bounded drain
   (the 2026-10-24 A/B showed it is not independently transplantable); `atomic_flags`/`page`/`slab`;
   the ViewModel picker test.

The profile-side `mm_struct_sz` limitation is now handled by measurement (item 2 above): the
verified value returns to the generated profile (probe/QEMU only, never a heuristic), the
per-kernel measured DB records it as a read-only fact, and the user applies it only by merging and
exporting a profile (`PORT-PLAN.md` Priority 1); the native leak remains stride-agnostic as the
unknown-stride fallback.


**Branch/worktree (2026-10-23 record, superseded).** `feat/extractor-5x-geometry`, based on
`document` @ `32b9ca8`, in `external/ghostlock-app-worktrees/extractor-5x-geometry`. Committed:
`9c899d6` (extractor) and `4baee6b` (app). A later rebase moved the branch onto `document`
`fbf6ed0`; the step-4/`nf_logger` work and the stride-field removal are `c3aeb69`/`95016e9`, and the
zeroed-iomem fix is `e510ea9`. **The missing clean-line fixes must be ported into this branch
(Priority 1 above); the extractor commits are not replayed onto the curated `port/diting-5.10`.**

**Done and verified.**

- Extractor: IKCONFIG fingerprint + patch-range fallback; three-valued route verdicts;
  `--feasible-out`/exit 7; pselect/multicast/sigreturn geometry; anchor verdict gate;
  omitted `execution`.
- App: two-pass picker, route/anchor log lines, diting timing preset, generation log/meta
  with `field_source` lines.
- Step 4: `structs.rs` derives 13/15 `task_struct` fields and the cred caps/refs from
  `init_task`/`copy_process`/`init_cred`; `field_source` lines; the 14-image
  `tests/structs_ondevice.rs` equals the measured series on every image.
- `nf_logger` no-BTF: type at offset **8**, ULOG=1/MAX=2/UNSPEC=0, the alias chosen by the
  type load, and the measured `loggers+0x10` anchor (not the ULOG slot at +8); all 14
  images match their profiles.
- QEMU regression 2026-10-22: 43/81/101 (three builds)/136 (two)/177/198/246 ten-exact; the
  246 profile is byte-identical to the independently recreated ground truth; the approved
  A-mechanism anchor `+0x2ec7bd8` is exact; anchors are exact where the runtime dump carries
  `dump_skip.zeroes` (the older dumps do not).
- Full 14-image `ondevice_profile` integration test passes (488 s); 64 extractor unit tests;
  115 app unit tests (only the pre-existing `ProfileMigrationEquivalenceTest` failure); APK
  641 built.

**Uncommitted (2026-10-23 record, superseded).** `tools/extract_rs/src/structs.rs`,
`tests/structs_ondevice.rs`, `derive.rs`/`lib.rs`/`main.rs`, the app's `field_source` meta line,
and the companion plan's progress section — all committed as `c3aeb69` on the rebased branch.

**Remaining host-only, in order.**

1. **Done (2026-10-23).** `task_seccomp`: `__secure_computing`'s 32-bit
   `current->seccomp.mode` load (`mrs SP_EL0`, disassembled as `s3_0_c4_c1_0`, then
   `ldr w, [x, #0x848]`), with `copy_seccomp`'s 16-byte struct copy as the fallback and
   `__seccomp_filter` as a second candidate. 2120 on all 14 images, equal to the BTF truth
   on four Pixel 5.10 builds, and it closes on the three codegen variants.
2. **Measured, never guessed: probe at generation; the app applies it only through an exported profile (2026-10-24).**
   `kernelsnitch.mm_struct_sz` is the SLUB stride, not `sizeof(mm_struct)`, and is not derivable
   from the Image (BTF gives sizeof; slab merging and alignment change the object size — 6.1:
   0x3c0 against 1024). The app cannot read it unprivileged: measured 2026-10-24,
   `run-as com.ghostlock.app` gets **EACCES** on both `/sys/kernel/slab/mm_struct/object_size`
   and `/proc/slabinfo` (`-r--r----- root:log`), and the spray runs before root. The value is
   therefore **measured** wherever a probe can see it, and a candidate set is decided by probe:
   - **The candidate set.** The observed family strides are the 32-multiples
     960/1024/1088/1216/1280. The probe decides among them; the gcd of several offsets bounds an
     out-of-set value by the 32 KiB slab.
   - **Probe at profile generation (live, unprivileged).** After a KernelSnitch leak the address
     is a real `mm_struct` object start in its order-3 slab, and the code already masks the base
     (`util.cpp:806`): `o = leaked & (ORDER3_SIZE - 1)` is `j * stride`. The true stride divides
     every observed offset; a wrong candidate fails per sample (1280 fails 3 of 4 offsets; 512
     fails unless `j` is a multiple of 8; 1088 is rejected by the second leak). The clean line's
     five leaks — offsets 0x3fc0/0x1e00/0/0x7bc0/0x3fc0, indices 17/8/0/33/17 at 960 — already
     identify **960** and reject 512/1024/1088/1216/1280; their gcd is 960. **Revised 2026-10-24:
     no extracted family list.** The candidates are the 64-multiples in [800, 1400]
     (`sizeof(mm_struct)` floors the window when the image gives it), the generator runs up to 10
     rounds with early exit (expected 2–3), and every candidate carries a vote count — the number
     of nonzero offsets it divides. No threshold filters the list: the **generation-time picker**
     shows every candidate with at least one vote, sorted by count with the best-supported marked
     (all-rounds, one disagreement, weak), preselects the candidate that won every vote, and lets
     the user confirm or pick another, or leave the field unset. The chosen value is written into
     the optional `kernelsnitch.mm_struct_sz` field, populated only from a measurement, never a
     heuristic. The evidence (offsets, gcd, votes, verdict) goes to the generation log only —
     the measured DB is written only from the root slabinfo read.
   - **Probe at profile generation (host, QEMU).** For an Image the project can boot, the QEMU
     harness reads the guest's `/proc/slabinfo` as root (the project already does: the 5.10.246
     image reports `mm_struct` 960). That is the definitive value; add it to the
     `qemu-crosscheck-profile.py` gate so bundled profiles carry the exact stride, not 0x500.
   - **The app-side application is the `PORT-PLAN.md` Priority 1 model (2026-10-24).** The
     measured DB is ground truth only: it is written after root from `/proc/slabinfo`, read-only,
     with source and evidence, and the user merges it into a profile through a home-view action.
     The leak-probe candidates are generation-time UI (the picker above), never DB entries. The
     profile is the only applied configuration, and profiles exist only on sdcard or as bundled
     assets. The earlier cache/override draft is superseded; no profile or override config lives
     in app data.
   - **Unknown stride on an uncached kernel: try anyway.** The native sprays with the compiled
     default and scans stride-agnostically (32/8 inner, 4 KiB outer; `7f859eb`). This reaches the
     route at the fallback rate: the document line's 25 objects/slab measured **2/5** with 0–1
     accepted pages, against **4/5** and 8–14 accepted pages when 960 was forced
     (`external/port/stride960-recheck/`; the clean line's 960 build reads **5/5**,
     `external/port/cleanline-recheck/`). The first leak can then infer the stride for the
     remaining preps in the same run; that in-run evidence stays in the run log (the measured DB
     is written only from the root slabinfo read), and the QEMU read remains the authoritative
     confirmation for generated profiles.
   - **Use the value twice.** `mm_objs_per_slab = ORDER3_SIZE / stride` for the spray, and an
     object-aligned first scan pass; the full 32/8/4 KiB grid remains the fallback when the stride
     is unknown or the aligned pass misses. The aligned pass is faster (960: 34 probes per slab
     vs ~1024 at inner 32) and avoids the fine-grid false-match exposure; the leak is still a
     probabilistic match, so the validation gate and the page-value check are unchanged.
   - Caveats: require multiple consistent leaks (the 8-collision match can rarely be false); a
     divisor of the true stride also divides every offset, so keep the candidate set/range and the
     slab-capacity bound; the mask assumes the order-3 slab (`MM_ORDER=3`), and the root/QEMU read
     supplies both object size and order. A failed probe never guesses: the field is omitted and
     the runtime path falls back to the compiled default and the agnostic scan.
   - Measured scan costs, for the record: on the diting (40 GiB direct-map span, 6 cores, 4 GiB
     slices extrapolated) S=960 0.8 s, S=32 20 s, S=8 80 s; a 4 KiB outer step is free; RAM-bank
     filtering cuts ~3×; the tag pass (15 validations) costs 263 s at S=32 but is only needed for
     non-canonical addresses. The old plan is `kernelsnitch-stride-fallback-plan.md` (app repo
     `docs/analysis/`).
3. **Done (2026-10-23).** BTF-hidden truth diff: four Pixel 7 (panther) 5.10 images with
   embedded BTF (5.10.157/189/209/214). `tests/btf_truth_ondevice.rs` masks BTF and asserts
   the derivation against it: the series is 15/15 equal to BTF on every image, every derived
   field equals BTF (now 7/15, `seccomp` included), cred caps 0x28/5 and refs [128,136,144].
   Finding: the `copy_process` anchors close on only 6/15 there (the `init_task` data
   anchors); the fingerprint still matches, so the template fills the rest and the profile
   is correct.
4. `task_atomic_flags` (best-effort; no stable single anchor) and `page`/`slab` (JSON
   report only, not carried by `--format conf`) — low value.
5. Optional host ViewModel test for the picker; the UI gate remains the real proof.

**Phone-only.** Install APK 641 and drive Parse source → `boot.img` on the 236 image:
confirm the picker lists both Feasible routes, the second pass saves exactly one profile
with the chosen route, and it loads. The packaged ARM extractor was gated on the diting
before step 4/nf_logger; re-running it with 641 is a cheap extra check.

**Release.** After the UI gate: commit step 4/nf_logger (operator), merge to `document`,
tag `diting-5.10-r8`, cut `pr/extractor-5x-geometry`, reconcile `port/diting-5.10`.

**Known findings/limits.** The custom LTO/`-Os` 5.10.236 image closes only 6 `task_struct`
fields because its `copy_process` patterns differ; the series template fills the rest, so
its profile is still correct, but an out-of-series LTO kernel may get only the `init_task`
data fields. The older QEMU dumps lack `dump_skip.zeroes`, so their anchors are not
checkable. The 246 profile is exact but remains non-device-gated.

## Implementation order

1. Waiter-layout struct + 5.10 constants (no behavior change).
2. `derive_pselect_layout` takes `Option<&Btf>`, 5.10 defaults, `Infeasible` classification; unit
   tests.
2b. Sigreturn derivation: `derive_sigreturn_layout` (the `rt_sigreturn` chain sums, the helper
   copy destinations, the futex strip home) with the `off + 0x58 <= 0x200` rule; unit tests and
   verdict wiring. 43/81/101 become Feasible, 136+ ambiguous, 246 Infeasible.
3. Per-route verdicts — Feasible / Infeasible / Unknown, including the multicast window rule and
   the sigreturn offset rule — computed before selection in analysis + main; a derivation failure
   is Unknown, not a constant fallback; selection per design 5; the emitted geometry follows the
   verdict (derived shift and sigreturn offsets over the family constants); forced-route
   semantics; `--no-disasm` with `--format conf` requires `--route`.
4. Shared-field derivation first: `derive_task_struct`/`derive_cred_layout` anchors, `mm_struct_sz`
   from `proc_caches_init`, the no-BTF `nf_logger` path, waiter `task`/`lock`; `resolve_structs`
   merges derived → template → null with per-field source logging (the older plan's phases 2–3,
   plus its phase-1 `nf_logger` path).
5. Series predicate and template fallback: IKCONFIG layout fingerprint first; the patch-precise
   range is the lowest-priority fallback, only when the blob is absent, and every value it fills
   is marked `heuristic`; the template applies only to underived fields inside the series; the
   series basis is emitted in the log.
6. Multicast waiter-offset fallback, anchor verdict gate (safe/needs-review emit, unsafe omitted),
   `mm_struct_sz` fallback.
7. Integration/QEMU gates above, including the BTF-off truth diff and the out-of-series negative
   test; evidence admitted under the repo's evidence rules only if a run is cited.
8. App: the two-pass ambiguity flow, the route picker (design 9), the anchor-verdict display
   (design 7) and the device-tuning preset (design 8); the one-feasible-route path keeps the
   current single-pass behavior.
9. App logging: persist the generation log and `meta` (design 10), including the series basis,
   per-field sources and heuristic flags; extend the export, and keep the raw log out of the
   config.
10. Branch and release: cut the work branch from `document` (the r7 tip, `32b9ca8`), **not** from
    `port/diting-5.10` — the dev line has diverged and does not carry the r7 extractor. Merge the
    finished work into `document`, tag `diting-5.10-r8`, and cut `pr/extractor-5x-geometry` from
    the release tip for the upstream-worthy extractor half. Rebuild the app so its bundled
    `libextract.so` is the new one. Reconcile `port/diting-5.10` separately by merging `document`
    into it (or re-authoring the clean line on `document`); it is not the base for this plan.
