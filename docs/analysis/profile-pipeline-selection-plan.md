# Profile-selected pipeline — plan (2026-11-09, amended 2026-11-10)

**Status:** proposed. No code until the operator approves. Parent design:
[`dirtyfrag-hybrid-root-design.md`](dirtyfrag-hybrid-root-design.md).

**Amendment (2026-11-10).** The pipeline field is an **ordered list**, resolved by the app at
execution time **before W1**; the generation UI does not ask for a pipeline. The original
scalar/no-fallback design and the parse-flow picker are superseded (§3.1, §3.3, §9). The reason is
the kernel/userspace split: the extractor's verdict is a kernel-image capability, while the
DirtyFrag stage depends on the ROM (libc++/libbase hook, cave, policy) and on runtime behaviour
(the spliced-page send path) that no image fact can settle. An explicit order lets the app try
DirtyFrag where it verifies and fall back to the proven chain **without ever making the device
permissive for a stage it could not verify**.

## 1. Problem

The A16 run `20261108-224100` is the evidence. The app resolved the **bundled** A16 profile
(`builtin=6.12.23-android16-5-abA165MUBS6CYL1-4k (bundled, authoritative); overrides=none`), which
carries `kdp = 1`. The app then ran the GhostLock credential chain (W1 → W1p → W2) and reset at the
W2 boundary, exactly where Samsung KDP rejects the forged `init_cred` pointer. It never reached the
root script or the Samsung ksud.

The reason is structural: the pipeline was a preference (`PrefSecondWay`, default `false`), not a
profile property. The profile knew the image rejects forged credentials; the app ignored that
because the user had not flipped a UI switch. The profile and the app disagreed about which chain
to run.

The first correction made the profile authoritative with a single scalar pipeline and no fallback.
That fixed the silent substitution but created two problems this amendment addresses: a generation
picker the user has no basis to answer (the kernel image cannot see the ROM), and a hard refusal
for every statically feasible image whose ROM the project has not run. The order resolves both: the
author records a precedence, and the execution process verifies each candidate before the W1 point
of no return.

## 2. Naming

- `ghostlock` — W1 → W2 → W3 credential chain.
- `dirtyfrag` — W1 only → libc++ page-cache stub into init → root shell → ksud handoff.
- `pipeline` is an **ordered list** of these names; the first viable entry runs.
- New code and docs use these names. The existing "first way / second way" phrasing in older
  documents is historical.

## 3. Design

### 3.1 Profile

The profile's pipeline key becomes an ordered list:

```hocon
pipeline = ["dirtyfrag", "ghostlock"]   # ordered; the first viable entry runs
```

- **Semantics.** The order is the author's precedence. The app resolves it **once, before W1**,
  walking the entries in order and running the first one that passes its static and runtime
  checks. It never re-resolves after W1 and never appends an unlisted pipeline.
- **One entry is the strict form:** `["dirtyfrag"]` on a KDP image that cannot run GhostLock;
  `["ghostlock"]` for a conservative profile. `["ghostlock", "dirtyfrag"]` is legal but expresses
  "prefer the proven chain"; the ship audit records it as a deliberate curation choice.
- **Legacy:** a missing key is `["ghostlock"]` (pre-selector profiles are GhostLock plans); a
  scalar `pipeline = "x"` is the one-element list `["x"]`.
- **Validation.** Every listed entry must be statically feasible in the superset's `pipelines[]`
  (an infeasible fallback is a defect, not something to skip silently); unknown names are refused.
  A `kdp = 1` image's list must contain `dirtyfrag` and must not contain `ghostlock` — the
  GhostLock chain is fatal there, so the strict form is the only valid one.
- `route.*` remains the W1 write-vehicle choice; the profile's route is a feasible one by
  construction, including the page-based `tcp_zerocopy` case.
- `kdp` is demoted to a legacy/diagnostic fact: the parser keeps accepting it so old documents
  load, but it is not emitted by the new extractor and is not consulted for selection (the list
  validation is).
- No `esp_fix`, `send_path`, or `dirtyfrag` block is added. Those are extractor verdicts, not
  profile parameters.

### 3.2 Extractor — the static gate

The extractor already decides route feasibility and refuses to export a profile with no feasible
route. It also emits the pipeline feasibility verdicts:

| pipeline | feasible when |
|---|---|
| `ghostlock` | `kdp` absent/0 (the extractor still refuses to export a profile with no feasible route) |
| `dirtyfrag` | the ESP fix is absent (`esp_guard` + `send_marking`), the send path attaches pages (`skb_splice_from_iter` or `ip_append_page`; not `copy`), and a route can deliver W1. `select_stack` is one W1 vehicle, not a requirement; page-free W1 is a quality flag. KDP does not block. |

The implementation accepts **any feasible route** for W1 (the old `select_stack` proxy is gone,
2026-11-10); the profile's selected route is feasible by construction, including page-based
`tcp_zerocopy`. The remaining send-path precision (the direct-call scan's negative `copy`
inference) is the pipeline-selection item in `PORT-PLAN.md`; the static verdict is a conservative
capability class, and the app's pre-W1 probe is the behavioural check.

The extractor derives the **default order** from the verdicts; it does not ask:

- both feasible → `["dirtyfrag", "ghostlock"]` (DirtyFrag first: the OnePlus A/B measured it 4.8×
  faster app-side and 17.6 s faster wall);
- only `dirtyfrag` → `["dirtyfrag"]` (the KDP shape);
- only `ghostlock` → `["ghostlock"]`;
- neither → generation refuses (clear error).

The order is recorded in the superset (`pipeline_order`) and written into the cut. `--pipeline`'s
forced single choice is replaced by an optional `--pipeline-order` override (curation and tests),
validated against `pipelines[]`; the normal generation path needs no flag. The on-device
extractor shares the same code, so the parse flow has nothing to ask.

The facts are recorded in `generation.meta` and the parse log: `kdp`, `esp_fix`, `send_path`,
`dirtyfrag_feasible`, `pipeline_order`. They are not written into the profile.

The A16 profile becomes `pipeline = ["dirtyfrag"]`.

### 3.3 App — execution-time resolution

Resolve the profile with the existing precedence (external > builtin > bundled), read the ordered
list, validate it, and walk it **before W1**:

| entry | viable when |
|---|---|
| `ghostlock` | statically feasible (not KDP); the normal pre-run gates apply |
| `dirtyfrag` | statically feasible **and** the ROM preflight passes **and** the primitive probe passes **and** the live state allows it |

- **ROM preflight** (the running ROM, not the image): the libc++/libbase sentry-constructor import
  graph, the tail-page cave fit for the stub, DEFEX/verity presence, the `IpSecService` and policy
  surface. This is the app's existing stage-plan computation (`DirtyfragPlan`) promoted to a
  refusal before W1.
- **Primitive probe** (the stage-2 shape): splice the app's own file into a UDP socket under a
  transport-mode IPsec transform, then read the block back. Changed = the kernel attaches the
  spliced page and the ESP path writes it; unchanged = the fix is present or the send path copies.
  It runs as an untrusted app, needs no root, and touches only the app's own file.
- **Live state**: SELinux state, seccomp, manager availability.

The first viable entry runs, and the run store logs the resolution
(`pipeline=<entry>` plus every rejected entry and its reason). **No fallback after W1:** once the
W1 write is issued, the list is spent. If the chosen stage fails after that, the stub restores
enforcing as its first act when it fires; otherwise the app bounds the stage and prompts a reboot
— the only way to clear permissive without root.

The probe distinguishes **setup-failed** (no `IpSecService`, SELinux refused the transform, could
not test) from **primitive-failed** (the read-back did not change). Setup-failed is "cannot
verify": in a best-effort list the next entry is tried; in a strict list the run is refused with
that reason. A primitive failure always skips `dirtyfrag`.

The generation UI **does not ask for a pipeline**. The parse/export flow writes the extractor's
order; the profile page shows it read-only. The pipeline picker (`ParseDialogStage.Pipeline`) and
its strings are retired. The debug-only `second_way` intent becomes a debug order override,
logged, silently ignored in release builds, and still subject to the list validation (it cannot
force GhostLock on KDP).

### 3.4 Native / wire

- The app resolves the list to one pipeline and passes the **resolved scalar** to the native.
  `pipeline` stays a scalar in the wire profile; the native cross-checks it against the invocation
  (full chain vs `--w1-only`; the DirtyFrag stage's `--dirtyfrag`) and hard-errors on a mismatch.
- The list itself stays app-side (the profile document); putting it in the binary schema is not
  needed for the cross-check. If that ever changes, the digest/golden move with it.
- `kdp` is not added to the new wire; legacy documents are handled app-side.
- Re-freeze the wire schema digest and the native-document golden only if the scalar's presence
  changes; update the round-trip and migration tests.

### 3.5 Bundles and the store

- The superset gains `pipeline_order` (derived, §3.2). `ship_golden_profiles.py` writes it into the
  rendered asset; a `meta.txt` order is an optional curation override, not a requirement. The
  content-aware `--check` validates every entry of the asset's order against `pipelines[]` and the
  order's derivation (or the recorded override), and `--refresh` rewrites an existing SHIPPED
  GOLDEN asset under the guarded rule.
- **Sequencing.** Until the app's execution-time resolver ships, a bundle must not put `dirtyfrag`
  first on a stage without device evidence. The interim curation keeps `["ghostlock"]` for the
  unverified entries and uses `["dirtyfrag", "ghostlock"]` only where both pipelines are feasible
  and the ROM is device-verified (diting 5.10.236, OnePlus 6.6.66); the A16 is the strict
  `["dirtyfrag"]`. Once the resolver lands, the derived order becomes the default for every
  statically feasible entry.
- The final audit (section 7) reconciles every asset's order against its own measured image; the
  device tier marks a first entry that has not been device-measured as experimental.

## 4. Migration and compatibility

Pre-selector profiles are GhostLock plans by construction: the DirtyFrag chain did not exist when
they were authored, so a missing `pipeline` means `["ghostlock"]`. The app applies that default and
logs it (`pipeline=ghostlock (legacy default)`); it never silently picks `dirtyfrag`.

- A profile that carries `kdp = 1` but omits `pipeline` is refused: the legacy default would run
  the known-fatal chain. It must be re-parsed or edited to `["dirtyfrag"]`.
- A scalar `pipeline = "x"` is read as `["x"]`. An array is the current form.
- The A16's old external document carries neither `pipeline` nor `kdp`; it is a pre-selector
  GhostLock plan and would run GhostLock. The bundled A16 profile carries `["dirtyfrag"]`; the old
  external document must not be selected on the A16.
- The bundled assets migrate to the list; the diting's external 960 profile gains the legacy
  one-element `["ghostlock"]` (or is re-parsed).
- `kdp` continues to parse for old documents; new generation omits it (the fact lives in the
  superset).
- Forward compatibility: an app build that predates the list sees an array where it expects a
  string and refuses the profile; an entry name the app does not know is refused rather than
  skipped (the app cannot evaluate its checks). The bundle and app are versioned together.

## 5. Tests and gates

**Extractor**

- Unit: synthetic ESP guard present/absent; send-path classification; KDP; the default-order
  derivation (both / one / none) and `--pipeline-order` validation.
- Corpus: diting 5.10.236 (`ip_append_page`, vulnerable, both feasible → `["dirtyfrag",
  "ghostlock"]`), A16 6.12.23 (`skb_splice_from_iter`, KDP, `["dirtyfrag"]`), duchamp 6.1.138
  (`copy` → `["ghostlock"]`), a KDP + ESP-fix synthetic (no feasible pipeline), and the existing
  route-verdict corpus. `options_ondevice` (with `GHOSTLOCK_IMAGE_DIR` set) is the whole-document
  gate on `pipeline_order`.
- `generation.meta` fields; refusal with no feasible pipeline.

**Profile / app**

- Parser accepts the list (array, scalar, missing); validation refuses an infeasible entry and a
  KDP list containing ghostlock; migration; round-trip; schema digest.
- Resolution matrix: both-feasible with probe pass (dirtyfrag chosen), probe primitive-fail
  (ghostlock, no W1), probe setup-fail (ghostlock in a list; refusal in the strict list), ROM
  preflight fail, strict `["dirtyfrag"]` (no fallback), KDP refusal. The picker is gone.
- Run-store log records the chosen entry and every rejection reason.
- Full `:profile-core:test` and `:app:testDebugUnitTest`.

**Native**

- Wire parse and the resolved-scalar cross-check; host build/lint/tests; digest and golden
  re-freeze. `cmp_disasm` is not required unless the profile plumbing touches the attack path.

**Device**

- Diting, GhostLock control: one fresh-boot run of the proven profile.
- Diting/OnePlus, best-effort list: the resolved pipeline is `dirtyfrag`; force the probe to fail
  (a synthetic/setup failure) and confirm the app takes `ghostlock` **without W1** (the device
  stays enforcing).
- A16, strict list: the bundled profile alone selects `dirtyfrag` (no toggle); the run should
  reach W1 → DirtyFrag → init shell → ksud; a stage failure prompts the reboot path.
- A16, a hand-edited `["dirtyfrag", "ghostlock"]`: refused before the native (KDP).
- Record the runs; update the A16 report and this design.

## 6. Implementation order

1. Plan approval (this amendment).
2. Extractor: the default order and `pipeline_order` in the superset; `--pipeline-order`; tests;
   store superset refresh.
3. Profile list schema and validation; app resolution + ROM preflight + primitive probe; picker
   retirement; tests.
4. Native resolved-scalar cross-check; digest/golden as needed.
5. Store/bundle order; interim curation; regenerate; content-aware `--check`.
6. Host gates.
7. Device gates (diting, OnePlus fallback, A16 strict).
8. **Measured bundle audit (final task)** — section 7; reconcile every asset's order.
9. Build and NAS delivery after the audit.

## 7. Final task — measured bundle audit

The bundle is not shipped on assumed pipelines. Before the final build, every bundled profile is
reconciled against a measurement of its own source kernel.

1. **Inputs.** Every `test-kernels` entry's `Image` and sidecars (the `options_ondevice` inputs),
   the A16 report image, and any hand-finished bundled asset with a source image. An asset with no
   source image cannot claim a measured pipeline; it is recorded as hand-finished and is not
   covered by the superset rule.
2. **Measure.** Run the updated extractor with `--options-out` on each image and record
   `pipeline_facts` (`kdp`, `esp_fix`, `send_path`), both `pipelines[]` verdicts, and the derived
   `pipeline_order`. The facts are per image; device sidecars do not change them. The store's
   `options-<release>.json` is the record; `options_ondevice` is the reproducibility gate.
3. **Reconcile every bundled asset** against its measurement:
   - any entry in the asset's order measured infeasible → defect; remove it from the order (or the
     asset) and record the reason;
   - exactly one feasible → the order must be its one-element list;
   - both feasible → the order carries the derived default or a recorded curation override; the
     audit records both verdicts and the order and does not silently rewrite the override;
   - neither feasible → the asset must not ship; remove/deprecate it and record the reason;
   - no source image → recorded separately; its order needs its own evidence, not a family
     assumption.
4. **Record a table** in the release evidence with one line per bundled profile: release, source,
   `kdp`, `esp_fix`, `send_path`, `ghostlock` verdict, `dirtyfrag` verdict, asset
   `pipeline_order`, action. Include the `ship_golden_profiles.py --check` output and the bundle
   count.
5. **Ship** the corrected assets through the guarded `--refresh`; the content-aware `--check` and
   the profile/app/native tests must pass.
6. **Device tier, where available.** The static measurement is the minimum for every asset. An
   asset whose first entry has not been device-measured — and whose ROM preflight/probe have not
   been exercised there — is marked experimental, per the project's device-gating rule. The A16
   strict run and the diting/OnePlus best-effort runs are the device checks; the rest remain
   static/experimental until a device gate exists. With the execution-time resolver, an
   experimental entry is a fallback candidate, not a promise.

The audit is the last task before the final build and NAS delivery; no bundled asset ships on an
assumed pipeline.

## 8. Risks

- **A fallback can mask a DirtyFrag regression.** If the probe or preflight fails persistently,
  every run silently degrades to GhostLock. The run log and the profile page must name the
  rejection reason, and the release audit must review the fallback rates.
- **The pre-shell permissive window remains.** The preflight and probe cannot prove that init's
  sentry constructor actually fires and the stage completes. A stage failure after W1 leaves
  SELinux permissive until reboot; the stub's first act restores enforcing when it fires, and the
  app prompts the reboot otherwise. This is why the order is resolved pre-W1 and never after.
- **The send-path static detection can be wrong on a new image.** The corpus is the guard; the
  probe is the runtime backstop; a false `copy` now only costs a fallback, not a refusal.
- **Probe false negatives and setup failures.** Classification must distinguish "could not test"
  from "does not work", or a working pipeline is suppressed.
- **A misordered list** (`["ghostlock", "dirtyfrag"]`) is legal but is a deliberate curation choice;
  the audit records it rather than flagging it as an error.
- **The A16 strict list has no fallback.** Its stage failure is the reboot path; the next A16 runs
  remain the gate.
- **Legacy profiles** migrate through the one-element form; a KDP profile without the key is
  refused rather than defaulted.

## 9. Open decisions (recommendations)

1. **Migration:** missing `pipeline` = `["ghostlock"]`; a `kdp = 1` profile without the key is
   refused (settled 2026-11-09).
2. **Toggle:** a debug-only order override, logged and release-ignored (recommended).
3. **Pre-W1 self-test:** now part of the execution-time resolver, not optional (settled
   2026-11-10).
4. **`kdp` in the wire:** not added; legacy app-side only (recommended).
5. **Order when both pipelines are feasible:** the extractor derives `["dirtyfrag", "ghostlock"]`;
   the generation flow does not ask; the execution process decides (settled 2026-11-10,
   supersedes the author-choice rule).
6. **Hand-finished assets without a source image:** keep them marked experimental with their own
   evidence (recommended), versus remove them.
7. **Probe failure classes:** setup-failed is "cannot verify" (fall through a best-effort list;
   refuse a strict one); primitive-failed always skips `dirtyfrag` (recommended).
8. **List in the wire:** app-side; the native receives the resolved scalar (recommended).

## 10. Non-goals

- The DirtyFrag block plan in the profile (it is ROM/runtime state).
- Root-manager/ksud selection; the Samsung manager scan fix is separate and done.
- The A16 DirtyFrag trigger/stub, live KDP/DEFEX, and the ksud handoff as device gates.
- Any KDP bypass for the GhostLock pipeline.
