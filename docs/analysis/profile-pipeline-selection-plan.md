# Profile-selected pipeline — plan (2026-11-09)

**Status:** proposed. No code until the operator approves. Parent design:
[`dirtyfrag-hybrid-root-design.md`](dirtyfrag-hybrid-root-design.md). This plan replaces the
UI-toggle selection of the two chains with a profile field and moves the static feasibility facts
into the extractor verdicts.

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

The correction is not another default. The profile is the per-image contract and must select the
pipeline. The extractor owns the static image facts; the app executes the selected pipeline or
refuses when a fact it can see contradicts it — it never substitutes the other pipeline.

## 2. Naming

- `pipeline = ghostlock` — W1 → W2 → W3 credential chain.
- `pipeline = dirtyfrag` — W1 only → libc++ page-cache stub into init → root shell → ksud handoff.
- New code and docs use these names. The existing "first way / second way" phrasing in older
  documents is historical.

## 3. Design

### 3.1 Profile

The profile gains exactly one key:

```hocon
pipeline = ghostlock   # or dirtyfrag
```

- The profile is authoritative. No app preference overrides it; a debug-only override may exist
  for testing and is logged (see 3.3).
- `route.*` remains the W1 write-vehicle choice. `pipeline = dirtyfrag` requires
  `route.select_stack` with its anchor/scratch/`mm_struct_sz`.
- `kdp` is demoted to a legacy/diagnostic fact: the parser keeps accepting it so old documents
  load, but it is not emitted by the new extractor and is not consulted for selection.
- No `esp_fix`, `send_path`, or `dirtyfrag` block is added. Those are extractor verdicts, not
  profile parameters.

### 3.2 Extractor — the static gate

The extractor already decides route feasibility and refuses to export a profile with no feasible
route. It gains the pipeline feasibility verdict:

| pipeline | feasible when |
|---|---|
| `ghostlock` | `kdp` absent/0 and the selected route is feasible |
| `dirtyfrag` | `esp_fix = absent`, the send path attaches pages (`skb_splice_from_iter` or `ip_append_page`; not `copy`), and **the profile's selected route has a feasible W1** (`select_stack`, `sigreturn`, `multicast_waiter`, or page-based `tcp_zerocopy`). `select_stack` is one W1 vehicle, not a requirement; page-free W1 is a quality flag. KDP does not block. |

The current implementation still checks `select_stack` as the W1 proxy; replacing it with the
per-route W1 verdict is the extractor gate cleanup in `PORT-PLAN.md`. That re-evaluates the 22
ghostlock-only store rows (5.10 pre-136/5.15: `select_stack` infeasible, `sigreturn` feasible);
the 6.1 `send_path=copy` rows stay ghostlock-only, and the A16 stays `select_stack`.

Both the per-route W1 verdict and the route-pair validation depend on the route verdicts being
per-kernel; the extractor's release/family dispatch, the 5.10-only sigreturn/multicast
derivations, and the family nomination are the route-verdict cleanup item in `PORT-PLAN.md`.

- If both are infeasible, generation refuses (clear error), just as it does for a zero-feasible
  route.
- The facts are recorded in `generation.meta` and the parse log: `kdp`, `esp_fix`, `send_path`,
  `dirtyfrag_feasible`. They are not written into the profile.
- The detection reuses the stage-1 static checks: the instruction-level
  `skb_has_shared_frag` test for the ESP fix, and the send-path test for
  `skb_splice_from_iter` / 5.10 `ip_append_page` vs a copying path. Add them to the Rust extractor
  with unit and corpus tests.
- The extractor only reports feasibility; it never ranks or chooses between the pipelines.
  - Exactly one feasible: that is the only pipeline the generator can write.
  - Both feasible: the profile author chooses. The app's generation flow asks; a store entry
    records its choice in `meta.txt`. There is no default and no priority.
  - Neither feasible: generation refuses.
- The generator writes the author's choice into the profile; it does not invent one.
- The on-device extractor shares the same code; the generation UI only offers feasible pipelines.
- The A16 profile becomes `pipeline = dirtyfrag`.

### 3.3 App

- Resolve the profile with the existing precedence (external > builtin > bundled), read
  `pipeline`, and branch:
  - `ghostlock` → the native runs the full chain (no `--w1-only`).
  - `dirtyfrag` → the native runs `--w1-only`; on exit 0 the app runs `runDirtyfragStage`.
- No fallback and no substitution. A contradictory profile is refused before the native; the app
  never silently runs the other pipeline. A **missing** `pipeline` is the legacy default
  `ghostlock` (pre-selector profiles were GhostLock plans); a `kdp = 1` profile without the key is
  refused (section 4), and an unknown value is refused.
- Generation, not the run: when the extractor reports both pipelines feasible, the parse flow
  asks the author and writes the chosen `pipeline`; when only one is feasible, it writes that one;
  the run path never prompts.
- The Advanced toggle leaves the product control set. A debug-only `second_way` intent remains for
  testing, logs `pipeline=… (override)`, and is ignored in release builds. The UI shows the
  profile's pipeline read-only.
- The runtime preflight remains for the ROM-side checks: libc++ cave/stub fit, init/libbase hook,
  SELinux state, and the manager scan. The static image facts are the extractor's job.
- Optional follow-up (decision 3): a pre-W1 self-test of the DirtyFrag primitive on the app's own
  file (the stage-2 probe shape) as a runtime backstop for external profiles.

### 3.4 Native / wire

- `pipeline` is carried in the wire profile. The native cross-checks it against the invocation
  (full chain vs `--w1-only`; the DirtyFrag stage's `--dirtyfrag`) and hard-errors on a mismatch.
  This prevents app/native drift.
- `kdp` is not added to the new wire; legacy documents are handled app-side.
- Re-freeze the wire schema digest and the native-document golden; update the round-trip and
  migration tests.

### 3.5 Bundles and the store

- A16: `pipeline = dirtyfrag`; the extractor facts are recorded in its generation record.
- Every store entry records an explicit `pipeline = ghostlock|dirtyfrag` choice in `meta.txt`
  (the store author's choice). The ship tool validates it against the superset's verdicts and
  writes it into the rendered asset. When both pipelines are feasible and `meta.txt` has no
  choice, `--check` reports `pipeline choice required`; it never falls back to a preference. The
  initial curation records a choice per entry rather than relying on a tool default.
- The superset (`options-<release>.json`) gains `pipeline_facts` and `pipelines[]` verdicts; it
  does not gain a `chosen_pipeline` — that is the author's choice, not the extractor's. All store
  supersets are regenerated with the new extractor; `options_ondevice` is the whole-document gate.
- `ship_golden_profiles.py` gains pipeline validation, a content-aware `--check` (asset vs
  superset + choice), and a guarded `--refresh` for existing SHIPPED GOLDEN assets. The rule
  becomes: every entry with a superset, a feasible route, and a feasible pipeline ships; an entry
  with no feasible pipeline is exempt with its reason.
- The final audit (section 7) measures every bundled profile's source kernel before release; no
  asset's pipeline is assumed from its family, its version, or its old asset.

## 4. Migration and compatibility

Pre-selector profiles are GhostLock plans by construction: the DirtyFrag chain did not exist when
they were authored, so a missing `pipeline` means `ghostlock`. The app applies that default and
logs it (`pipeline=ghostlock (legacy default)`); it never silently picks `dirtyfrag`.

- A profile that carries `kdp = 1` but omits `pipeline` is from the transition window (KDP was
  emitted before the selector); it is refused with a `pipeline` invalid field, because the legacy
  default would run the known-fatal chain. The parse flow regenerates it with the choice.
- The A16's old external document carries neither `pipeline` nor `kdp`; it is a pre-selector
  GhostLock plan and would run GhostLock. The bundled A16 profile now carries
  `pipeline = "dirtyfrag"`; the old external document must be re-parsed or edited, and must not be
  selected on the A16.
- The bundled assets all carry an explicit line; the diting's external 960 profile was edited to
  add `pipeline = "ghostlock"` (and the bundled diting profile already carries it).
- `kdp` continues to parse for old documents; new generation omits it (the fact lives in the
  superset).
- Forward compatibility: a new profile containing `pipeline` is rejected by app builds that
  predate the key (`KnownTopLevel`); this is true of every newly added top-level key. The bundle
  and app are versioned together.

## 5. Tests and gates

**Extractor**

- Unit: synthetic ESP guard present/absent; send-path classification; KDP.
- Corpus: diting 5.10.236 (`ip_append_page`, vulnerable, `ghostlock` feasible), A16 6.12.23
  (`skb_splice_from_iter`, vulnerable, `dirtyfrag` feasible), duchamp 6.1.138 (`copy` →
  `dirtyfrag` infeasible), a KDP + ESP-fix synthetic (no feasible pipeline), and the existing
  route-verdict corpus.
- `generation.meta` fields; both-feasible generation requires an explicit author choice (no
  default); refusal with no feasible pipeline.

**Profile / app**

- Parser accepts `pipeline`; legacy refusal; validation groups; round-trip; migration; schema
  digest; app branch; toggle override; UI text.
- Full `:profile-core:test` and `:app:testDebugUnitTest`.

**Native**

- Wire parse and cross-check; host build/lint/tests; digest and golden re-freeze. `cmp_disasm` is
  not required unless the profile plumbing touches the attack path.

**Device**

- Diting, GhostLock control: one fresh-boot run of the proven profile to confirm no regression.
- A16, DirtyFrag: the bundled profile alone must select `dirtyfrag` (no toggle); the run should
  reach W1 → DirtyFrag → init shell → ksud. The ksud handoff is the gate; the live KDP/DEFEX and
  MTK trigger/stub remain A16 device gates.
- A16, legacy external profile without `pipeline`: the app refuses before the native.
- Record the runs; update the A16 report and the design doc.

## 6. Implementation order

1. Plan approval.
2. Extractor facts and pipeline verdicts; tests; store superset refresh.
3. Profile schema, wire, native cross-check, digest/golden.
4. App branch, legacy refusal, toggle retirement, tests.
5. Store entry choices and A16 asset; regenerate the bundle.
6. Host gates.
7. Device gates and evidence.
8. **Measured bundle audit (final task)** — section 7; reconcile every asset, refresh,
   content-check.
9. Build and NAS delivery after the audit.

## 7. Final task — measured bundle audit

The bundle is not shipped on assumed pipelines. Before the final build, every bundled profile is
reconciled against a measurement of its own source kernel.

1. **Inputs.** Every `test-kernels` entry's `Image` and sidecars (the `options_ondevice` inputs),
   the A16 report image, and any hand-finished bundled asset with a source image. An asset with no
   source image cannot claim a measured pipeline; it is recorded as hand-finished and is not
   covered by the superset rule.
2. **Measure.** Run the updated extractor with `--options-out` on each image and record
   `pipeline_facts` (`kdp`, `esp_fix`, `send_path`) and both `pipelines[]` verdicts. The facts are
   per image; device sidecars do not change them. The store's `options-<release>.json` is the
   record; `options_ondevice` is the reproducibility gate.
3. **Reconcile every bundled asset** against its measurement:
   - chosen pipeline measured infeasible → defect; replace it with a feasible pipeline or remove
     the asset, and record the reason;
   - exactly one feasible → the asset must carry it;
   - both feasible → the asset carries the author's recorded choice; the audit records both and
     does not override the choice;
   - neither feasible → the asset must not ship; remove/deprecate it and record the reason;
   - no source image → recorded separately; its pipeline needs its own evidence, not a family
     assumption.
4. **Record a table** in the release evidence with one line per bundled profile: release, source,
   `kdp`, `esp_fix`, `send_path`, `ghostlock` verdict, `dirtyfrag` verdict, asset `pipeline`,
   action. Include the `ship_golden_profiles.py --check` output and the bundle count.
5. **Ship** the corrected assets through the guarded `--refresh`; the content-aware `--check` and
   the profile/app/native tests must pass.
6. **Device tier, where available.** The static measurement is the minimum for every asset. A
   profile whose chosen pipeline has not been device-measured is marked experimental, per the
   project's device-gating rule. The A16 DirtyFrag run and the diting GhostLock control are the
   device checks; the rest remain static/experimental until a device gate exists.

The audit is the last task before the final build and NAS delivery; no bundled asset ships on an
assumed pipeline.

## 8. Risks

- The A16 DirtyFrag pipeline is not device-proven; the profile will select it, so the next runs are
  the gate. One run per fresh boot; a run that dies after W1 leaves SELinux permissive until
  reboot.
- The extractor's send-path detection can be wrong on a new image; the corpus is the guard, and
  the optional self-test is the runtime backstop.
- Requiring `pipeline` forces legacy profiles through a re-parse; the rig's external profile is the
  first one.
- The debug override must not become a hidden product switch again; release builds ignore it and
  the run log names the source.
- The measured audit can shrink the bundle: an asset whose chosen pipeline is infeasible, or
  whose kernel has no feasible pipeline, must be removed/deprecated rather than kept on an
  assumption. That is the rule working; the audit table records the reason.

## 9. Open decisions (recommendations)

1. **Migration:** missing `pipeline` = `ghostlock` (pre-selector profiles are GhostLock plans); a
   `kdp = 1` profile without the key is refused (settled 2026-11-09).
2. **Toggle:** debug-only override (recommended), versus remove entirely.
3. **Pre-W1 self-test:** follow-up (recommended) versus include in the first cut.
4. **`kdp` in the wire:** not added; legacy app-side only (recommended).
5. **When both pipelines are feasible:** the author chooses; there is no generator default and no
   priority (settled 2026-11-09). The parse flow asks, and a store entry records the choice.
6. **Hand-finished assets without a source image:** keep them marked experimental with their own
   evidence (recommended), versus remove them. The A16 has its report image, so this applies only
   to an asset that cannot be measured at all.

## 10. Non-goals

- The DirtyFrag block plan in the profile (it is ROM/runtime state).
- Root-manager/ksud selection; the Samsung manager scan fix is separate and done.
- The A16 DirtyFrag trigger/stub, live KDP/DEFEX, and the ksud handoff as device gates.
- Any KDP bypass for the GhostLock pipeline.
