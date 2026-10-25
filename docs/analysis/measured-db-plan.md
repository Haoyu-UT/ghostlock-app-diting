# Measured database and the profile storage model (2026-10-25)

Status: implementation plan for `feat/measured-db` (PORT-PLAN Priority 1, items 3–6). L-level:
it changes where profiles live, what the editor persists, and adds a cross-layer contract
(native root script → app data → UI). No native attack-path change: the root script gains one
read-only `/proc/slabinfo` capture, and the native profile wire is untouched.

## Implementation status (2026-10-25)

Implemented on `feat/measured-db` (stacked on `feat/extractor-5x-geometry` @ `44fe05f`; the tree
is uncommitted for the operator to review):

- **Measured DB** — `MeasuredProfileStore` (HOCON, `schema_version = 1`, atomic write, merge by
  key, refuses an unreadable/newer file), root-script `/proc/slabinfo` capture into
  `$HOME_DIR/.ghostlock_slabinfo`, ingest only after a completed attack run, the raw capture as
  the run's `slabinfo-mm_struct.txt` sidecar, and the read-only Measurements screen (Advanced).
- **Sources** — `ExternalProfileStore` (SAF read + persisted grant), `ProfileDocumentParser`
  (includes resolved against bundled assets only), precedence external > builtin > bundled, an
  unreadable external selection is an error not a fallback, and the selection reference
  (URI/name/release/sha256/parent) in preferences. The live controller has **no** edit layer.
- **Editor** — the session controller gets a `MemoryOverrideStore`; export through SAF is the
  only save; diff against the bundle and rebase (bundle becomes the base, edits kept); exported
  documents carry a `# ghostlock-profile parent=…` lineage comment.
- **Merge** — the home card appears when a measured fact differs from the active profile; the
  preview shows field/profile/measured/source/evidence; the export writes a new document and
  offers to select it (never applies the DB automatically).
- **Legacy cleanup** — list the app-data documents, export any (optionally with the stored
  override applied to matching releases), delete only after an explicit confirmation; cancelled
  exports keep the data.
- **Tests** — new `MeasuredProfileStoreTest`, `ExternalProfileStoreTest`; the controller/source/
  edit tests rewritten for the new model. Host gates pass; the only app test failure is the
  pre-existing `ProfileMigrationEquivalenceTest` fixture-size check.
- **Device** — the measured fact was produced by a root phase and appeared in the DB; the merge
  export was written to Downloads and selected; the selection survived a reboot (diagnostic run
  `state=completed`, `external=… applied`, `stride=960`). The five-boot series and its result are
  recorded in `external/port/measured-db-2026-10-25/`: the final build ran **5/5** with a fixed
  run tap, and the same-day smoke control (the unchanged 650 APK) also ran **5/5**. An earlier
  1/5 series on the final build used repeated uiautomator searches before each tap; its native
  profile input was **byte-identical** to the control's (`profile.bin` sha `5eab76ca…`, digest
  `0x1ae95c6f59734bb3`), so the failures are attributed to that instrumentation, not the build.
  Rule for future harnesses: locate the run button once after a defined scroll, then use fixed
  coordinates — never repeated uiautomator dumps in the run window.
- **Device-found fix** — the first legacy export applied an override's same-route branch by
  replacing it, dropping the lock anchor (`select_stack { waiter_shift = null }`). The export now
  follows the merger's rule (`LegacyProfileExport`): same branch merges field-wise, a different
  branch replaces; nulls keep the document's value. Verified on the device with the repaired
  export, then the legacy data was exported and deleted.
- **Stride picker (extractor branch, then rebased)** — the old English list of
  `N/M rounds · X objects/slab` rows became an evidence-led sheet in `6301413` on
  `feat/extractor-5x-geometry`: one recommendation, a level (Confirmed / Consistent / Mixed /
  Insufficient) with a localized reason, radio alternatives, the raw table behind technical
  details, and Skip as its own action. `feat/measured-db` was committed (`23c00ec`) and rebased
  onto it; the rebased flow keeps the sheet, uses the export footer, and feeds it the
  root-measured fact (`rootMeasuredStride`) so a kernel with a DB fact shows **Confirmed**.
  Device-checked on versionCode 651: the sheet rendered `960 字节 / 已确认`, the reason, the
  alternatives, the details expander, and the SAF export on "Use"; record `stride-picker-zh.png`
  in `external/port/measured-db-2026-10-25/`.


## Why

The 2026-10-24 stride series showed the bundled 5.10.236 profile lacked the Slab stride (960)
that the clean line ships, so the document line sprayed 25 objects/slab and finished 2/5 where
the clean line finished 5/5. The stride cannot be derived from the image:
`mm_struct_sz` is the SLUB stride, not `sizeof(mm_struct)`. It can be **measured** — the
unprivileged leak probe votes, and a root `/proc/slabinfo` read is ground truth. What is missing
is a place to keep that fact, a rule that facts never silently become behaviour, and a storage
model where a profile is a document the user owns rather than an app-data override layer.

## Model

### 1. Sources and precedence

A profile document is either a **bundled asset** or an **external file on the SD card**. App
data keeps no profile documents and no override layer.

Live resolution order for the device's release:

1. **External** — the document the user selected with the system picker (SAF, persistable read
   permission). It wins over the bundle for its release: the bundle stays the default, an
   explicit selection is an explicit statement.
2. **Builtin** — a hand-picked bundled asset (the existing escape hatch).
3. **Bundled** — the asset whose `release` equals the device's `uname -r`.

An external selection that can no longer be read (file deleted, permission lost) is an error,
not a silent fallback to the bundle: the run log and the profile screen say why. Clearing the
selection restores the bundle.

**Update 2026-10-26 — the home support flag follows the same model.**
`isKernelSupported()` = bundled release ∪ legacy `user_profiles` import ∪ the stored external
selection's release (`releaseSupportedByProfileSources`, covered by `ProfileLayerPolicyTest`).
Before this, a device with no bundled profile could select an external document — it loaded —
but the home stayed "Not supported" and `runExploit()` refused. Device test:
`external/port/external-profile-support-2026-10-26/` in the port repository.

App data keeps, and only keeps: the bundled assets; the measured DB; the run logs (with the
per-run `profile.conf`/`profile.bin` and the source metadata); the selected profile's reference
(URI, display name, release, SHA-256, parent lineage); ordinary settings.

The editor never writes app data. Edits live in an in-memory base + sparse map; the only save
is an export through SAF. An unexported edit is lost, and the UI says so before leaving.

### 2. Measured DB — facts only

Per kernel `uname -r`, a fact is `key -> value, source, evidence, measured_at`.

- **Written only after root.** The root script (uid 0, after W3) reads `/proc/slabinfo` for the
  `mm_struct` line and writes `$HOME_DIR/.ghostlock_slabinfo` atomically (header `# <uname -r>`
  + the line), mode 644, exactly like the iomem cache. The app ingests it only when the attack
  run completed (`state=completed`), copies the raw file into the run folder as
  `slabinfo-mm_struct.txt`, and records the fact with `source=root-slabinfo` and the raw line
  as `evidence`.
- **Never a precedence layer.** The run reads only the applied profile. The DB feeds the
  read-only measurements screen and the explicit merge (below). The native in-run leak probe
  stays the safety for an unmerged or stale profile.
- **Unprivileged probe candidates never enter the DB.** `--probe-stride` output is evidence for
  the generator UI, not a fact.
- Store: `filesDir/measured_profiles.conf`, HOCON, `schema_version = 1` (below). Read-only UI.

### 3. Merge

The home screen shows a button when the device release has DB facts that differ from the active
profile. It opens a preview: field, profile value, measured value, source, evidence. Confirming
builds a **new profile document** (the active document with the facts applied), validates it,
and requires an export through SAF. Nothing is applied in place; the source document is
untouched. After a successful export the app offers to select the exported file for the next
run (an explicit selection, never automatic).

### 4. Editor

- Base = the active source document; edits = an in-memory sparse map (route, fallback, general,
  advanced). Rendering resolves base + edits + device tuning, exactly as a run resolves.
- **Export is the only save** (SAF). Revert reloads the base and drops the edits.
- **Diff / rebase against the bundle.** The editor shows the differences between the current
  result and the bundled profile for the device release, and offers a rebase: the bundled
  document becomes the new base while the in-memory edits are kept. This is how a profile
  written against an older bundle is moved forward after an app update.
- Exported documents carry a comment header recording lineage (parent source and hash). It is a
  comment, not a schema key, so the native wire and `ProfileResolver` stay unchanged.

### 5. Legacy cleanup

Old builds kept imported documents in `filesDir/user_profiles/` and a sparse override in
`ghostlock_prefs`. A one-time flow lists them; the user exports any document through SAF,
optionally applying the stored override to the entry with the same release. Only after an
explicit confirmation are the app-data documents and the override deleted. A cancelled or
failed export keeps everything and re-prompts; nothing is deleted silently. The override never
survives the cleanup, whether or not it was applied.

## Data formats

Measured DB (`measured_profiles.conf`):

```
schema_version = 1
kernels = [
  {
    release = "5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284"
    updated_at = 1761350000000
    facts = [
      {
        key = "kernelsnitch.mm_struct_sz"
        value = 960
        source = "root-slabinfo"
        evidence = "mm_struct 123 456 960 34 8 : tunables ..."
        measured_at = 1761350000000
      }
    ]
  }
]
```

Fact keys are dotted profile paths (`kernelsnitch.mm_struct_sz`); this is what makes a fact
mergeable and comparable with the active profile. Extra non-profile keys would be visible in the
UI but never merged, so the root ingest records only profile-addressable facts.

External selection reference (preferences):

```
external_profile_uri, external_profile_name, external_profile_release,
external_profile_sha256, external_profile_parent, external_profile_parent_sha256
```

Export lineage header (first line of an app-exported document):

```
# ghostlock-profile parent=<bundled:<release>|external:<name>@<sha8>|builtin:<release>> sha256=<hash>
```

## Code map

| file | change |
|---|---|
| `src/core/attack/ops.cpp` | root script: atomic `/proc/slabinfo` `mm_struct` capture into `$HOME_DIR/.ghostlock_slabinfo` |
| `data/MeasuredProfileStore.kt` | new: versioned fact store, atomic write, merge-by-key |
| `data/ExternalProfileStore.kt` | new: SAF read + persistable permission + hash; entry selection by release |
| `data/AndroidProfileConfigController.kt` | sources/precedence; in-memory override store for sessions; diff/rebase rendering; no live overrides |
| `data/AndroidGhostlockRepository.kt` | ingest after a completed run; selection; export/merge/legacy APIs; delete the live user-profile copy path |
| `data/ProfileEditorSession.kt` or controller ctor | session base + memory overrides |
| `ui/GhostlockViewModel.kt` | merge state, measurements, selection, export-as-save, legacy flow |
| `ui/AdvancedUI.kt` | Load-config screen (external/bundled), editor actions, measurements screen, legacy screen |
| `ui/GhostlockUI.kt` | home merge banner; actions; screens |
| `res/values*/strings.xml` | en + zh |
| tests | store round-trip, ingest parse, precedence, merge diff, rebase, cleanup, editor render |

## Tests and gates

Host: `make -C src ghostlock` (zero warnings), `make -C src lint-tidy`, `make -C src
native-host-tests`; Gradle unit tests (Robolectric where Android APIs are used); profile-core
tests.

Device: build the APK, install `-r -d`, run one fresh-boot attack to write the fact and confirm
the measurements screen; then a fresh-boot series with a **merged + exported + selected**
profile, measured against the 960 4/5 and clean-line 5/5 records. Export/selection exercised on
the phone through SAF. Screen off and auto-dim restored afterwards.

## Non-goals

- No automatic application of DB facts, ever.
- No change to the native profile wire, the schema digest, or the attack routes.
- No sdcard directory listing: an external profile is a picked URI, not an app-managed folder.
- `port/diting-5.10` stays untouched.
