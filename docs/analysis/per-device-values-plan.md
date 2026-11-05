# Per-device values — profile schema v2 (design plan)

**Status:** implemented 2026-11-04 (schema v2, `device_defaults`, the 5.10 + `dew` migration).
Editor write-back and extractor emission remain as follow-ups.
**Origin:** the 2026-11-04 profile-scope audit
(`external/port/profile-scope-audit-2026-11-04/README.md`) and the MTK report
`external/github_error_reports/5.10.198-android12-9-00085-g226a9632f13d-ab11136126/20261104-115100.zip`.

## Implementation status (2026-11-04)

Landed:

- `PerDevicePhys` (`profile-core`): v2 maps → the running device’s scalar (or null), with the
  atomic-pair, duplicate-key, type and schema checks; v1 scalars pass through.
- `AndroidProfileConfigController`: resolves the maps before the merge, accepts document schema 1
  or 2, and reads `device_defaults.conf` keyed by `Build.DEVICE`. `isDitingDevice()` and the
  `execution-diting.conf` branch are gone.
- `ProfileMerger.fillRouteExecutionDefaults`: an explicit null no longer shadows a route preset
  (the same “null = shipped default” contract as the tuning keys).
- `ProfileExporter`: resolves the maps device-neutrally (null) for its `.bin` fixtures.
- Assets: the eight 5.10 profiles are v2 with `{ diting = … }` physical maps and null timing;
  `6.6.89-…5a0ffb4` is v2 with `{ dew = … }`; `device_defaults.conf` carries the diting timing.
- Tests: `PerDevicePhysTest` (11 cases), `DeviceDefaultsTest` (diting 30/10000/5000 vs generic
  1000/50000/50000), `CpuPairHintTest`; `NativeDocumentEquivalenceTest` resolves each migrated
  profile with its authoring device and reproduces the frozen golden bytes; `ProfileLayerPolicyTest`
  updated for the diting defaults.

**Support gate (2026-11-04, later).**

- `ProfileConfig` carries the resolved `physLoad`/`physOffset`; `KernelSnapshot.devicePairMissing`;
  `physicalPairUsable()` requires a pair on MediaTek and keeps the compiled per-generation default
  on Qualcomm. An MTK device without a pair is not runnable and the start log says
  “device physical layout missing; attach vendor_boot/dtbo (MediaTek) and re-parse”.
- The native `ResolvedAddresses::init_for_soc` refuses the same case (`EINVAL`), so a bypass cannot
  run on the compiled MTK default; `address_space_test` covers the refusal and the qcom default.
- The bundled 6.x maps now carry the measured MediaTek devices: `duchamp` (6.1.115, 6.1.138 ×2),
  `spinel` (6.12.30), `aristotle` (6.12.38), `dew` (6.6.89). The Qualcomm profiles keep no map;
  their generation default is the pair.
- `SupportPolicyTest` (SoC recognition + the usable rule, including the `MTxxxx` prefix) and the
  `DeviceDefaultsTest` 6.x map cases pass; the full native host suite, `address_space_test`,
  `assembleDebug` and `lint-tidy` are green; the full app suite keeps only the known
  `ProfileMigrationEquivalenceTest` fixture failure.

Gates: `:profile-core:test` green; `:app:testDebugUnitTest` green except the known
`ProfileMigrationEquivalenceTest` fixture-size failure; `:app:assembleDebug` builds.

**Extractor `--device` cut + new bundle (2026-11-05).**

- `ghostlock-extract --device <codename>` renders `--format conf` and the cut as schema v2 with
  `kernel_phys_load = { <codename> = <value> }`; `--options-out` and the store supersets stay
  device-neutral. `cut_with_device`/`cut_plan_with_device`; the store `meta.txt` `device` line drives
  the cut; `cut_ondevice` covers the yunluo and rubens cuts.
- New bundled kernels, both QEMU-crosschecked (10/10 offsets + anchor):
  `5.10.101-…-gf4c0e37` (yunluo, V13.1.1.0) and `5.10.168-…-g81e7418` (rubens, OS1.0.2.0; new
  runtime in the test-kernels store, `device = rubens`). The 5.10.198/209 profiles already carry
  both devices. The app index, native-document golden and exporter agreement include the new
  profiles.
- Stored plan: `docs/analysis/per-device-values-plan.md`; matrix evidence:
  `external/port/mtk-device-matrix-2026-11-04/`.

**Device identity fallback + device-sidecar store shape (2026-11-05, later).**

- **Identity is not always `Build.DEVICE`.** The Redmi Note 15 4G (`spinel`) reports
  `ro.product.device=missi` (its system/product partitions are a mainline `missi` build), while
  `ro.product.vendor.device=spinel` and `ro.product.bootimage.device=spinel`; the OTA's
  `pre-device` is the MTK vendor name `mgvi_64_armv82`. The lookup now tries, in order,
  `Build.DEVICE`, `ro.product.vendor.device`, `ro.product.bootimage.device`, and uses the first
  identity that has an entry. `PerDevicePhys.resolveFor` returns the resolved document plus the
  matched key; the controller passes the candidates to both the phys map and `device_defaults`.
  `DeviceIdentity` (app) reads the two fallback properties via `SystemProperties`. This amends the
  earlier "map keys are `Build.DEVICE`" rule: the key is a device identity, with Build.DEVICE
  primary and the vendor/boot-image identities as fallbacks. All other fetched devices agree on
  the first identity (diting, NX769J, NX809J, NX799J, OP612BL1, ASUS_AI2401, tegu; the Xiaomi
  codenames match their package filenames).
- **The store now carries the device sidecar sets.** Every entry's sidecars moved from the entry
  root to `devices/<codename>/`; `meta.txt` carries `devices = <codename>[, …]`. 106 sidecar files
  across the corpus; the 5.10.198 and 5.10.209 entries carry `diting` (`uefi`), `yunluo`
  (`vendor_boot`+`dtbo`) and `rubens` (`vendor_boot`+`dtbo`), the last two copied from the fetched
  OS1.0.9.0/OS1.0.10.0/OS1.0.16.0 packages. The store key is the unique codename (`spinel` for
  the Redmi Note 15 4G), not `Build.DEVICE`.
- **The superset carries every device derivation.** `options-<release>.json` gained
  `devices[]` (`device`, `kernel_phys_load`, `kernel_phys_offset`, `phys_source`, `candidates[]`,
  `plans[]`). The top-level fields remain the first (primary) device. The scratch/plans are
  recomputed per device because `pick_w1_scratch` reads the physical delta; the harness runs the
  extractor once per `devices/<device>/` set with `--device <name>` and merges the entries. The
  cut is `(superset, route, plan, device)`; `cut_with_device` selects the device's plans and pair.
  The corpus regenerated (`generate_options`), `options_ondevice` and `cut_ondevice` pass, and a
  new multi-device test cuts diting/yunluo/rubens on both 5.10.198 and 5.10.209 and compares each
  with the CLI. Evidence: `external/port/codename-check-2026-11-05/`.
- **On-device extractor integration (2026-11-05, later).** The parse call now passes
  `--device <vendor device>` (`DeviceIdentity.profileKey()`), so a user-generated profile is
  schema v2 with `kernel_phys_load = { <device> = … }`. The parse presence checks
  (`physLoadPresent` / `physOffsetPresent` / `missingSidecarFields`) resolve the v2 map for the
  running device instead of reading a map with `getLongAt`; the ambiguous-route cut
  (`OptionSuperset.devices` and `cut(route, plan, device)`) selects the device's pair and emits
  the v2 map, and the route-picker callers pass `options.device`. `PerDevicePhys` now accepts a
  map with a whole-`null` counterpart (the load-only `uefi` case) while still rejecting a map
  mixed with a scalar; a null field is the native default. Tests: `OptionSupersetDeviceCutTest`
  (3), the new `PerDevicePhysTest` map+null cases; the full app suite is 178 tests with only the
  known `ProfileMigrationEquivalenceTest` fixture failure.
- **Not in this cut:** the parse flow has not been exercised through the UI on the diting yet;
  the editor still exports a resolved v1 document; the Motorola/Infinix codenames remain
  unconfirmed; the bundled map for the spinel entries already uses `spinel`, which the fallback
  now resolves.

Remaining (not in this cut):

- The `Sog10ProfileCoreRegressionTest` now skips (its 5.15.189 asset was dropped in the r8 bundle
  cut `38ef1bdc`); restore the asset or delete the test if the profile is not returning.
- The editor export now preserves the selected document's schema-v2 physical maps: `renderMerged`
  restores the running device's entry (the resolved or edited value) and every other device key,
  keeps a load-only source's `null` offset, and adds the running device's key when an edited value
  targets a device the source did not carry. `UserProfileStore.exportHocon` and the legacy
  `legacyProfileDocument` keep schema 2 when the physical maps are present. Tests:
  `EditorPhysMapTest` (bundle edit keeps other devices; absent-device edit adds both entries;
  load-only source keeps the map + null) and the `UserProfileStoreTest` v2/v1 exports. The
  editor's field display/default hint and clearing rule remain open.
- The extractor's `--device` map emission, the store `devices[]` derivation, the app's parse-call
  device key, the map-aware parse presence checks and the device-aware option cut are done. What
  remains is the UI parse test on the diting (parse `boot.img` + `uefi`, expect `{ diting }`,
  export/select/run) and the editor/export v2 preservation.
- The Motorola Edge 60 Fusion and Infinix X6879/X6873 profiles stay v1 with top-level scalars until
  their `Build.DEVICE` codenames are confirmed.
- `BuiltinProfileCatalog.builtin` / `OffsetMatching` remain dead code (only tests reference them).

## Problem

A profile is keyed by `uname -r`, which identifies the kernel image. The physical pair
(`kernel_phys_load` / `kernel_phys_offset`) is a device/bootloader fact and is not decided by the
uname: the same GKI build runs on different platforms with different layouts. The 5.10 assets pinned
the diting pair, the resolver prefers a profile-supplied load over the SoC default
(`src/core/memory/address_space.cpp:88-107`), and a MediaTek device running the same 5.10.198 build
wrote every W1 attempt to the wrong physical page (`clean=1/1`, verify failed, 15/15).

The device-scoped values must be selectable by device; the kernel-scoped values stay keyed by uname.

## Decisions (2026-11-04)

- **Schema v2.** `kernel_phys_load` and `kernel_phys_offset` become **per-device maps**
  (`<device> = <value>`). A v1 scalar is still read as a legacy value for every device.
- **No generic `per_device_overrides` block.** Only the physical pair is a dictionary; the editor
  problem is confined to two known fields.
- **The bundled profiles set the diting-measured timing parameters to `null`**:
  `execution.race.route_wait_ms`, `execution.race.setup_settle_us`,
  `execution.routes.select_stack.enter_delay_us`. `null` means “no override”.
- **The app supplies a per-device default when the timing is null.** Generic tuning remains
  `execution-tuning.conf`; the diting preset becomes a data table keyed by `Build.DEVICE`
  (`device_defaults`). `isDitingDevice()` and the codename branch in `readExecutionTuning()` are
  deleted.
- **`selected_cpus` is not a profile fact.** The app derives the pair from the device’s clusters and
  forces it at resolve time; the profile’s copy is a hint and is not authoritative. A wrong hint
  (e.g. CPU 8 on an 8-core device) is inert: the merger overwrites it, the wire’s `recommended_cpus`
  is filled from the forced pair, the native validates the pair and reverts on failure
  (`runtime_config.cpp:25-64`), and the editor drops it on export. Add a unit test for this.
- The wire is unchanged: after resolution the phys fields are scalars (or null) and the timing is an
  integer, exactly as today. The wire digest and native golden stay frozen.

## Schema

```hocon
schema_version = 2
release = "5.10.198-android12-9-00085-g226a9632f13d-ab11136126"

kernel_phys_load   = { diting = 2818572288 }
kernel_phys_offset = { diting = 2147483648 }

execution {
  race {
    route_wait_ms   = null
    setup_settle_us = null
  }
  routes {
    select_stack { enter_delay_us = null }
  }
}
```

Rules:

1. In v2 the two phys fields may be a map or null; in v1 they remain a scalar or null. A map in a v1
   document is an error. A scalar in a v2 document is accepted as a legacy all-device value.
2. Map keys are `Build.DEVICE` values, exact and case-insensitive; duplicate keys after case-folding
   are rejected. Values are integers.
3. The two maps are atomic **when both are maps**: the same key set; a key in one without the
   other is an error. A field may be a whole `null` while the other is a map (a sidecar that
   carries only the load, e.g. the common Qualcomm `uefi`); a map mixed with a scalar is rejected.
4. Lookup tries `Build.DEVICE`, then `ro.product.vendor.device`, then
   `ro.product.bootimage.device`; the first identity present in the map wins. No key → the field
   resolves to null → the native’s compiled/platform default applies. No fallback scalar in v2.
5. Timing keys may be `null` or absent in any version. The merge already treats an incoming null as
   “no override” (`deepMergeValues`, `ValueModel.kt:72-84`), so null leaves the device default.
6. The existing coupled-group validation still runs after the phys lookup.

## Resolution

1. Parse the document; accept `schema_version` 1 or 2. For v2, validate the phys maps as above.
2. Substitute each phys map with the running device’s value (or null). The rest of the pipeline sees
   the scalar/null shape it sees today.
3. Build the tuning defaults: `execution-tuning.conf` (generic) plus `device_defaults[Build.DEVICE]`
   if present. The document’s non-null values override; route presets fill absent route groups
   (`fillRouteExecutionDefaults`). The route preset is the non-diting default (`enter_delay_us =
   50000`); the device table supplies `5000` on a diting.
4. Force the CPU pair, validate, encode as `schema_version = 1` for the wire.

Placement: the phys substitution is a pure function in `profile-core`; the tuning lookup stays in
`AndroidProfileConfigController.readExecutionTuning()` (now table-driven). No `ProfileMerger` change
beyond receiving the resolved scalars it already receives.

## Device defaults table

```hocon
device_defaults {
  diting {
    execution {
      race { route_wait_ms = 30  setup_settle_us = 10000 }
      routes { select_stack { enter_delay_us = 5000 } }
    }
  }
}
```

This replaces `execution-diting.conf` and `isDitingDevice()`. Adding a measured device is a data
entry, not an app change. The values are the batch-E/F-calibrated ones recorded in the 5.10.236
asset comments; the table carries the same rationale as a comment.

## Editor — open design

- **Phys fields:** display the running device’s value (or “no value / default”); editing writes
  `kernel_phys_load[Build.DEVICE]` and `kernel_phys_offset[Build.DEVICE]` together, adds the keys
  when absent, and preserves every other device key verbatim. The export stays v2 with the maps.
- **Timing fields:** ordinary nullable scalars. A null value shows the device default as a read-only
  hint; editing sets a scalar; clearing writes null and restores the default.
- No generic dictionary editor is needed; the only new type is “per-device scalar” on two fields.

## Compatibility

- **v1 documents:** scalar phys, timing values or absent; unchanged.
- **v2 documents:** maps; old apps reject v2 explicitly (`unsupported profile schema`), rather than
  failing later on a map where a number is expected.
- **Bundled assets are per-APK**, so v2 in the bundle cannot strand an old install.
- Writers that force `schema_version = 1` must preserve 2 when the document has phys maps:
  `UserProfileStore.exportHocon` (`:165`), `AndroidGhostlockRepository.kt:1288`,
  `AndroidProfileConfigController.kt:450` (editor view).
- The legacy converter’s “v2” terminology refers to the normalized v1 form; do not conflate it with
  `schema_version = 2`.

## Migration

| profiles | change |
|---|---|
| 5.10.81/101/136/177/198/209/226/236 | v2: phys maps with the `diting` entry; the three diting-measured timing keys set to `null` (the device table supplies 30 / 10000 / 5000 on a diting; generic elsewhere). `selected_cpus` may stay as a hint. |
| 6.1.145 g9b69cc (Motorola Edge 60 Fusion) | v2: phys maps with its device entry |
| 6.1.157 a8b0b54 (Infinix X6879/X6873, MT6788) | v2: same |
| 6.6.89 5a0ffb4 (`dew`, Redmi 15C / POCO C85) | v2: phys maps with `dew` |
| all other 6.x | unchanged (no phys values, no device-measured timing identified) |

**Prerequisites:** the Motorola and Infinix codenames are not in local records (no test-kernel store
entry). `dew` is known from the OTA name. Do not migrate those two until `Build.DEVICE` is confirmed.

## Code touchpoints

- `profile-core/.../ProfileResolver.kt`: v2 acceptance; phys map validation; scalar/map typing.
- New `profile-core/.../PerDevicePhys.kt` (or functions in the resolver): lookup/validate, pure.
- `NativeProfile.kt` / `ProfileMerger`: receive the scalar/null after substitution; no wire change.
- `AndroidProfileConfigController.kt`: `readExecutionTuning()` reads `device_defaults`; delete
  `isDitingDevice()` and the `execution-diting` branch; editor map handling; relax the schema check
  (`:755`, `:762`) to 1..2.
- New asset `device_defaults.conf` (replaces `execution-diting.conf`).
- Extractors: emit phys maps under `--device <codename>` (the app passes `Build.DEVICE`); without a
  device key, emit null/empty and no unscoped scalar. `# fact_sources` records the device and source.
- `BuiltinProfileCatalog` / `OffsetMatching`: dead in production (only tests); deleting them is the
  cheapest correct option. If revived, the catalog must resolve the phys map for a device before
  flattening.

## Tests and gates

- Unit: v1 map rejected; v2 map accepted; matching key substitutes; missing key → null; scalar in v2
  treated as legacy; mismatched key sets rejected; duplicate keys rejected; non-integer value
  rejected; timing null leaves the tuning value; device table entry merges; no entry → generic.
- Golden: a v2 document with a phys map and null timing resolves to the same wire bytes as the
  equivalent v1 document with the value baked in and the timing explicit. Wire digest and native
  golden unchanged.
- Existing suites: profile-core, app Gradle (known fixture failure excepted), native host suite
  untouched, `make -C src ghostlock`, `lint-tidy`, `ExporterAgreementTest` (Robolectric device has no
  entry → device-neutral fixture remains valid).
- No `cmp_disasm` change (no native modification).
- Device: diting no-op — resolve a migrated 5.10 profile and compare the wire digest with the
  current one; optional one-boot smoke. The MTK mismatch is covered by a unit test with a simulated
  `Build.DEVICE`.

## Follow-ups (not this cut)

- Editor per-device entry editing (write-back rules and UI cues) if users need it.
- Legacy v1 external profiles with a top-level scalar pair keep today’s behaviour; consider a run-log
  notice when the pair equals another platform’s compiled default.
- Remove `selected_cpus` from the profiles once the UI no longer uses it as a hint.

## Rollout order

1. Schema/resolver + `device_defaults` + tests (no asset changes).
2. Migrate `dew` and the 5.10 family (codename known).
3. Confirm Motorola/Infinix codenames, migrate those two.
4. Rig check + release notes (`v2 documents require the new app`).
