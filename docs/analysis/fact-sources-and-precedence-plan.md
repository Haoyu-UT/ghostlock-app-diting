# Fact sources, domains and precedence for profile derivation

Level: **L** (profile format and the profile→native contract). Status: **stages 1–5 implemented
2026-10-29 and the bundle items are closed (6.1 caps/copy split into `credential-6_1.conf`, the
6.x `empty_zero_page` values patched, the 5.15 block confirmed as the 5.x one); the r8 cut
remains.**
Written 2026-10-28 after two independent failures on one vendor kernel (OnePlus CPH2723, stock
6.6.66) showed the same root cause pattern.

Test-corpus status (2026-10-29): every 5.15/6.x store entry now has a QEMU runtime witness —
26/26 boots, 25 candidates, every checkable `offset.*` exact and all 24 carried anchors exact
(`external/port/qemu-corpus-2026-10-29/`). The per-entry `meta.txt` states `profile_provenance`
(`device` / `qemu` / `upstream` / `none`) and a `qemu_check` line; a profile without such a
witness is a candidate, not a golden. See `external/test-kernels/README.md`.

## Why this exists

Two facts went wrong in one day, on one vendor kernel (OnePlus CPH2723, stock 6.6.66):

1. **The physical pair.** The extractor derived `kernel_phys_load` from the iomem `Kernel code`
   start, which is seeded with `__pa_symbol(_text)` on some images and `__pa_symbol(_stext)` on
   others (0x10000 higher). The first record said "6.6+"; a 69-image survey then showed the
   choice does **not** follow a release rule at all — 5.10 and **6.12.69** use `_text`, while
   5.15/6.1/6.6 and 6.12.23/30/38 use `_stext`, and 6.12.30 vs 6.12.69 are consecutive builds
   of the same device — which is exactly the per-image fact this document exists for. `kernel_phys_offset` came from the lowest System-RAM chunk instead of
   `memstart_addr`, which arm64 rounds down to `ARM64_MEMSTART_ALIGN` (1 GiB on 4K pages; the
   rule is in 5.10 too) — the emitted offset was 0x1960000 high. The profile only worked after
   both were corrected by hand.

   **Decision (2026-10-28):** the fix is not a better iomem interpretation — `/proc/iomem` is
   removed as a source for the physical pair. See *Physical placement: no iomem* below.
2. **The cred layout.** The 6.12-only W2 repair was gated on a release predicate
   (`cred_usage_is_long()`, "6.10+") because that is where mainline made `struct cred.usage`
   `atomic_long_t`. The vendor 6.6.66 kernel **backports** it, so `uid` is at `init_cred+8` on a
   6.6 kernel; the gate kept the repair off and W2 failed 15/15 with the exact 6.12 signature.

Both are the same mistake at different layers: **a per-image fact was taken from a version
predicate or an unverified heuristic, although a per-image source existed** (BTF carries the cred
layout; the bootloader's own memory map carries the physical placement; the kernel's arm64 rule
defines the round-down).

The durable fix is not more special cases. It is a fact model: every value the profile needs is a
*fact* with a **domain**, a **source**, a **confidence**, and a defined set of **witnesses**; and
the sources have a precedence per class of fact.

## Definitions

- **Fact** — a value the profile (or the route) needs, e.g. `task_struct.cred`, `cred.uid`,
  `rt_mutex size`, `pselect waiter shift`, `mm_struct slab stride`.
- **Domain** — the axis the value lives on: *image offset* (relative to `_text`), *symbol
  address* (link-time VA), *physical address*, *runtime VA*, *field offset*, *sizeof*, *slab
  stride*, *frame depth in bytes*, *enum value*. Two values are comparable only in the same
  domain; cross-domain comparison is a bug, not a mismatch.
- **Source** — where a value comes from: `btf`, `kallsyms`, `disassembly`,
  `release-template`, `compiled-default`, `runtime-measurement`, `operator`, `bootloader`
  (xbl_config / uefi / vendor_boot / dtbo).
- **Confidence** — `verified` (primary + same-domain witness), `derived` (single per-image
  primary), `measured` (runtime), `heuristic` (family default on a release that is not the
  template's), `default` (compiled constant), `suspect` (a witness contradicted it — blocks
  emission as verified), `unknown` (no source produced it).
- **Witness** — a second source that can independently produce the same fact *in the same
  domain*. Witnesses corroborate; they never fill a missing member of a coupled group.
- **Coupled group** — a set of facts produced by one decision (e.g. one struct layout). All
  members must come from the same source decision; a group may have witnesses but not mixed
  primaries.

The confidence ladder, highest first: **verified > derived > measured > heuristic > default**;
`suspect` is outside the ladder (refuses). `operator` is a source, not a confidence: an operator
value is authoritative for the run but never counts as verified.

## Source precedence, per class

| fact class | primary, best → worst | witnesses |
|---|---|---|
| struct layout (field offsets, sizes, enum values) | **image BTF** → release layout template → compiled default | disassembly access sites, kallsyms type sizes (rarely) |
| symbol offsets/addresses (`init_task`, `init_cred`, logger slots, `selinux_state`, the zero page) | **image kallsyms** → disassembly reference site → compiled default | disassembly reference offset |
| code geometry (pselect/futex frames, route strips, waiter shift, feasibility) | **image disassembly** → operator override → compiled default | running kernel only (QEMU/device) — no static witness |
| runtime facts (SLUB stride, memory limits, slabinfo) | **device measurement** → image-derived proxy (e.g. `sizeof`) → compiled default | a second measurement (picker vs slabinfo) |
| physical placement (`kernel_phys_load`, `memstart_addr`) | **bootloader metadata** (xbl_config FDT / uefi memory map / vendor_boot header / dtbo DTB) → operator `--phys` → compiled default (key omitted) | the bootloader's other map (xbl vs uefi vs vendor_boot DTB), in the *same* domain; **`/proc/iomem` is not a source** (see below) |
| route policy (which route, anchor triple) | derivation/verdict → operator triple → none (refuse) | the device gate |

Operator-supplied values (`--anchor-*`, CLI overrides) sit above all of these for their run and
are logged as `operator-supplied, not derived`; they never promote a fact to `verified`.
`--phys` is the exception in one direction: the extractor uses it when no bootloader source
supplies the load, so it is a labelled fallback rather than an override of a bootloader fact.

## Physical placement: no iomem

`/proc/iomem` is not a source for `kernel_phys_load` or `kernel_phys_offset`. Both values it
offered are post-boot runtime views whose contract is not the profile's:

- `Kernel code` is seeded with `__pa_symbol(_text)` or `__pa_symbol(_stext)` depending on the
  image, not the release: a 69-image survey (5.10.43 .. 6.12.69) found both, and the two spinel
  builds OS3.0.301 (6.12.30) and OS3.0.303 (6.12.69) straddle it. So "the load is this start"
  is high by 0x10000 on some images and exact on others.
- The lowest `System RAM`/carveout base is not `memstart_addr`: arm64 rounds
  `memblock_start_of_DRAM()` down to `ARM64_MEMSTART_ALIGN` (1 GiB on 4K pages). The diting
  hides it — a `reserved` carveout below System RAM lands the walk on the right base anyway —
  while the CPH2723 has no such carveout, so the emitted offset was 0x1960000 high and the
  anchor resolved to a stale alias.

A wrong explicit value is worse than none: on the CPH2723 the native's compiled defaults
(`0xa8000000` / `0x80000000`) were exactly right, so a null pair would have worked where the
iomem-derived pair did not.

The source set for physical placement is therefore:

1. **bootloader metadata** — the `xbl_config` FDT or `uefi` memory map (the kernel's own map
   entry) for the load; the `vendor_boot` header `kernel_addr` and the `dtbo`/`vendor_boot` DTB
   `/memory` base for the offset;
2. **operator `--phys`** when no bootloader source is in hand, logged as operator-supplied;
3. **null** — the key is omitted and the native's compiled default applies
   (`P0_KERNEL_PHYS_LOAD` 0xa8000000, `QC_GKI_6_12_PHYS_LOAD` 0xc7800000, `P0_PHYS_OFFSET`
   0x80000000).

The Image's own section symbols remain a same-domain witness when a static range is available
from an authorized source (`Kernel data` = [`_sdata`, `_end`); `Kernel code` starts at `_text`
or `_stext`), and the 69-image survey is why a release predicate cannot stand in for the
per-image check. They are not a reason to read iomem.

On the app path the consequence is explicit: a device-specific load now requires the boot image
plus a sidecar (Qualcomm: `xbl_config`, else `uefi`; MediaTek: `vendor_boot`, else `dtbo`), or
the profile leaves the pair null for the native's default. The parse advice already asks for
those images; its `sourceSuppliesLoad()` predicate still counts `iomem`, which becomes dead when
the source is removed. Note this is the extraction path only — the native's runtime
`.ghostlock_iomem` cache (the root child's dump, used to narrow the KernelSnitch direct-map
span) is unaffected, because it never supplies the physical pair.

Implementation (2026-10-29): **removed.** The extractor no longer reads iomem — the `--iomem`
option and the `iomem` module are gone, the four integration tests no longer pass it, and the
app's `sourceSuppliesLoad()` / `ParsePhysTest` no longer treat it as a load source. The fact-model
stages below are unchanged by it.

## Domains: the no-cross-domain rule

This project already has the canonical example: `sizeof(struct mm_struct)` (0x4c0) is **not**
`kernelsnitch.mm_struct_sz` (the SLUB stride — 960/1024/1280 by family). Comparing them is
meaningless and would have "corrected" a correct value. Other traps:

- image offset vs link-time symbol address vs runtime VA vs physical address (KASLR, phys load,
  `memstart_addr`);
- field offset within a struct vs the struct's offset within its owner;
- `sizeof` vs slab stride vs cache line;
- frame depth (bytes below `sp`) vs strip word index (`word = (depth - base) / 8`).

Every fact carries its domain, and the cross-check engine compares only same-domain values.

## Witness policy is asymmetric

| witness result | meaning | action |
|---|---|---|
| agrees | strong corroboration | confidence becomes `verified` |
| **missing** | normal — disassembly misses patterns; kallsyms lacks some names; BTF lacks some types | **no penalty**; the fact keeps its primary source's confidence |
| **contradicts** | the *derivation* picked the wrong object, the image is not the one that is running, or the domain is wrong | `suspect`: not emitted by default; log both values, their sources and domains, and the object the losing value actually matches. An operator override emits the value with a comment in the profile header — no other state |

Why missing is not a failure: a disassembly-derived value is a real number from the real bytes;
its failure mode is being *absent* (pattern not recognized — the `add`/`RegisterOrSP` scanner bug
made references invisible, not wrong), *misattributed* (right number for the wrong object), or
*dead* (an alternatives block or a vendor path that never executes — the diting `+0x5f8` probe).
A contradiction therefore says "one of these two is describing something else", not "the witness
is wrong".

Consequence for confidence: **geometry facts can never be statically `verified`.** They have no
per-image witness; their verification is a running kernel (QEMU frame cross-check, device gate).
That is already how the project treats them; the fact model just states it.

## Coupled groups

Resolved as a unit, one primary source per group:

- **waiter layout** — `{tree node kind (plain rb_node vs rt_waiter_node), tree/pi offsets, task,
  lock, prio offset, wake_state offset, ww_ctx presence, compact flag, prio packing}`. This is
  the group behind `is_compact_waiter_family()` (extractor) and `compact_waiter_has_wake_state()`
  (native). A vendor backport makes the release a wrong primary; BTF makes it right.
- **cred layout** — `{usage width, uid offset, gid/suid offsets, security offset, caps
  offset/count, copy size, ref fields}`. Behind the W1p `+4`, the W2 repair `+8`, and the
  hardcoded 6.x template (`caps_offset=48`, `copy_size=136`).
- **rt_mutex layout** — `{sizeof(rt_mutex) (the anchor pitch), waiters/owner offsets,
  wait_lock}`.
- **route geometry** — `{shift, waiter shape, strip budget, feasibility}` — one decision from one
  disassembly pass.
- **physical placement** — `{kernel_phys_load, phys_offset, KIMAGE base}` — one derivation; the
  three must agree with the Image's own section symbols (`_text`/`_stext`, `_sdata`, `_end`).

A profile that mixes members of one group from different sources (e.g. BTF waiter offsets with a
release-derived compact flag) is invalid even if every individual value happens to be right.

## Fact inventory — what is derivable and who consumes it

| fact | domain | current source | better source | consumer |
|---|---|---|---|---|
| task_struct 15 fields | field offset | BTF (done) | — | profile |
| `rt_mutex_waiter` task/lock/wake_state/ww_ctx | field offset | **BTF (stage 3: `waiter_layout` emitted)** | — | select branch (`compact`/`wake_state`); multicast geometry keeps its route keys |
| waiter tree kind / offsets / prio packing / compact flag | field offset + layout | **BTF (stage 3 emitted+consumed); release fallback** | — | select branch, prio word |
| `cred.usage` width, `uid`, `security`, `sizeof` | field offset / size | **BTF (stage 3 emitted+consumed); 6.x template fallback** | — | W1p/W2 uid repair, cred-copy bounds |
| `sizeof(rt_mutex)`, `rt_mutex_base` offsets | size / field offset | **BTF (stage 3 emitted+consumed); family 32 fallback** | — | anchor stride lower bound |
| `thread_info.flags` offset | field offset | **constant** | **BTF** (embedded thread_info) | W3 TIF_SECCOMP target (later sub-stage) |
| `seccomp.mode` / filter offsets | field offset | constant (BTF resolved, unused) | BTF | W3 seccomp targets (later sub-stage) |
| enum values (`TASK_NORMAL`, `WAKE_FLAG_*`, `TIF_*`, `RT_MUTEX_HAS_WAITERS`) | enum | **constants** | **BTF enum** | waiter words, PI |
| `selinux_state.enforcing` offset | field offset | assumed 0 | BTF | W1 target |
| `nf_logger` element size/layout | field offset / size | **constant ×8** | BTF | slide anchor math |
| symbol offsets (`init_task`, `init_cred`, loggers, zero page) | symbol address | kallsyms (done) | — | profile |
| pselect/futex frames, shift, route verdicts | frame depth | disassembly (done) | — (device/QEMU witness) | route |
| SLUB stride | slab stride | device measurement (done) | — | spray |
| physical pair | physical | iomem **with the two bugs above** (to be removed) | bootloader metadata (xbl/uefi/vendor_boot/DTB) → `--phys` → compiled default | profile |

## Failure policy

- A missing best source falls back **with its label**, never silently: the profile carries the
  value and the extraction log records `source` and `confidence` per key.
- A contradiction marks `suspect`; by default the extractor does not emit the value. An operator
  override at generation emits it with a plain **comment in the profile header** naming the key,
  the value used, the conflicting value and both sources — no source flag, schema key or run-log
  state. The comment is human-readable only: the app's HOCON parser ignores it and its editor may
  drop it on re-save, so it is an audit trail, not machine state.
- A `heuristic` fact (family default on a release that does not match the template) may be
  emitted but must be visible in the log and the profile header; the app's existing
  "unverified candidate" surface already reads this kind of state.
- Operator values are emitted as ordinary values; the extraction log records them as
  `operator-supplied, not derived`, and they are never counted as verified. No profile flag is
  added for them — the same rule as a conflict override.

## Exposing a conflict

A conflict (same image, same domain, two values) is shown at generation in one sentence — the
key, both values and both sources — with the full record (member names, anchor sites, type IDs)
behind a details view. The user chooses: accept the primary value (recorded as the header comment
above), attach the image that resolves it, or stop. A `wrong_image` identity failure is not a
choice: it refuses and names the identity field that differs. Missing witnesses are never shown;
an invalid cross-domain comparison is an extractor bug, not a user choice.

The comment is the only persistence. No source enum, wire key, run-log field or pre-run gate is
added; if a machine consumer ever needs the state, the additive-key rule below applies.

## Emission and compatibility

- The profile's HOCON shape does not change in stage 1: provenance lives in the extraction log
  and `--explain` on stderr (a file sidecar and profile header comments are later stages).
  Conflict records are comments too, not keys.
- Stage-3 profile keys are **additive and optional**: `cred.usage_size`, `cred.uid_offset`,
  `cred.security_offset`, `kernelsnitch.rt_mutex_size`, and
  `waiter_layout.{compact,pi_tree,task,lock,wake_state}`. The extractor emits them only from BTF;
  absent key = today's behaviour (release parsing / constants), so existing profiles and old
  extracts stay byte-identical. `thread_info_flags` and `seccomp_mode_offset` were not derived by
  stage 2 and remain a later sub-stage.
- The wire schema digest covers declared keys; the golden re-freeze is part of the change that adds
  each key, and both sides (Kotlin `entries()/apply()`, native `OPT`/`PLAIN`) ship together.

## Testing

Four levels; the last is the only one that proves the model.

1. **Unit — the model itself.** `Fact<T>` and the comparison engine:
   - a cross-domain comparison is a type error (or fails `expect_same_domain()`), so the
     `sizeof(mm_struct)` vs slab-stride class cannot silently compare;
   - precedence per class: a synthetic source table yields the expected winner and confidence
     label, including `heuristic`/`default` when the per-image source is absent;
   - witness policy: agree → `verified`; missing → confidence unchanged; contradict (same image,
     same domain) → `suspect` and the coupled group blocked; identity mismatch → `wrong_image`;
     an invalid comparison → hard error, never `suspect`;
   - emission: a `suspect` fact is not written by default; an override writes the value plus
     exactly one comment line, with no new key and no other state;
   - coupled groups: one suspect member blocks the group; mixed primaries are rejected.
2. **Corpus regression.** The 69 image files already on disk (42 extracted + 27 OTA boot
   images):
   - the code-start survey becomes an expected-value table (`_text` on 5.10 and 6.12.69,
     `_stext` on 5.15/6.1/6.6 and 6.12.23/30/38), including the 6.12.30 vs 6.12.69 pair — a
     release predicate fails it by construction;
   - BTF-derived layouts (cred, waiter, `rt_mutex`) asserted per image by
     `tests/layout_facts_ondevice.rs`; 5.10.236 is the no-BTF control and must reproduce today's
     emitted values through the labelled template;
   - every generated profile compares with its existing ground truth; stages 1–2 leave the
     values byte-identical (labels and comments only) and the wire digest unchanged; stage 3
     adds optional keys and re-freezes the digest and the native-document hashes;
   - the QEMU corpus is the runtime witness behind the store (2026-10-29): 26 boots, 25
     candidates, all checkable offsets and all 24 carried anchors exact, strides 960/1024/1280
     by family. `tests/families_ondevice.rs` reproduces every golden (24 entries; the patched
     6.12.69 has none). The bundled 6.x `empty_zero_page = null` is a bundle-regeneration item,
     not an image fact.
   - stage 3: the extractor `report` test asserts the new keys appear only when BTF supplied
     them, and that a no-BTF 5.10 profile has none; `profile_binary_test` round-trips the keys
     and checks the native accessors; `NativeProfileDigestTest` round-trips them and pins the
     re-frozen digest; `NativeDocumentEquivalenceTest` pins every builtin document's new wire
     hash; `families_ondevice` now compares the `waiter_layout` block too. The regenerated
     6.x/5.15 store goldens carry the keys; the bundled assets do not yet, and the native
     release fallback covers them.
   The image bytes stay out of the repo: the corpus test is env-gated on the image directory and
   the expected tables are tracked text.
3. **Contradiction fixtures — the failure paths, not the happy path.**
   - CPH2723 cred: template 4-byte vs BTF 8-byte on 6.6.66 — assert `suspect`, group blocked, and
     the report names `uid` as the member the losing value matches;
   - 6.12.69 code start: the image says `_text`; assert the per-image value wins and no release
     predicate exists to override it;
   - foreign image: the 6.6.66 image with a 6.12.23 kallsyms/BTF must produce `wrong_image`, not a
     value dispute;
   - a deliberate sizeof-vs-stride comparison must fail as invalid, not produce a mismatch;
   - an override fixture asserts the exact comment line and that the parsed values are otherwise
     unchanged; the HOCON parser still parses it.
4. **Device — geometry and the chain.** With the two phones in hand:
   - CPH2723 (6.6.66) and myron (6.12.23): parse their own `boot.img`, compare the image's BTF
     layout groups against the running kernel's `/sys/kernel/btf/vmlinux` (a same-domain oracle),
     then run the chain with the generated profile — the existing gates, unchanged;
   - diting 5.10 (no BTF): `missing` must cost nothing; the emitted profile must stay
     wire-equivalent to the bundled one (digest match) and the select route must still complete;
   - QEMU remains the only witness for frame geometry (the frame cross-check), since no static
     source can be.

Gates: `cargo test` (unit + the env-gated corpus test), a zero-warning release build, the app's
Gradle tests; `cmp_disasm` is required for stage 3's route/cred changes (baseline: the shipped
`1414f4f8…` native; read the per-target instruction counts and ignore the known missing
`multicast_*` control failure). The profile **golden is re-frozen only when a change adds a key**,
never for a comment; stage 3 re-froze the schema digest (`0x6a327466c48683db`) and the
native-document hashes. Device result (2026-10-29): both the 6.6.66 OnePlus and the 6.1.138 POCO passed the anchored
select chain; the 6.1 keyguard is a none-secure swipe (no PIN) and `wm dismiss-keyguard` is the
reliable unblock. The 6.1 `caps_offset`/`copy_size` were the bundle item; item 6 fixes them.

## Staging

1. **Fact model + explain (no behaviour change) — implemented 2026-10-29.** `src/fact.rs`
   defines `Fact<T> { value, domain, source, confidence }`, the `Domain`/`Source`/`Confidence`
   enums and the cross-domain guard. `--explain` prints one row per derived profile key to
   stderr (constant header keys omitted), and the profile bytes are unchanged.
2. **The three facts that already bit us, from BTF — implemented 2026-10-29.** `src/layout.rs`
   derives `rt_mutex_size` (`sizeof(rt_mutex)`), the waiter branch (`rt_mutex_waiter.prio` is
   present on the compact shape) and its field offsets, and the cred `usage` width / `uid` /
   `security` / cap run / copy size. Release logic remains the labelled fallback (family pitch
   32, family waiter offsets, the 6.x template). The facts are `--explain` rows and comparison
   warnings; the profile is unchanged. `tests/layout_facts_ondevice.rs` pins the per-family BTF
   values over the corpus. **Finding:** the hardcoded 6.x template matches 6.6/6.12 (usage 8,
   caps 48, copy 136) but not 6.1 (usage 4, caps 40, copy 128) — the template is 6.6/6.12-shaped;
   the 6.1 warning is now visible whenever a 6.1 image is parsed.
3. **Native consumes the new keys — implemented 2026-10-29.** The extractor emits
   `cred.usage_size` / `cred.uid_offset` / `cred.security_offset`,
   `kernelsnitch.rt_mutex_size` and `waiter_layout.{compact,pi_tree,task,lock,wake_state}` only
   when BTF supplied them, so 5.10/no-BTF profiles stay byte-identical. The Kotlin codec and the
   native transport carry them as optional keys. The native uses `usage_size` in the cred-copy
   bounds, `uid_offset` for the W1p/W2 `init_cred` uid repair (the 6.6.66 vendor backport),
   `waiter_layout.compact`/`wake_state` for the compact-waiter branch, and `rt_mutex_size` as the
   anchor stride's lower bound. The wire schema digest is re-frozen
   (`0x6a327466c48683db`); the native-document golden is re-frozen; 5.10 generated profiles are
   byte-identical. Host gates: extractor 100 unit + the 5.10/cross-family tests, profile-core,
   native host suite, app 149 with only the known `ProfileMigrationEquivalenceTest` fixture
   failure. The 6.1 caps/copy template mismatch was left to item 6; this stage does not change
   existing caps/copy values. **Device gate 2026-10-29:** the OnePlus CPH2723 (stock 6.6.66)
   passed the anchored select chain with the new keys — `W1p`/`W2` repaired at `init_cred+8`,
   anchor slots 8..15, every route call `clean=1/1`, `native exited code=0`, `KernelSU ready`.
   The device exposed one app-side gap: `ProfileResolver.KnownTopLevel` had to learn the
   `waiter_layout` block (fixed with a test; APK `21678e23…`). The POCO duchamp (6.1.138) also
   passed after its none-secure keyguard was dismissed with `wm dismiss-keyguard` (the phone has
   no PIN; the earlier "blocked" reading was an automated swipe that opened Settings): `compact=1`,
   `W1p`/`W2` at `init_cred+4`, anchor slot 0, `slabinfo 1024`, `native exited code=0`,
   `KernelSU ready`. The 6.1 `caps_offset`/`copy_size` were still the 6.x template's 48/136 (BTF
   40/128); item 6 fixes them.
4. **App validation — implemented 2026-10-29.** `ProfileResolver.validateLayoutGroups` (shared by
   the app and the exporter) enforces the cred/waiter/rt_mutex value groups; the generated profile
   header carries one `# fact_sources:` line with each fact's source/confidence; the identity
   check (`ProfileMerger.requireIdentity`) refuses a foreign layer before the device uname is
   stamped; the controller surfaces an external selection for another release instead of silently
   using the bundle. Tests: the coupled-group cases, `ProfileMergerTest`, the updated
   `ProfileLayerPolicyTest`. The 6.6.66 profile passes. The first cred bound was
   `copy == security+8`, which flagged the 6.1.138 profile (136 vs the BTF 128) and found the
   bundle defect; the final bound is `copy >= security+8`, because 5.x places
   `user`/`user_ns`/`ucounts`/`group_info` and the rcu head after `security` and its copy is
   `sizeof(cred)` (176). The invalid-path validator still bounds every declared ref/cap.
5. **Tests and gates — implemented 2026-10-29.** The fixtures: the 6.6.66 BTF usage/uid (8/8) and
   the 6.1.138 security/caps (+120/+40) warnings in `families_ondevice`; the code-start survey
   test (6.12.30 `_stext` vs 6.12.69 `_text`); the existing sizeof-vs-stride refusal; the operator
   `--phys` header comment; the foreign release. Gates: extractor 103 unit, code-start, codegen
   45 s, families 77.5 s, 5.10 99.5 s; profile-core (16 resolver tests); app 149/1 known; APK
   `98f80f5a…`. Device: the OnePlus 6.6.66 home is `受支持` and the anchored chain completed under
   the stage-4 app (anchors 16..23, W1p/W2 at `init_cred+8`); the POCO 6.1.138 is `受支持` and the
   chain completed from the **bundle alone** (item 6).
6. **Bundle fix — 2026-10-29.** A new `credential-6_1.conf` (copy 128, caps 40) is included by
   the 19 6.1 assets and the self-contained 6.1.145 is edited in place; the 5.15 assets keep the
   5.x block (copy 176, caps 48, four refs), because `security + 8` is not `sizeof(cred)` there.
   The extractor's caps/copy override is restricted to the 6.x template block (the 5.x block is
   already per-image: `btf.size("cred")` and the init_cred capability run), and the
   `# fact_sources` header now matches the body on 5.x. The 5.15 store profile is regenerated and
   `families_ondevice` passes. On the 6.1 POCO, with the external selection cleared and a verified
   process restart (the earlier app process had survived `am force-stop`, so its run was not a
   bundle gate), the home is `受支持 / 配置已就绪` and run `20261029-091829` completes the chain
   with `builtin=… (bundled, authoritative)`, the bundle's tcp route `clean=1/1`,
   `exploit complete` at T+20.2 s, `native exited code=0` and `KernelSU ready`.

## Non-goals

- Not the app's document-layer precedence (external > builtin > bundled) — that is a different
  axis and stays as it is.
- Not moving symbol addresses into BTF — BTF has types, not addresses; kallsyms stays.
- Not eliminating release templates — they remain the labelled fallback for no-BTF images
  (5.10 diting) and for facts with no better source.
- Not re-deriving at runtime what the profile already carries; the runtime keeps only the
  measurements that are inherently per-boot (SLUB stride, physical placement).

## Risks

- **Schema churn** on the wire: each new key needs Kotlin + native + golden, and a staged rollout
  must keep old profiles valid (the "absent = old behaviour" rule is the guard).
- **Over-engineering.** The fact inventory is bounded by what the attack path consumes; it is not
  a generic provenance system.
- **Couple-group strictness could refuse a working vendor profile** until a group member is
  derived; the fallback (labelled heuristic) must remain emittable so the current device does not
  regress.
- **BTF parser ambiguity** for anonymous/union members; a member that cannot be resolved
  unambiguously must be `unknown`, not guessed.
- **The no-cross-domain rule** is easy to violate in new code; the fact wrapper should make a
  cross-domain comparison a type error or an explicit `expect_same_domain()` call.

## Open questions

- Is confidence part of the profile document (visible to the app and the user) or an
  extraction-side sidecar at first? The app already surfaces an "unverified candidate" notion;
  reusing it is cheaper than a new document field.
- Where does coupled-group validation live — extractor, app load, or both? (The extractor can only
  validate what it assembled; the app can also validate an operator-edited document.)
- Do operator values carry a "conflicts with derived" state, or only "operator wins"?
- Does the on-device extractor (same crate, no CLI) expose `--explain` in the UI, or only in the
  generation log?
