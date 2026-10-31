# Page-free stack-stamp routes — removing the payload page from select, sigreturn and multicast

Status: **design; Stages 0, 1, 2a and 2b device-gated.** L-level (attack-critical path, profile wire schema, cross
native↔Kotlin↔extractor contract). Operator asked for the plan before any code, 2026-10-29.
**Stage 0 measured 2026-10-30.** 0.1 **FAIL** — the relaxed "non-zero byte" rule is refuted; the
compiled check tests bit 0 of `initialized`, so the odd rule stands. 0.2 **PASS both arms** — the
cred-copy template is dead and `fake_fops` is a boolean, so §5 may drop both (see the §2 *Result*
blocks and `external/port/page-free-stage0/`).
**Stage 1 §3.1 baseline reconciled 2026-10-30**: all nine corpus tests green after two
corrections — the stale 5.10.246 golden (the extractor now emits its multicast anchor triple) and
two pre-fix `anchor_scan` assertions (the 2026-10-27 scanner fixes retired `__log_buf`'s
`Unsafe` and `dump_skip.zeroes`' live reads); the reconciled hashes are frozen in
`external/port/page-free-stage1/golden-hashes.txt`.
**Stage 1 implemented and device-gated 2026-10-30 (diting, build `bea0af05…`): PASS.** The
`selinux` and `w1_scratch` blocks are in the profile, wire and resolver; the extractor emits both
and picks the scratch slot inside the named anchor with the odd-`initialized` rule; the native
writes `data_alias(X) + 0x100` and the anchor allocator reserves the collateral slots. Device
gate: **test arm 5/5 fresh boots completed** with `w1_value_source=scratch` value
`0xffffff802aa3a700` and no acceptance rejection; the page-path control arm also **5/5**. Host:
corpus 9/9, extractor 108 unit, native host suite, profile-core, app 151 with only the known
fixture failure; schema digest re-frozen to `0x28706e4538054d46`. The gate is per image, not per
family: the sampled 6.1.138 profile runs `tcp_zerocopy` (excluded by design) and its serial-port
anchor base admits no in-region scratch, so it stays page-based. The page is still
prepared at this stage (§3.6) — skipping it is Stage 3. Evidence:
`external/port/page-free-stage1/`.
**Stage 2a (select task word) device-gated 2026-10-30: PASS.** The change was already shipped in
`44fe05f8` (both routes stamp `slide_init_task()`); the gate verified it. Test arm **10/10**
fresh boots completed with `init_task->pi_waiters` `0/0` before and after every run and **48/48**
walk-exit samples clean on two instrumented runs; the control arm — same build with only the two
words reverted to `fake_task` — was **0/10**, every run resetting the device at the first W1 select
attempt. Stage 2b (sigreturn) followed, below. Evidence: `external/port/page-free-stage2a/`.
**Stage 2b (sigreturn task word) device-gated 2026-10-30: PASS.** Test arm **9/10** fresh boots
completed (64/64 route calls `clean=1/1`, `drain=0 ms`; the one failure is the known `+0x188`
delivery class); `init_task->pi_waiters` **24/24** read pairs clean and 21/21 sampled walk exits
clean on the completed instrumented run. Control arm — the one-word revert to `fake_task` — was
**0/10**, every run reset at the first W1 sigreturn attempt (`drain=-1 ms` where the store tail
survived). Evidence: `external/port/page-free-stage2b/`.
**Stage 3 (skip the page) implemented and device-gated 2026-10-30: select PASS, sigreturn
rate-fail but mode kept by the operator decision (anchored ⇒ page-free), regression PASS;
multicast PASS on the ksun 236 diting (6/6 page-free, no page prepared).** `page_free_capable` is a route
policy bit and the effective flag is policy ∧ `w1_scratch` ∧ the route's anchor; the page-free
branch skips `prepare_good_kernel_page` and installs the request-derived layout (W1/W1p scratch,
W2 `init_cred`, leaf `target-8`), logging `page_free=1 reason=policy+scratch+anchor` and
`base=0`. Select: **10/10** fresh boots, 80/80 route calls `clean=1/1 drain=0 ms`, 20/20
`pi_waiters` pairs clean, no `[spray]`/prepare/stride line, `exploit complete` T+14.9–15.6 s
(page path T+26–34 s), 48/48 walk exits clean on the instrumented runs. Sigreturn: **6/10**
against the page-based 9/10 — all four failures the known `+0x188` strip-clobber class — so the
pre-registered *rate* fails; the operator decision keeps the mode: an anchored route is page-free
for every route that can support it, with no separate profile switch, and the rebuild is
byte-identical to the gated test build (`e958b36c…`). Multicast **PASS on the ksun 236 diting**:
**6/6** page-free boots completed the whole chain with no page prepared (48/48 multicast calls
clean, T+11.6–14.1 s), the W1 scratch placed in a second safe region — the built-in Samsung
serial driver's dead port array (§3.3 option (a), since both multicast lock anchors fail the
byte-2 parity) — and the 198 arm was dropped by the operator on 2026-10-30 (the device was
given up; the construction, scratch `+0x2c34600`, stays on record but ungated). A
settle-interval amendment would be a sigreturn *rate* experiment, not a mode
decision. Regression: the bundled pre-scratch profile ran
**10/10** with `page_free=0 reason=no-scratch`, `[spray]`/`prepare`/`w1_value_source=page`
present. Evidence: `external/port/page-free-stage3/`.

Supersedes the page-free follow-up named in `multicast-anchor-plan.md` §3 / §6.3; corrects its
§4.4 "W2 cred — yes" row **only if Stage 0b passes** (see §2). The anchor itself is unchanged.

## 0. Definition, scope, and the no-accumulation rule

**Page-free** describes a *run*, not a build: for a profile that carries the required anchors and
selects this mode, `prepare_kernel_page()` is never called, so that run performs no heap spray, no
KernelSnitch leak, no page-acceptance gate and no reclaim-socket work — the chain performs only
stack-stamp and leaf writes against the anchors. Everything stays in the binary: a profile without
the anchors (or a route that needs the page, e.g. tcp) behaves exactly as today, leak and spray
included. There is no global behaviour change and no code path is deleted.

Routes in scope: `select_stack`, `sigreturn`, `multicast_waiter` (anchored branch).
`tcp_zerocopy` is **excluded**: its fake lock is a crafted object (`owner`,
`waiters.rb_leftmost`) that a zero anchor cannot drive — closed 2026-10-28
(`anchor-family-and-tcp-anchor-plan.md`; never reopen as an anchor problem).

**No accumulation of errors.** Every stage below ends in a device gate with pre-registered pass
criteria and is blocked from starting until the previous gate is recorded (host gates may run
ahead; device claims may not). A failed gate stops the plan: it is recorded, the design is
amended, and no later stage's code is built on it. Static analysis proposes; only the device
settles.

## 1. What still consumes the payload page

Inventory of the document line (2026-10-29). "Content" means the kernel dereferences page memory
through a stamped pointer; "address" means only the page's address is used; "sentinel" means a
non-zero guard in userspace.

| # | consumer | routes | where | kind | removal |
|---|---|---|---|---|---|
| 1 | W1 write value `page_base + 0x100` | all routes (backend `w1`) | `payload_write_layout()` | address | §3 scratch anchor |
| 2 | waiter `lock` word | select, sigreturn | route stamp | content (`fake_lock`) unless `lock_anchor_image` | anchor (already present on diting) |
| 3 | waiter `task` word | select, sigreturn | route stamp | **none since `44fe05f8` (2026-10-25)**: both routes stamp `profile::slide_init_task()`. This row was inventoried against the pre-`44fe05f8` line, where the word carried `fake_task` (`page + 0x1280`, "0x400" in the older offset scheme) | already implemented; §4 verifies it on the device |
| 4 | multicast two-word stamp | multicast page branch | `encode_multicast_waiter` | content (`fake_lock`, `fake_task`) | anchored branch (already present) |
| 5 | W2 credential *vehicle* | page-based routes only | page waiter's pi node | content | n/a for anchored routes: the anchored vehicle is the stack-tree erase (`w2-anchored-cred-repair-plan.md`) |
| 6 | W2 `fops` / credential copy | all routes | `util.cpp` fill + route `prepare()` guards | **sentinel** (static audit; confirm §2.2) | §5 drop for page-free |
| 7 | tcp fake lock | tcp_zerocopy | `tcp_zerocopy_route.cpp` | content | excluded |

### 1.1 The W2 audit (static, pending device confirmation)

`fill_profile_cred_copy()` (`util.cpp:317`, called at `:685`) writes a cred template into the
page at `CRED_COPY_OFF` (page 0x200; TCP 0x5980). Its address is stored only in
`heap.current.fake_fops`, which is read only by the routes' non-zero guards
(`select_stack_route.cpp:621,697`, `sigreturn_route.cpp:478,536`,
`tcp_zerocopy_route.cpp:220`) and ignored by `payload_write_layout_matches_request()`. No stamp,
no zc struct and no fake-task field carries that address. History agrees: since
`e83da92e^:src/core/main.c:473` the W2 value is `data_addr(init_cred)` for `mode == 2`, and
upstream `main` is identical — the template was never the written value in the available history.

Conclusion (to be settled by §2.2, not by this paragraph): the fops/cred-copy path is a sentinel
plus a dead fill, and the anchored routes have **no** W2 content dependency. If Stage 0b refutes
it, a W2 page-free vehicle becomes its own stage and §4.4 of the multicast anchor plan stands.

## 2. Stage 0 — measurements and pre-registered decisions

All on the diting 236 rig (stock kernel; the installed app and its external 960 select profile
are the control; test builds installed over, reverted after). Each experiment is a **test build**
carrying the minimal patch; the patch and the build hash go in the evidence dir, and the release
line never carries the patch.

### 2.1 The W1 acceptance predicate (`accepts_page`)

The gate must test the byte of the write value that lands on `selinux_state.initialized`, and
that byte is **not the same across families**. Corpus audit, 2026-10-29
(`tools/extract_rs/examples/selinux_layout.rs`, BTF where present; the 5.10 images carry no BTF,
so their row is the source + device-config layout):

| family (images) | BTF | `enforcing` | `checkreqprot` | `initialized` | value byte on `initialized` |
|---|---|---|---|---|---|
| 5.10.236 / 5.10.198 / 5.10.246 | none | 0 | 1 | 2 | **2** |
| 5.15.194 | yes | 0 | 1 | 2 | **2** |
| 6.1.25 / 6.1.138 | yes | 0 | 1 | 2 | **2** |
| 6.6.30 / 6.6.66 / 6.6.102 | yes | 0 | absent | 1 | **1** |
| 6.12.23 / 6.12.38 / 6.12.69 | yes | 0 | absent | 1 | **1** |

`initialized` is a one-byte bool on every image; `enforcing` is at offset 0 and `disabled` is
absent everywhere, so the target-symbol assumption holds. The 6.6/6.12 shift means the shipped
hardcoded byte 2 (`((right >> 16) & 1)`) checks `policycap[0]`, not `initialized`, on those
families — harmless only because the page value `page_base + 0x100` always leaves byte 1 = 0x01
and byte 1 is `initialized` there. The gate therefore wastes about half the prepared pages on
6.6/6.12 for an unrelated bit.

The corrected predicate is family-aware: **the byte at the profile's `initialized` offset must be
non-zero**. The offset is carried in the profile as a field-offset fact — a new `selinux` block
(§3.5): `initialized = 2` on 5.10 (release template, no BTF), 2 via BTF on 5.15/6.1, 1 via BTF on
6.6/6.12 — with `enforcing = 0` and `disabled` absent validated, and the extractor failing closed
if either changes. Profiles that predate the block fall back to a release-derived offset (2 below
6.6, 1 from 6.6), so they behave correctly and remain the page-path control.

- Patch: `accepts_page` takes the offset from the profile and accepts when that byte is != 0; one
  log line prints the target byte of the accepted value (the release line keeps neither).
- Procedure (diting, 5.10, offset 2): fresh boot; anchored select chain; W1 must land on a page
  whose byte 2 is **even and non-zero** (from that log line); W2 and W3 must then complete;
  ≥3 fresh-boot runs.
- **Pass**: the relaxed rule ships for the families with `initialized` at 2 (5.10/5.15/6.1); the
  scratch filter becomes `byte(initialized_offset) != 0`. **Fail** (SID-lookup-shaped failure at
  W2, or failure only on even-byte runs): the odd rule stands for those families, and the scratch
  extractor requires bit 16 = 1 there.
- 6.6/6.12 need no test of the old rule: with `+0x100` byte 1 is fixed at 0x01, so `initialized`
  is never at risk there; one regression run on a 6.6 or 6.12 device confirms the chain after the
  gate stops checking `policycap[0]`.
- Either result is recorded with the observed values.

**Result (2026-10-30, diting 236, test build `c80b067f…`): FAIL.**

- Run `20261029-235007` accepted `byte=0x0c` (even, non-zero — exactly the newly-admitted class),
  the route reported `clean=1/1`, and the kernel then took the `initialized == false` arm on every
  SID lookup (`security_sid_to_context_core: called before initial load_policy on unknown SID
  1786`); the box reset at ~367 s. The run store was left `state=running`. Evidence:
  `external/port/page-free-stage0/stage0-1/run-1/`.
- Mechanism, and why the premise was wrong: the compiled check is a **bit-0 test**, not a
  non-zero test — `add x8,x23,#0x2; ldarb w8,[x8]; tbnz w8,#0x0` in the exact-config 5.10.236
  build (same source/config/compiler as the stock Image). `initialized` is a C `_Bool`; writing a
  byte > 1 into it is undefined behavior, so LLVM assumes 0/1 and tests bit 0. Any even byte
  reads as false. The shipped `((right >> 16) & 1) == 0` rule was testing exactly this bit on the
  offset-2 families; it was right, and for the right reason. Disassembly and DWARF:
  `external/port/page-free-stage0/stage0-1/disasm-initialized-check.txt`.
- **The fail branch applies**: the odd rule stands for 5.10/5.15/6.1; the corrected family-aware
  predicate is `bit0(byte(initialized_offset)) != 0` (which on 6.6/6.12 is byte 1, fixed at
  `0x01`/`0x81` by `+0x100`, so always satisfied). The §3.4/§3.6 scratch requirement becomes:
  the scratch's `initialized` byte must be **odd**, i.e. on the offset-2 families the scratch
  address's bit 16 must be 1 (`value = alias + 0x100`, byte 2 = address bits 16–23).
- A second run (`20261030-000106`) is not a data point: Android's phantom-process trimmer
  SIGKILLed the native during the spray (`code=137`, `am_kill … Trimming phantom processes`).

### 2.2 The W2 fops/cred sentinel

Two independent test builds, each with the control chain as its baseline:

1. **Poison**: `fill_profile_cred_copy` writes `0xAA` instead of the template. If W2 still
   verifies attempt 1 (`child uid = 0`, `child is root!`) and the chain completes, the copy is
   dead.
2. **Sentinel**: `fake_fops = 1` (non-zero, not an address) for credential writes. If the guards
   pass and the chain completes, `fops` is a boolean.

**Pass** (both): §5 drops the fill and the guard; the anchored routes are page-free at W2.
**Fail** (either): the plan gains a Stage 3b to find the real reader/vehicle; §1.1 and the
multicast anchor plan's W2 row stay as written.

**Result (2026-10-30, diting 236): PASS both arms.**
- Poison build (`apks/stage0-2-poison.apk`, `7b1158c7…`): `fill_profile_cred_copy` fills the
  credential-copy region with `0xAA`. Run `20261030-001408`: W2 attempt 1 verified (`W2: cred` →
  `W2: init_cred uid repair` → W3-0), `exploit complete`, `native exited code=0`, `KernelSU
  ready`. The template is dead.
- Sentinel build (`apks/stage0-2-sentinel.apk`, `12e483c2…`): `fops = 1` for credential writes.
  Run `20261030-001648`: the guards passed a non-address fops and W2 attempt 1 verified; the chain
  completed. `fops` is a boolean.
- Evidence: `external/port/page-free-stage0/` (`stage0-2-poison/run-1`, `stage0-2-sentinel/run-1`).
  §5 may stop calling `fill_profile_cred_copy` and drop the fops guard; the anchored routes have
  no W2 content dependency on the page.

**Stage 0 exit:** 2.1 and 2.2 reported in the evidence dir; Stage 1 freezes its initialized-byte
rule and W2 scope from these results and only then. The leak-address distribution needs no
separate experiment: every gate run logs the prepared value (rejected pages already print their
base; §2.1's patch logs the accepted value's target byte), so the retry-sampler question — are
successive prepares independent draws? — is read from the stage series' logs, failed and crashed
runs included. A clustered per-boot byte means retries are not a lever; a spread means they are.
It gates nothing.

## 3. Stage 1 — the W1 scratch anchor

### 3.1 Golden baseline and full-corpus regression (before any extractor change)

The extractor change is tested against the golden corpus, and the protocol starts by repairing the
baseline, not the code:

1. **Reconcile the goldens first.** With the *current* extractor, regenerate every image in
   `external/test-kernels/` and diff against its golden (`profile.conf`, `profile-<route>.conf`,
   `qemu-anchored.conf`, selected by `meta.txt`'s `profile_provenance`). Every mismatch is
   resolved before the extractor is touched, on the provenance ladder — device-verified > QEMU
   crosscheck > derived — and the fix lands on whichever side the evidence says is wrong (a stale
   golden is corrected, an extractor bug is fixed and recorded). The reconciled set is frozen with
   a hash list in the evidence dir. A golden set that already disagrees with the extractor cannot
   measure a change.
2. **Baseline snapshot.** Record each image's golden hash and the current extractor output.
3. **Full-corpus regression after the change.** Regenerate every image and compare:
   - existing keys must be **byte-identical** (offsets, task/cred fields, geometry, route and
     anchor decisions) — no drift from the schema/emitter work;
   - the new keys (`selinux.*`, `w1_scratch*`) must be present/absent exactly as derived, with the
     fail-closed checks firing where a premise or witness is missing.
   Tests: `GHOSTLOCK_IMAGE_DIR=external/test-kernels cargo test --test ondevice_profile`
   (`Image-5.10.*`) and `--test families_ondevice` (`Image-5.15.*` / `6.1` / `6.6` / `6.12`), plus
   the rest of the suite (`layout_facts_ondevice`, `structs_ondevice`, `route_verdicts_ondevice`,
   `codegen_ondevice`, `code_start_ondevice`, `btf_truth_ondevice`, `anchor_scan`). The app-side
   wire digest and golden documents are re-frozen in the same pass.

**Gate:** every store image matches its reconciled golden for the pre-existing keys, all tests are
green, and the new keys validate on every family. Any drift blocks the Stage 1 device gate; an
image without a golden is recorded as such, never silently skipped.

### 3.2 What it is

A second anchor: a zeroed, writable, kernel-mapped region used as W1's write **value** and as
the erase's collateral scratch. The value is the region's address (via `data_alias`), chosen so
that storing it over `selinux_state` leaves `enforcing = 0` and `initialized` admissible:

- value % 256 == 0 (byte 0 = 0x00 → `enforcing = 0`);
- the family's initialized byte admissible per §2.1 (the byte at offset 2 non-zero, or odd
  otherwise, on 5.10/5.15/6.1; the byte at offset 1 fixed by `+0x100` on 6.6/6.12);
- the collateral (`value + 8`, and the compare at +16) stays inside the region;
- the hole is reserved: it is never handed out as a lock slot and no live object reads it.

The scratch's safety criterion is weaker than the lock anchor's: the kernel only *reads and
writes* the 0x18 bytes at `value`, it does not dereference them. "Zero, writable, reference-free"
remains the conservative selection rule.

### 3.3 Sourcing the region (the first open design question)

The diting's lock anchor is `dump_skip.zeroes` `+0x2a3a590`, 0x1000 bytes = 128 slots of 0x20 —
fully consumed by the rotating lock slots (run-09 used slots 0–8 in one chain). Options:

- **(a) a second safe region** — preferred; the anchor scan (`anchor.rs`, `bss_scan`/`bss_xref`)
  must be run on every target image and the result recorded. The diting may not have one.
- **(b) a reserved slot inside the lock anchor region** — one 0x20 slot is enough for the
  collateral; requires the allocator to skip it (`route/lock_anchor.cpp`) and the profile to
  state it. Cost: 128 → 127 slots (64 → 63 on the 198's 0x800 region). The slot must not be the
  one W1's own walk uses.
- **(c) no page-free profile** — the profile keeps the page path; the migration is per-profile,
  never a release default.

The extractor emits the chosen offset; the resolver refuses a scratch that overlaps the lock
anchor's used range (unless it is the reserved slot, declared as such).

### 3.4 Extractor

New emission `w1_scratch_image` (name/placement decided with the schema, §3.5), derived by the
same scan, and the checks:

- in `[__bss_start, __bss_stop)`, not in init sections, zero in the image (BSS) — plus the QEMU
  in-guest read as the witness;
- no references, or only references that do not read/write the 0x18 bytes;
- the `initialized`-byte admissibility at the chosen offset, computed against the family's
  `initialized` offset (§2.1: 2 on 5.10/5.15/6.1, where it varies with the offset's bits 16–23;
  1 on 6.6/6.12, where `+0x100` fixes it at 0x01 so any scratch passes) and with the same
  `data_alias` conversion the native uses; the **alignment premises** (PAGE_OFFSET alignment,
  `kernel_phys_load` ≥ 64 KiB, slide granularity) checked and **failed closed** — if a premise
  does not hold, no scratch is emitted;
- a `--explain` row: `w1_scratch.image` = `(image-offset, disassembly, derived)`; the
  initialized-byte check is a checked predicate, not a separate fact; premises recorded as
  checked.

### 3.5 Profile schema and app

- New optional key(s), recommended as a top-level block `w1_scratch { image = …, … }` because W1
  is backend-level, not route-level. Exact key set to be fixed at review; the lock anchor's
  `route.<route>.lock_anchor_*` trio is the precedent for shape, not for placement.
- **`selinux` block (field offsets, a separate concern from the scratch)**: `selinux { enforcing
  = 0, initialized = N }`. These are `Domain::FieldOffset` facts, not `offset.*` (those are image
  offsets), and they belong to the profile the same way `cred.*` and `task_struct.*` do. The
  extractor emits them from BTF on 5.15/6.x (`Source::Btf`, `Derived`) and from the release
  template on 5.10 (`Source::ReleaseTemplate`, `Heuristic`), validates `enforcing == 0` and
  `disabled` absent, and fails closed when neither witness exists. The native consumes
  `initialized` in `accepts_page` (§2.1) and in the scratch admissibility (§3.4); a profile
  without the block uses the release-derived fallback (2 below 6.6, 1 from 6.6). The resolver
  validates the block (`enforcing == 0`, `initialized < 8`) and the wire digest is re-frozen with
  the rest of this stage.
- `ProfileResolver.KnownTopLevel` (profile-core `ProfileResolver.kt:12`) must admit it; add a
  coupled-group check: scratch must not overlap the route anchor's `[image, image+bytes)` unless
  declared as the reserved slot; the initialized-byte admissibility is not validated here (image
  fact, §3.4).
- Exporter/editor carry the key through; absent key ⇒ page path (old and external profiles are
  the controls in every gate).
- **Parse/export flow**: when the exported profile is page-free — anchored route **and** a scratch
  emitted by the scan — the stride picker (`--probe-stride` / `StrideVerifier`, the leak-only
  rounds that write `kernelsnitch.mm_struct_sz`) is skipped and the field is not required. When
  the route verdict is tcp, or the scan found no scratch (the §3.3 option-c case), the picker
  runs exactly as today. The measured DB may still record a stride for such an image; it is just
  not consumed by the profile.
- **Measured-stride handling for a page-free profile**: no picker is shown (above); the root
  `slabinfo` fact keeps being ingested into the measured DB after completed runs and is
  display-only — recorded for reference, not consumed by the profile.
- Wire schema: optional fields change the binary digest and the golden documents; re-freeze
  both sides and the Kotlin/native round-trip tests as part of this stage. `schema_version`
  stays 1 with optional fields only.

### 3.6 Native and backend

- `payload_write_layout()` gains an explicit value source: page (today) or anchor scratch.
  `value = data_alias(w1_scratch_image) + 0x100` — the same construction as the page value: byte
  0 = 0 (`enforcing`) and byte 1 = 1, which is what keeps 6.6/6.12 safe where byte 1 *is*
  `initialized`; on 5.10/5.15/6.1 the extractor guarantees the initialized byte (offset 2) is
  non-zero, or odd if §2.1's device test refutes the relaxed rule.
- `prepare_good_kernel_page()` is not called when the session is page-free; `heap.current.base`
  stays 0 and `prepare()`/route guards become conditional (§5). At **this** stage the page is
  still prepared for select/sigreturn (they still need `fake_task`), so the only variable is
  W1's value — that isolation is the point of the stage.
- Log `w1_value_source=scratch alias=… init_byte=…` and keep the old `page … even byte` line only
  for page-derived values.

### 3.7 Stage 1 device gate

- Host gate first: §3.1's reconciled full-corpus run must be green (existing keys byte-identical,
  new keys validated on every family).
- Control: current build + external 960 select profile (page path, no scratch).
- Test: same profile regenerated with the scratch; page still prepared.
- Procedure: fresh boot; run the chain; **success = no `page … even byte` line, W1's logged value
  is the scratch alias, the chain completes**, across the same series size as the control.
- Negative control (host): an extractor/validator test with a scratch whose initialized byte
  (offset 2 on the 5.10/5.15/6.1 path) is 0 must be refused; a scratch overlapping the anchor's
  used slots must be refused.
- Fail action: record and stop; the design (sourcing option, initialized-byte rule, or schema) is
  amended before Stage 2.

Evidence: `external/port/page-free-stage1/` with the minimum kit (dmesg-tail, kmsg-polled,
summary; `stream.log` stays on disk).

**Result (2026-10-30): PASS.** Five fresh-boot runs per arm on the diting (build `bea0af05…`,
versionCode 668). The test arm (control profile + `selinux { enforcing = 0, initialized = 2 }` +
`w1_scratch { image = 44279296 }`) completed **5/5**, every run logging
`w1_value_source=scratch image=+0x2a3a600 alias=0xffffff802aa3a600 value=0xffffff802aa3a700` and
no acceptance rejection; the control arm (page value) completed **5/5**, rejecting 0–4 even-byte
pages per run as the shipped predicate requires. `W1 scratch +0x2a3a600 reserves anchor slots
11..12 (window +0x170)` logged on every route call. No gate run's kernel log carries
oops/panic text. Two control-arm boots and one test-arm boot accepted the tap without starting a
run and were retried on a fresh boot (an app-side start flake, recorded in the evidence README;
the kernel log is clean). Per-run numbers:

| arm | run | store | state | `exploit complete` | W1 value source |
|---|---|---|---|---|---|
| test | run-1 | `20261030-010636` | completed | T+29.817 s | scratch `0xffffff802aa3a700` |
| test | run-2 | `20261030-011236` | completed | T+32.965 s | scratch |
| test | run-3 | `20261030-011439` | completed | T+38.182 s | scratch |
| test | run-4 | `20261030-011650` | completed | T+52.468 s | scratch |
| test | run-5 | `20261030-011915` | completed | T+37.655 s | scratch |
| control | run-1 | `20261030-012137` | completed | T+47.584 s | page |
| control | run-2 | `20261030-012355` | completed | T+38.977 s | page |
| control | run-3 | `20261030-012608` | completed | T+47.888 s | page |
| control | run-4 | `20261030-013935` | completed | T+38.558 s | page |
| control | run-5 | `20261030-014724` | completed | T+42.039 s | page |

Details: `external/port/page-free-stage1/`.

## 4. Stage 2 — the waiter `task` word (`init_task`)

Change: select, then sigreturn, stamp `profile::slide_init_task()` into the waiter's `task` word
instead of `heap.current.fake_task`, when the route is anchored. Precedent: tcp (from the start),
multicast-A (4/4 diting, 198 phone W1/W2), and the page waiter already uses `init_task`
(`util.cpp:509`). The documented cost (multicast-anchor-plan §6.2) is real: a walk can take a
real task's `pi_lock`, and a missed dequeue would leave real, persistent pi state behind.

**Implementation status (2026-10-30, before the 2a gate): already shipped.** `44fe05f8`
(2026-10-25, "adopt the clean line's completion protocol") moved both routes' stack-waiter `task`
word from `heap.current.fake_task` to `profile::slide_init_task()` — **unconditionally**, not only
when anchored — for safety and upstream fidelity, not rate. So Stage 2 needs no route change: the
page still lists the task word as a consumer only on the *unmigrated* line. What has never been
measured is the mechanism: whether the anchored select walk leaves information in real task state.
The 2a gate is therefore a device verification with a **reverted test build** as its control:

- **test**: the shipped tree (`slide_init_task()`), the Stage 1-gated APK `bea0af05…` (668).
- **control**: the same tree with only the two select words reverted to
  `heap.current.fake_task` (the pre-`44fe05f8` value) — a test build, never the release line. This
  is exactly the plan's fail-action state, so the comparison answers "does init_task cost rate?".

**Where the word came from, and what it buys.** It is not a 10-25 invention. The 10-14
consumer-drain work traced the *anchored* walk's step [9] (`!rt_mutex_owner(lock)` →
`wake_up_process(rt_mutex_top_waiter(lock)->task)`; `next_lock` = the anchor `0xffffff802aa3a590`,
owner 0) and measured that wake on the stamp's `fake_task` word at **5.378 s per call**, with the
payload page resprayed/freed ~30 ms after the window — a UAF shape, not just latency. The fix
(the two stack stamps → `slide_init_task()`) landed the next day on the pre-clean dev line as
`24ca73a7` (29/29 calls `clean=1/1 drain=0 ms`); the r6 document line never carried it (build
638, `b8d350d`, still `fake_task`); the clean line had it from `9bacaf65`; `44fe05f8` brought it
to the document line **together with the bounded drain**. The rate is unaffected either way — the
10-25 A/B read 6/10 vs 5/10 (p = 1.0), select sat at ceiling — which is why the old builds
*looked* fine: with no bounded drain the 5.4 s wake was simply waited out, UAF window open. With
the drained protocol the same wake is `consumer_stuck`, and the 2a control shows that combination
resetting the device 10/10 at the first W1 attempt. The word is read only on the anchored walk
([9] needs `owner == 0`); on the page path the walked lock's owner is the forged task, so the
word is inert and the page *content* is what matters.

**Why a forged wake is slow (tail measured, inner branch inferred).** Step [9] is real kernel
behaviour: when a walk finds a lock with no owner, it wakes the top waiter's task. With the
stamp's `task` = `fake_task`, that pointer is into the payload page — and by the time the wake
runs, the page has been freed and resprayed (~30 ms after the window), so the kernel takes
`p->pi_lock` and evaluates the wake fast-path (state bits, on-rq/on-cpu, target CPU) on *recycled
memory* dressed as a `task_struct`. Those checks are a few loads that normally exit at the first
test; on arbitrary bytes they need not short-circuit, and the call drops into the scheduler's slow
path on meaningless fields. The record measured the tail exactly — the wake is 100% of the call,
131–186 ms in the arm-d calls, 2.26 s in one, 5.378 s worst — but did not isolate the internal
branch that consumed it. With `init_task` the pointer is a real, permanent task whose state is
`TASK_RUNNING`, so `try_to_wake_up` exits at its first state test and the call returns in
microseconds (29/29 `drain=0 ms` in the 10-14 series; 80/80 in §4.1). The page path never reaches
[9]: its lock's owner word is the forged task itself, so the chain adjusts that owner and never
wakes the waiter's task word.

Two sub-stages, separately gated — select's evidence does not carry sigreturn:

### 4.1 select

- The page is still prepared (so the only variable is the task word).
- Fresh-boot series, **10 runs per arm**, pre-registered before the first boot; success =
  completion rate not worse than the control arm of the same size, with the mechanism check below.
- **Mechanism check:** read `init_task->pi_waiters` (`rb_root.rb_node` and `rb_leftmost`) through
  a kprobe absolute fetcharg (`scripts/sample-pi-waiters.sh`) **before and after every run**, and
  on two instrumented runs through a return probe on `rt_mutex_adjust_prio_chain`
  (`scripts/arm-piw-walk-readback.sh`) so every walk's exit is sampled. Both words must be NULL
  everywhere. Any residue fails the stage, even if the chain completed. On the diting the words
  sit at `init_task` alias `0xffffff802a79be80` + `0x880` / `+0x888` (profile `task_struct.pi_waiters`
  = 2176; the alias is boot-invariant — `data_alias` of a fixed physical address).
- Include natural failures in the series (they are the interesting walks). Watch for stalls and
  wedges; a stall that does not auto-reboot is a failure of this stage regardless of the rate.
- No kprobes are armed during the counted runs; the instrumented runs are recorded separately and
  not counted toward the rate.

**Result (2026-10-30): PASS.** All numbers below are measured; per-run artifacts are in
`external/port/page-free-stage2a/`.

*Rig and provenance.* diting, kernel `5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284`;
`su` available from boot (verified: boot `32c32173…`, `su -c id` at 18.7 s uptime, no run in
flight); `panic_on_oops=1` and `panic=-1` left at their defaults (an oops panics and reboots).
Both arms ran the same profile, `external/port/page-free-stage1/device-gate/test-profile.conf`
(sha256 `e0e8c4a0…`: anchored select, W1 scratch, page still prepared). Readback words:
`init_task` alias `0xffffff802a79be80`, `pi_waiters.rb_root.rb_node` = alias+`0x880` =
`0xffffff802a79c700`, `rb_leftmost` = alias+`0x888` = `0xffffff802a79c708`; clean = both `0x0`.
Probe positive control: `piw-falsify` produced one real `rt_mutex_adjust_prio_chain` call and the
return probe logged one line, `rb=0x0 lm=0x0`, before any run was trusted.

*Arms.* test = APK `bea0af05…` (versionCode 668, native `e0228818…`), the shipped
`slide_init_task()`; control = APK `5b407369…` (668, native `865ed4b8…`), the same tree with
exactly the two select words reverted to `heap.current.fake_task` (`control-taskword.patch`, two
lines: `select_stack_route.cpp` words 8 and 12).

**Test arm, 10 fresh boots (no probes armed).** Every run: `w1_value_source=scratch
image=+0x2a3a600 … value=0xffffff802aa3a700`, anchor slots 0–7 (8 route calls, one slot each),
every `pselect route done calls=1 success=1 status=0 clean=1/1 step=0 errno=0`,
`exploit complete`, `native exited code=0`, `KernelSU ready`, store `state=completed`.

| run | store | state | `exploit complete` | consumer drain | W1 attempt | route calls | anchor slots | pi_waiters pre | post |
|---|---|---|---|---|---|---|---|---|---|
| run-1 | `20261030-022100` | completed | T+39.268 s | 0 ms | 1/15 | 8 | 0–7 | `0x0/0x0` | `0x0/0x0` |
| run-2 | `20261030-022444` | completed | T+33.435 s | 0 ms | 1/15 | 8 | 0–7 | `0x0/0x0` | `0x0/0x0` |
| run-3 | `20261030-022655` | completed | T+35.212 s | 0 ms | 1/15 | 8 | 0–7 | `0x0/0x0` | `0x0/0x0` |
| run-4 | `20261030-022906` | completed | T+33.469 s | 0 ms | 1/15 | 8 | 0–7 | `0x0/0x0` | `0x0/0x0` |
| run-5 | `20261030-023444` | completed | T+45.931 s | 0 ms | 1/15 | 8 | 0–7 | `0x0/0x0` | `0x0/0x0` |
| run-6 | `20261030-024019` | completed | T+34.342 s | 0 ms | 1/15 | 8 | 0–7 | `0x0/0x0` | `0x0/0x0` |
| run-7 | `20261030-024234` | completed | T+33.859 s | 0 ms | 1/15 | 8 | 0–7 | `0x0/0x0` | `0x0/0x0` |
| run-8 | `20261030-024450` | completed | T+33.683 s | 0 ms | 1/15 | 8 | 0–7 | `0x0/0x0` | `0x0/0x0` |
| run-9 | `20261030-024704` | completed | T+36.283 s | 0 ms | 1/15 | 8 | 0–7 | `0x0/0x0` | `0x0/0x0` |
| run-10 | `20261030-024922` | completed | T+34.509 s | 0 ms | 1/15 | 8 | 0–7 | `0x0/0x0` | `0x0/0x0` |

Totals: **10/10 completed**; **80/80 route calls** `clean=1/1` and `drain=0 ms` (8 calls per run);
20/20 read pairs `0x0/0x0`; every read pair on the **same boot id** (no run rebooted the device);
no oops text in any polled kernel sample. run-2's first boot produced no run store (start
refused) and was retried on a fresh boot — not counted.

**Instrumented test runs (walk-exit readback; not counted toward the rate).**

| run | store | state | `exploit complete` | walk exits | non-null | caller classes | pi_waiters pre | post |
|---|---|---|---|---|---|---|---|---|
| instr-1 | `20261030-021617` | completed | T+31.618 s | 24 | 0 | 8 `remove_waiter`, 8 `rt_mutex_adjust_pi`, 8 `task_blocks_on_rt_mutex` | `0x0/0x0` (34.87 s) | `0x0/0x0` (113.31 s) |
| instr-2 | `20261030-021825` | completed | T+29.015 s | 24 | 0 | 8 / 8 / 8 (same three) | `0x0/0x0` (35.16 s) | `0x0/0x0` (113.41 s) |

Totals: **48/48 walk exits read `rb=0x0 lm=0x0`**, all in `libghostlock.so`; both runs completed
on the same boot id they started on.

**Control arm, 10 fresh boots — 0/10, every run reset the device during the first W1 select
attempt.** Driver outcome `reboot` for all ten (the device vanished, then booted with a new boot
id); the run store is left `state=running`.

| run | store | state | driver | consumer drain (where the store tail survived) | last native-log line |
|---|---|---|---|---|---|
| run-1 | `20261030-025206` | running | reboot | -1 ms | `=== W1: SELinux === target=…` |
| run-2 | `20261030-025445` | running | reboot | -1 ms | `W1 scratch +0x2a3a600 reserves anchor slots 11..12` |
| run-3 | `20261030-025739` | running | reboot | — | `W1 scratch +0x2a3a600 reserves anchor slots 11..12` |
| run-4 | `20261030-030030` | running | reboot | -1 ms | `=== W1: SELinux === target=…` |
| run-5 | `20261030-030323` | running | reboot | — | `W1 scratch +0x2a3a600 reserves anchor slots 11..12` |
| run-6 | `20261030-030614` | running | reboot | -1 ms | `=== W1: SELinux === target=…` |
| run-7 | `20261030-030907` | running | reboot | -1 ms | `W1 scratch +0x2a3a600 reserves anchor slots 11..12` |
| run-8 | `20261030-031159` | running | reboot | — | `=== W1: SELinux === target=…` |
| run-9 | `20261030-031452` | running | reboot | — | `W1 scratch +0x2a3a600 reserves anchor slots 11..12` |
| run-10 | `20261030-031746` | running | reboot | — | `=== W1: SELinux === target=…` |

The five `drain=-1 ms` tails are the signature's own: the consumer's call was still in the walk
past the 2 s drain (the forged-task wake the 2026-10-14 work identified), and the route took the
`consumer_stuck` dirty stop. The box then reset within the documented freeze window (the known
~21 s auto-reboot class); no oops text was captured, so the panic signature itself is not
measured here. The boot after the last reset reports `ro.boot.bootreason=reboot` while every
script reboot reports `reboot,shell` — the resets are the device's own.

**Verdict against the pre-registration.** Rate: test **10/10** ≥ control **0/10**. Mechanism:
**20/20** run read pairs and **48/48** walk-exit samples clean. No human-required wedge. So the
shipped `init_task` word is not merely no slower than `fake_task` — with the anchor the old word
is non-viable (10/10 resets at the first W1 attempt), and the anchored select route works because
of the change. `tcp_zerocopy` remains excluded; sigreturn is Stage 2b. Evidence:
`external/port/page-free-stage2a/`.

### 4.2 sigreturn

Same gate on the diting with a sigreturn test profile. Not inferable from 4.1 (different syscall
frame and held locks).

**Result (2026-10-30): PASS.** Rig as 2a (diting, `5.10.236…ab14313284`, `su` from boot, panics at
their defaults). Profile (both arms): `external/port/page-free-stage2b/device-gate/test-profile.conf`
(sha256 `ecf20d97…`) — the 5.10.236 sigreturn profile (`route.sigreturn { waiter_off_sve = 256,
waiter_off_plain = 240 }`, anchor `0x2a3a590 / 4096 / 32`) plus `selinux { enforcing = 0,
initialized = 2 }` and `w1_scratch { image = 44279296 }`; page still prepared. Arms: test APK
`bea0af05…` (668, native `e0228818…`); control APK `26652fd7…` (668, native `e1ea1a7a…`) — the same
tree with `sigreturn_route.cpp`'s `waiter_words(...)` task argument reverted to
`heap.current.fake_task` (`control-taskword.patch`, one line; a rebuild of the restored tree
reproduces `e0228818…`, so the native hash, not the APK md5, is the arm's identity). Readback words
and probe as in 4.1.

**Test arm, 10 fresh boots (no probes).** Every completed run: 7 `sigreturn route done` calls
(`calls=1 success=1 status=0 clean=1/1 step=0 errno=0 stamps=1..7 misses=0`, each `drain=0 ms`,
anchor slots 0–6), `exploit complete`, `native exited code=0`, `KernelSU ready`, store
`state=completed`.

| run | store | state | `exploit complete` | route calls | anchor slots | pi_waiters pre | post |
|---|---|---|---|---|---|---|---|
| run-1 | `20261030-101724` | completed | T+34.453 s | 7 | 0–6 | `0x0/0x0` | `0x0/0x0` |
| run-2 | `20261030-101936` | completed | T+27.177 s | 7 | 0–6 | `0x0/0x0` | `0x0/0x0` |
| run-3 | `20261030-102311` | completed | T+26.177 s | 7 | 0–6 | `0x0/0x0` | `0x0/0x0` |
| run-4 | `20261030-102511` | completed | T+27.515 s | 7 | 0–6 | `0x0/0x0` | `0x0/0x0` |
| run-5 | `20261030-102716` | completed | T+27.937 s | 7 | 0–6 | `0x0/0x0` | `0x0/0x0` |
| run-6 | `20261030-102922` | completed | T+26.583 s | 7 | 0–6 | `0x0/0x0` | `0x0/0x0` |
| run-7 | `20261030-103124` | completed | T+28.346 s | 7 | 0–6 | `0x0/0x0` | `0x0/0x0` |
| run-8 | `20261030-103329` | completed | T+42.079 s | 7 | 0–6 | `0x0/0x0` | `0x0/0x0` |
| run-9 | `20261030-103724` | running | — (1 clean call, then +0x188) | 1 | 0–1 | `0x0/0x0` | lost (reboot) |
| run-10 | `20261030-104019` | completed | T+28.217 s | 7 | 0–6 | `0x0/0x0` | `0x0/0x0` |

Totals: **9/10 completed**; **64/64 route calls** `clean=1/1` with `drain=0 ms`; **24/24** read
pairs `0x0/0x0` (0 residue). run-9's second route call faulted at its first pre-stamp in
`rt_mutex_adjust_prio_chain+0x188` (NULL deref at `0xf`, `x27 = 0xf`, via `__sched_setscheduler`)
— the known clobbered-`waiter->lock` delivery class, not the task word; kernel text
`external/port/page-free-stage2b/device-gate/test/run-9/oops.txt`. Two boots produced no run store
(start refused) and were retried.

**Instrumented test runs (not counted).** instr-2 completed: 21 walk exits, 0 non-null, pre/post
`0x0/0x0` on the same boot, `exploit complete` T+42.1 s. instr-1 died in the same `+0x188` class at
the first pre-stamp with the return probe armed (the call trace shows `kretprobe_trampoline`), so
it is diagnostic, not a rate datum.

**Control arm, 10 fresh boots — 0/10.** Every run reset the device during the first W1 sigreturn
attempt (store `state=running`, driver `reboot`, boot id changed); five runs' store tails show
`drain=-1 ms` (the forged wake past the 2 s drain → `consumer_stuck` stop), the rest died before
the post-stamp line was durable. The boot after the last reset reports `ro.boot.bootreason=reboot`
(no `,shell`). No oops text was captured in the control arm (the box vanished first). Per-run
stores: `20261030-104308/104602/104851/105139/105433/105723/110015/110256/110549/110838`, all
`state=running`.

**Verdict.** Rate: test **9/10** ≥ control **0/10**; mechanism: 24/24 read pairs and 21/21 sampled
walk exits clean; no non-recovering stall. The sigreturn route's anchored walk has the same
result as select's: the shipped `init_task` word makes every call return in `drain=0 ms`, leaves
real pi state untouched, and the pre-change word is non-viable with the anchor and the drained
protocol. Evidence: `external/port/page-free-stage2b/`.

Fail action either sub-stage: keep `fake_task` for that route; the page stays a listed consumer;
the plan records the route as page-based.

## 5. Stage 3 — skip the page (page-free capability)

Only after Stage 1 + Stage 2 (route by route) and Stage 0b pass.

- Native: add `page_free_capable` to the route policy, and the effective flag =
  policy ∧ profile has scratch ∧ profile has the route anchor; log `page_free=1 reason=…`.
- `attack_write`: skip `prepare_good_kernel_page`; routes must not read `heap.current.base`,
  `fake_lock`, `fake_task`, `fake_fops` on the page-free path (§1 rows 1–3, 6 all gone).
- **The slab stride stops being consulted**: `kernelsnitch.mm_struct_sz` has exactly one
  consumer chain — `prepare_kernel_page` → `mm_objs_per_slab` → the `pre`/`spray`/`post` context
  sizing and `KernelSnitchOwner::create` (`util.cpp:463-473,706-718,917`). A page-free profile
  therefore needs no stride, and a page-free run must log no `[spray] mm_struct stride` line.
  The field stays in the schema (frozen wire) and keeps its measured value for the page path
  (tcp, no-anchor profiles); the stride picker remains relevant only there, and the
  generation-side skip is specified in §3.5.
- Route guards: `if (!page_free) { base/lock/fops checks }`.
- W2: stop calling `fill_profile_cred_copy`; keep the credential block in the wire (frozen
  digest; `usage_size`/`uid_offset`/`security_offset` still feed the W1p/W2 repair).
- Evidence: logs show no `[spray]`, no `prepare_kernel_page`, no reclaim; `base=0`.

### 5.1 Device gates per route

- select (diting): fresh-boot series; success = completion rate ≥ control, `init_task->pi_waiters`
  clean after every attempt, no spray lines.
- sigreturn (diting): same.
- multicast (the 198 phone is the reporter's, so the gate ran on the ksun 236 diting): W1/W2
  with the scratch; the W3-0 `comm` limiter is tracked separately and is not this stage's
  criterion. Success = W1 and W2 pass with no page prepared. **PASS 2026-10-30 on the ksun 236
  diting:** 6/6 page-free boots completed the whole chain with no page prepared (48/48 multicast
  calls clean, T+11.6–14.1 s), the W1 scratch in the Samsung serial port array
  (`+0x20b7200`; §3.3 option (a), because both multicast lock anchors fail the byte-2 parity).
  The 198 arm was dropped by the operator on 2026-10-30 (device given up): the same
  construction is on record (scratch `+0x2c34600`) but ungated.
- Regression: tcp and every profile without the anchors still prepare the page; the old
  `page … even byte` line still behaves per §2.1's outcome. The explicit arm for this stage is an
  **anchor-less profile** (bundled pre-scratch, external, or older-extractor): its logs must still
  show `[spray] mm_struct stride=…`, the prepare line and the leak, and its chain rate must match
  the control. That arm is what keeps the stride (`kernelsnitch.mm_struct_sz`), the spray and the
  KernelSnitch alive — the migration adds a configuration and removes nothing.

Evidence: one directory per route, same minimum kit.

**Implementation (2026-10-30, worktree uncommitted).** `page_free_capable` is a static
capability on the route policy (`SelectPolicy`, `SigreturnPolicy`, `MulticastPolicy` true;
`TcpPolicy` inherits the false default), and the effective flag + first missing conjunct are
`route::page_free()` / `route::page_free_reason()`. `attack_write` branches to
`support::prepare_page_free_context()`, which zeroes every page verdict field (`base`,
`fake_lock/w0/task/fops`), resolves W1's scratch value (the same `w1_value_source=scratch`
line the page path prints), and installs the request-derived layout — W1/W1p carry the scratch
alias, W2 carries init_cred, leaf writes carry `target - 8`. The route page guards and the
per-attempt page rebuild are conditional; the multicast W1b repair and the W2 fast-repair
prebuild are skipped on the page-free path (the repair fires as a page-free write instead).
The page path is untouched: the credential fill, the fops sentinel and every spray/leak/
acceptance line stay as they were.

Host gates: native build zero warnings, `lint-tidy`, all host targets (`route_policy_test` adds
the policy ∧ scratch ∧ anchor matrix and the reason strings). Device: the first smoke run
(select, store `20261030-161317`) reads `page_free=1 reason=policy+scratch+anchor`, no
`[spray]`/`prepare_kernel_page`/stride line, `page=0000000000000000` in the route setup,
`w1_value_source=scratch image=+0x2a3a600`, and completes at **T+15.4 s** against the
page-based series' T+26–42 s. The counted series and the regression arm are in
`external/port/page-free-stage3/`.

### 5.2 Result (2026-10-30, diting 5.10.236)

Builds: test build (all three routes capable) packaged native `e958b36c…` (APK `b6d0a185…`);
the interim rollback build `ee68e181…` (superseded — the decision below restores the test build
byte-for-byte); control = the Stage 2a/2b page-based arms (native `e0228818…`). Profiles: select
`e0e8c4a0…`, sigreturn `ecf20d97…`, bundled regression `8ddf27bd…`.

**select — PASS.** Every run `page_free=1 reason=policy+scratch+anchor`, 8 route calls
`clean=1/1 step=0 errno=0 drain=0 ms`, slots 0–7, `page=0000000000000000`, no
`[spray]`/`prepare_kernel_page`/stride line, `pi_waiters` `0x0/0x0`:

| run | store | state | complete | calls | slots | piw pre/post |
|---|---|---|---|---|---|---|
| run-1 | `20261030-161522` | completed | T+15.129 s | 8 | 0–7 | `0x0/0x0` |
| run-2 | `20261030-162054` | completed | T+15.351 s | 8 | 0–7 | `0x0/0x0` |
| run-3 | `20261030-162949` | completed | T+15.356 s | 8 | 0–7 | `0x0/0x0` |
| run-4 | `20261030-163140` | completed | T+15.392 s | 8 | 0–7 | `0x0/0x0` |
| run-5 | `20261030-163909` | completed | T+14.924 s | 8 | 0–7 | `0x0/0x0` |
| run-6 | `20261030-164100` | completed | T+15.452 s | 8 | 0–7 | `0x0/0x0` |
| run-7 | `20261030-164250` | completed | T+15.229 s | 8 | 0–7 | `0x0/0x0` |
| run-8 | `20261030-164440` | completed | T+15.571 s | 8 | 0–7 | `0x0/0x0` |
| run-9 | `20261030-164631` | completed | T+15.363 s | 8 | 0–7 | `0x0/0x0` |
| run-10 | `20261030-164822` | completed | T+15.407 s | 8 | 0–7 | `0x0/0x0` |

Instrumented (not counted): `20261030-170140` and `20261030-170917`, both completed, **24/24**
walk exits `rb=0x0 lm=0x0` each, read pairs clean. Totals: 80/80 calls, 20/20 pairs.

**sigreturn — rate FAIL by rule, mode kept by operator decision (2026-10-30).** 6/10 against the
page-based 9/10. Every run `page_free=1`; the four failures are the known `+0x188` class (faults
`0xc`/`0x11`) at calls 1/4/6/6:

| run | store | state | calls (clean) | complete |
|---|---|---|---|---|
| run-1 | `20261030-173017` | completed | 7 (7) | T+12.593 s |
| run-2 | `20261030-173222` | **running** | 5 (5), crash at 6 | — |
| run-3 | `20261030-173614` | completed | 7 (7) | T+12.409 s |
| run-4 | `20261030-173815` | **running** | 0, crash at 1 | — |
| run-5 | `20261030-174206` | completed | 7 (7) | T+12.839 s |
| run-6 | `20261030-174408` | completed | 7 (7) | T+12.797 s |
| run-7 | `20261030-174603` | **running** | 3 (3), crash at 4 | — |
| run-8 | `20261030-174950` | completed | 7 (7) | T+13.208 s |
| run-9 | `20261030-175152` | **running** | 5 (5), crash at 6 | — |
| run-10 | `20261030-175541` | completed | 7 (7) | T+11.172 s |

Per-call 4/55 vs the control's 1/64 (Fisher p ≈ 0.30); read pairs clean on the six completed
runs; the four resets lost the post-read. The pre-registered fail action (per-route rollback) was
applied and smoked (select `20261030-182652` `page_free=1`/T+15.3 s; sigreturn
`20261030-182903` `page_free=0 reason=route-not-capable`, page lines present), then **superseded
by the operator decision: an anchored route is page-free for every route that can support it,
with no separate profile switch.** `page_free_capable` is back to true on select, sigreturn and
multicast (tcp excluded); the rebuild is byte-identical to the test build (`e958b36c…`), so no
re-gate. Multicast: **PASS on the ksun 236 diting** — 6/6 page-free boots completed the chain
with no page prepared (48/48 multicast calls clean, T+11.6–14.1 s), the W1 scratch in the
Samsung serial driver's dead port array (`+0x20b7200`, value `0xffffff802a0b7300`); the
lock-anchor regions cannot host it (byte-2 parity), so this is §3.3 option (a) in practice.
The 198 arm was dropped by the operator on 2026-10-30 (device given up); the construction
(scratch `+0x2c34600`) is on record but ungated.

Multicast per-run, page-free arm (ksun diting, profile `profile-page-free.conf`, scratch
`w1_scratch.image = 34304512`): stores `20261030-191937` (T+12.812 s), `201418` (T+13.836,
first attempt a cpuset refusal, retried), `195827` (T+13.653), `200316` (T+14.067), `200525`
(T+14.066), `200731` (T+11.591) — all completed, 8/8 multicast calls clean, no `[spray]` or
`prepare_kernel_page`; the smoke `191719` (T+13.612) and the interrupted `194423` also
completed. Page-based control (same kernel, same profile minus the scratch): `20261030-202359`
(T+36.931), `204022` (T+39.970), `204257` (T+42.033), `204813` (T+36.735); two boots never
started after three taps each (harness). The 0x118-byte collateral window
(`0x20b7300..0x20b7318`) read zero through a kprobe before the runs; the array's xref is one
`adrp` in `s3c24xx_serial_probe`, zero init-range hits, and the live DT has no `samsung,*` node.

**Regression — PASS.** Bundled pre-scratch profile, 10/10, every run `page_free=0
reason=no-scratch`, `[spray] mm_struct stride=960 objects_per_slab=34`,
`prepare_kernel_page ok` ×8, `w1_value_source=page`:

| run | store | complete |
|---|---|---|
| run-1 | `20261030-175827` | T+38.531 s |
| run-2 | `20261030-180054` | T+33.307 s |
| run-3 | `20261030-180312` | T+43.141 s |
| run-4 | `20261030-180546` | T+48.274 s |
| run-5 | `20261030-180824` | T+44.576 s |
| run-6 | `20261030-181052` | T+39.957 s |
| run-7 | `20261030-181321` | T+40.074 s |
| run-8 | `20261030-181545` | T+56.068 s |
| run-9 | `20261030-181823` | T+60.239 s |
| run-10 | `20261030-182107` | T+48.129 s |

Multicast: **PASS on the ksun 236 diting** — the flash was approved, done (the ksun Image on
`boot_a`) and restored (`075e3fa2…`); 6/6 page-free boots completed the whole chain with no page
prepared (48/48 multicast calls clean, T+11.6–14.1 s), the W1 scratch in the built-in Samsung
serial driver's dead port array (`+0x20b7200`; the lock-anchor regions fail the byte-2 parity,
so this is §3.3 option (a)). The page-based control on the same kernel started 4/6 (two boots
exhausted the start retries — harness) and every started run completed at T+36.7–42.0 s with
spray/prepare. The 198 arm was dropped by the operator on 2026-10-30 (device given up); the
construction (scratch `+0x2c34600`) is on record but ungated.

## 6. Stage 4 — release surface

- Carry the scratch in the bundled profiles where the derivation exists — the 8 5.10 assets
  (236 device-gated; 209/226 derived on device-proven anchors; 136 derived on a QEMU profile;
  81/101/177/198 second-region) — and stop there: **no new bundled configs** (operator decision
  2026-10-31). The 6.x/5.15 page-free surface is the derivation path (§6.1), not shipped assets.
  Re-freeze the golden documents (the schema digest does not move); the app test line (the known
  `ProfileMigrationEquivalenceTest` fixture failure aside). The store's 35 option supersets are the extractor regression; the seven other store-backed
  suites are green.
- `RELEASE-diting-5.10-r8.md` carries the page-free claim per route and per profile (only where
  the gates in §5.1 passed), and the fact rows.
- Docs: mark the page-free follow-up in `multicast-anchor-plan.md` as scoped here; correct its
  §4.4 W2 row only if Stage 0b passed; add the scratch to `anchor-derivation-plan.md` as a
  second consumer of the scan.

### 6.1 Derive-anywhere generation (revised 2026-10-31)

Operator decisions: the release ships **no new bundled configs**; any user must be able to derive a
page-free profile from their own image on every series. The scratch-source question is therefore an
extractor/parse-flow policy, not a bundle exercise.

- **One pass, one superset document.** A single run emits everything the image yields: every
  feasible route with its verdict and full geometry, every anchor candidate with its scan verdict,
  `conditioned`/`unvetted` policy flag, anchor triple and page-free placement (scratch image +
  reserved slots, or second-region window), and **every** page-free plan plus the page and
  anchor-only plans per route. The extractor omits nothing; the UI applies the display rule
  (one safe option → auto; several safe options → offer, no page; conditional-only → page plus
  the conditioned options). The policy chain is in-anchor pick → `bm_pmd` → `serial8250_ports` (the
  operator's unconditional regions); `s3c24xx_serial_ports` is conditional and enters an attested
  plan only, because its premise is a device fact the app cannot check before W1 — SELinux denies
  `/sys/class/tty`, the driver's sysfs node and `/proc/device-tree` (measured 2026-10-30), and
  root exists only after the chain.
- **Cut, not re-parse.** `(superset, route, plan) → profile` is a pure function; the route dialog
  and the page-vs-conditional prompt both select from the same document, so one parse serves the
  whole flow. The CLI's `--format conf --anchor` follows the same auto plan (it must not disagree
  with the cut); the operator flags (`--anchor-image/bytes/stride`, `--w1-scratch-*`) still
  override for a gate.
- **The only prompt** is page vs the conditional space, and only when the needs-review region is
  the sole page-free source; default page. The exported profile records the source/evidence in a
  header comment.
- **Route preference.** When both `select_stack` and `tcp_zerocopy` are feasible, `select_stack`
  is the recommended/primary option (page-free capable; tcp is excluded by design), tcp the
  alternative.
- **Testing.** The store keeps **one superset per kernel** (`options-<release>.json`) and no
  runnable profiles; the old `(choice, profile)` fixtures retire. The test runs the maximal mode
  (all sidecars, no suppressing flags) and compares the whole document: a nullable field takes the
  valued variant, and a choice among options is listed in the file. The cut is tested separately
  (superset → profile, a sample per family) and against the CLI's `--format conf --anchor`
  (`tests/cut_ondevice.rs`, four plan shapes), as are the prompt/attestation ViewModel cases and a
  device walkthrough parsing 5.10.177/198 without running the foreign profile.
- **Gates** (5 fresh boots each, one device at a time): 5.10.236 diting bundled smoke (2 runs);
  6.1.138 duchamp derived select; 6.6.66 CPH2723 derived select; 6.12.23 myron derived select
  (first exploit run there). 5.15: one corpus image, no device — derivation tested, no claim.

### 6.2 Family scope (audited 2026-10-30)

Page-free is gated by the **route** (select / sigreturn / multicast; tcp excluded), not by the
kernel family. The extractor's anchor and scratch emission is family-agnostic; the family supplies
only `selinux_state.initialized` (BTF: 1 on 6.6/6.12, 2 on 5.10/5.15/6.1) and the named-anchor
preference list (`s3c24xx_serial_ports` first on 6.1). Measured across the store's images:

- 6.6.66: anchor `__dump_skip.zeroes +0x23019c8` (0x1000/32), `initialized=1`, scratch emitted
  (`image` anchor+0x38, slots 9..10);
- 6.12.23: anchor `+0x265fa70`, `initialized=1`, scratch emitted (anchor+0x90, slots 20..21) —
  the same image offset with and without the xbl sidecar, because `+0x100` fixes byte 1 at 0x01
  once the alignment premises hold;
- 6.1 splits per image, not one block. All twelve store images derive the same named anchor
  (`s3c24xx_serial_ports`, 0x1ce0 B) at their own offsets, and the byte-2 residue divides them:
  **five admit an in-region slot** — 6.1.115 (`image` 35874048), both 6.1.118 (35874048 /
  35878144), 6.1.25-g8744d1c0 (34275584), 6.1.75 (35355392) — and **seven refuse**: the three
  6.1.138 images (0x22484e0), 6.1.25-g9f6af9a, 6.1.57, 6.1.78 and 6.1.99. The deciding bit is
  **bit 16 of the anchor's image offset** (byte 2 odd): the in-region offset moves byte 1 only,
  unless the region straddles a 64 KiB boundary and the window sits past the crossing. The
  symbol lands wherever the build's image layout puts it — the twelve anchors span ~0x1a KB — so
  adjacent builds fall on either side of the bit. The sampled device (POCO 6.1.138) is in the
  refuse group, so its page-free needs a second region; the five hits need no such thing.
  The `+0x100` is not the cause: on the byte-2 families a valid value is
  `base + o` with `o ∈ [0, region)` and `value ≡ 0 (mod 256)`, so byte 2 changes only when
  `base_low16 + o` carries past 0x10000. The POCO's base low 16 is 0x84e0 and the region 0x1ce0 —
  no carry, so every in-region offset (any constant, not just 0x100) leaves byte 2 at 0x24. Only
  a region whose base admits the parity (a second region, or a different anchor) removes the
  block; the same arithmetic is why the ksun multicast scratch left `dump_skip.zeroes` for the
  serial array.

What keeps 6.x page-based today is data, not code: no bundled 6.x profile states a lock anchor,
the device-gated 6.1 route is `tcp_zerocopy` (excluded by design), and no 6.x page-free device
gate exists. 6.6/6.12 are the easiest family parity-wise: any anchor admits a scratch.

### 6.3 Second-region candidates (audited 2026-10-30)

Where the in-anchor slot fails (bit 16 = 0), the `.bss` scan plus a QEMU in-guest read of the exact
Images found two regions that are zero at runtime:

| candidate | size | evidence | covers |
|---|---|---|---|
| `bm_pmd` (`arch/arm64/mm/mmu.c`, `__page_aligned_bss __maybe_unused`) | 0x1000 | safe verdict; its refs are the 16K-page early-mapping paths only (`BUG_ON(!IS_ENABLED(CONFIG_ARM64_16K_PAGES))`), never taken on a 4K kernel; QEMU read zero on 5.10.177 and two 6.1.138 Images | 5.10.81/101/177/198; the three 6.1.138 Images |
| `serial8250_ports` | 0x6a00 | needs-review; refs only from the 8250 driver, which binds nothing on these phones — measured on the diting (no 8250/ns16550 node, no `serial8250` platform driver, no `dw-apb-uart`) and the CPH2723 (no `snps,dw-apb-uart` node, `dw-apb-uart` registered with zero device links); QEMU read zero on 6.1.25-g9f6a / 6.1.57 / 6.1.78 | 6.1.25-g9f6a, 6.1.57, 6.1.78 |

None of the three is family-scoped: the corpus scan (42 Images, 5.10–6.12) has
`serial8250_ports` and `bm_pmd` in `.bss` on **every** image, and `s3c24xx_serial_ports` is `.bss`
on 6.1/6.6/6.12 and `.data` on 5.10/5.15 (the symbol is present there too — 5.10.236 at
`+0x28a6eb0`, below `__bss_start`; the anchor scan's `.bss`-only scope is why it looks absent).
What differs per image is section, extent and the bit-16 parity, not the family.

Premises: `bm_pmd` needs 4K pages (on 16K the early-mapping paths run and it is live) — checkable at
run time via the page size and at generation time from the image config; `serial8250_ports` needs
no 8250 device — held by every phone checked (no ISA/PCI UART, no `ns16550a`/`snps,dw-apb-uart`
node, and `dw-apb-uart` registered with zero links where present), but still a device fact rather
than a kernel one; `s3c24xx_serial_ports` needs no `samsung,*` node. Each is already expressible as
`w1_scratch.image` (the native reserves slots only when the scratch lies inside the anchor), and a
device kprobe readback on the target remains the gate before a profile claims one.

## 7. Facts and confidence

| fact | domain | source | confidence | witness |
|---|---|---|---|---|
| `w1_scratch.image` | image-offset | disassembly | derived | QEMU in-guest read of the region; device gate |
| initialized-byte admissibility | checked predicate | disassembly (offset bits) + the field-offset fact below | derived | same |
| `selinux_state` layout: `enforcing`@0, `disabled` absent, `initialized` offset (2 on 5.10/5.15/6.1, 1 on 6.6/6.12) | field-offset | BTF on 5.15/6.x; release template + device config on 5.10 | derived (BTF) / heuristic (5.10 template), **fail-closed when unwitnessed** | BTF in-image (§2.1 corpus audit); device run |
| alignment premises (page offset, load, slide) | image/build facts | config/kallsyms | validated, fail-closed | extractor refusal tests |
| region zero/ref-free | image property | disassembly | derived | QEMU read + device gate |
| `initialized` semantics: **bit 0** of the byte, not "non-zero" | kernel semantics | compiled check (`tbnz #0` on the `_Bool` load) | **measured** 2026-10-30 | device run `20261029-235007` + disassembly |
| page-free effective flag | enum | derived from profile facts + route policy | derived | logged at run start |
| `init_task` task word | runtime-va alias | kallsyms/data_alias | derived | pi_waiters readback (§4) |

Every row above appears in the extractor's `--explain` table or the run log; none is a bare value.

## 8. Risks and open questions

1. **Scratch sourcing** (§3.3): a second safe region may not exist on some images; the reserved
   slot costs one slot and touches the anchor allocator. Per-image scan results decide.
2. **The odd-rule question** (§2.1) is unresolved; the plan carries both branches.
3. **Field drift across families** (§2.1): `checkreqprot` was removed at 6.6, moving `initialized`
   from byte 2 to byte 1; `disabled` is absent on every sampled image but could be compiled in
   later. The predicate must be a profile fact, and the extractor fails closed when it cannot
   witness the layout (no BTF and no template). Profiles without the `selinux` block fall back to
   the release-derived offset.
4. **`init_task` persistence** (§4): a missed dequeue poisons real global state; the pi_waiters
   readback is the gate, and any residue is a stop.
5. **Carrier differences**: select/sigreturn/multicast walks hold different locks in different
   syscall frames; evidence is per route, never pooled.
6. **Schema placement**: top-level `w1_scratch` vs route-scoped; the resolver whitelist and the
   wire digest must be updated together.
7. **Old/external profiles**: absence of the scratch must keep the page path bit-for-bit; this is
   the control in every gate.
8. **The rig's current profile** is external (SAF); Stage 1+ needs a regenerated profile with the
   scratch, exported and re-selected.

## 9. Non-goals

- tcp_zerocopy migration; page-path removal; a W2 credential-vehicle redesign (unless §2.2 fails);
  changing the page gate for page-based profiles beyond §2.1's confirmed outcome; any page-free
  claim for a profile that has not been device-gated — the gate is the profile, not the family.

## 10. Stage gates at a glance

| stage | change | device gate | pass | fail |
|---|---|---|---|---|
| 0.1 | `accepts_page` uses the profile's initialized byte (2 on 5.10/5.15/6.1, 1 on 6.6/6.12) | diting, ≥3 fresh boots on an even-nonzero byte; one 6.6/6.12 regression run | chain completes on both | **OBSERVED FAIL 2026-10-30** (run `20261029-235007`): odd rule stands for the offset-2 families; scratch filters that byte |
| 0.2 | cred copy poisoned; fops = 1 | diting, 1 run each (2 builds) | W2 verifies, chain completes | add Stage 3b; §4.4 stands |
| 1 | scratch anchor end-to-end, page still prepared | host: §3.1 full-corpus golden run green; device: diting select series | W1 value = scratch, no page rejection, chain completes | amend sourcing/schema; stop |
| 2a | select task word = init_task (already shipped in `44fe05f8`; the gate verifies it, control = the word reverted in a test build) | diting series (10/arm) + pi_waiters readback before/after every run and at every walk exit on 2 instrumented runs | **PASS 2026-10-30**: test 10/10 vs control 0/10, pi_waiters NULL everywhere | select keeps fake_task |
| 2b | sigreturn task = init_task (shipped; gate verifies with a one-word revert as control) | diting series (10/arm) + pi_waiters readback before/after every run and at every walk exit on 2 instrumented runs | **PASS 2026-10-30**: test 9/10 vs control 0/10, pi_waiters NULL everywhere | sigreturn keeps fake_task |
| 3 | skip prepare, page-free flag | select + sigreturn on diting; multicast on 198 | select **PASS 2026-10-30** (10/10, no spray/leak, `base=0`, pi_waiters clean, 48/48 walk exits); regression **PASS** 10/10; sigreturn **rate FAIL by rule** (6/10 vs page 9/10, all `+0x188`) but **mode kept by operator decision** (anchored ⇒ page-free, no separate switch); multicast **PASS 2026-10-30** on the ksun 236 diting (6/6 page-free, 48/48 calls clean, no page) via the Samsung-array scratch; the 198 arm was dropped (operator, 2026-10-30) | a rate below control is recorded as such; the mode itself is a design decision (operator, 2026-10-30) |
| 4 | profiles, docs, r8 | release gate | built profiles + notes | — |

No stage starts until its predecessor's gate is recorded in the evidence dir and in this document.
**A result block carries the numbers, not just the verdict**: build hashes and versionCodes, the
profile hash, every run's store stamp and state, the chain timings, the readback values and the
anchor slot sequence — the per-run data is the record, and the evidence dir only backs it.
