# Anchor generation beyond 5.10, and the `tcp_zerocopy` lock anchor

Status: **Part A implemented (2026-10-27); Part B refuted on the device (2026-10-28) and reverted.**
Two Misc items in `PORT-PLAN.md` were merged into one plan because the second was gated by the
first. The device test showed the tcp route's fake lock is a crafted object, not a zero `rt_mutex`,
so a zero anchor cannot carry it — see *B* and *C* below. The scanner/pitch/family-gate work
(Part A) stands.

## Question

1. Can the extractor emit `route.<name>.lock_anchor_*` for families other than the 5.10
   `android12-9` series — 5.15, 6.1, 6.6, 6.12 — and what exactly has to be measured per family?
2. Can `tcp_zerocopy`, the route that actually runs on 6.1, take its fake lock from an anchor
   instead of the reclaimed payload page, so a 6.1 device stops depending on page delivery for the
   lock word?

## Measurements (2026-10-27)

### The pitch is 32 bytes on every sampled family

`lock_anchor_stride` is the family's `sizeof(struct rt_mutex)` — the fake lock's footprint, which
the PI walk reads and writes. Derivation from each image's own embedded BTF (`rt_mutex` /
`rt_mutex_base`, `bpftool btf dump`):
`external/port/anchor-6x-2026-10-27/btf-rt-mutex.txt`.

| family | image | `rt_mutex` size | layout |
|---|---|---|---|
| 5.15 | 5.15.194 | 32 | wait_lock@0 waiters@8 owner@0x18 |
| 6.1 | 6.1.25 / 6.1.78 / 6.1.138 (×2) | 32 | same |
| 6.6 | 6.6.30 / 6.6.77 | 32 | same |
| 6.12 | 6.12.23 / 6.12.69 | 32 | same |

So `ANCHOR_STRIDE = 32` is not 5.10-specific: the struct is 32 bytes and identically laid out on
all four families sampled. The 5.10 image has no BTF, so its 32 stays the measured constant.

### The scanner was under-reporting references — two real defects

`anchor::scan_references` (`tools/extract_rs/src/anchor.rs`) was proved wrong on 6.1 by the
2026-10-21 `duchamp-6.1` record: it reported 0 live reads and 0 live writes for every "safe"
candidate while direct decoding found references. Two root causes, both confirmed by decoding the
actual instructions with the crate's own yaxpeax decoder:

1. **`add` never matches.** yaxpeax renders the operands of `add x9, x9, #0x858` as
   `RegisterOrSP`, not `Register`; the scanner's `Opcode::ADD` arm matches only `Register`, so the
   arm has never fired on any image. Every `adrp; add; ldr [xN]` access is invisible, and on 6.1
   that is the dominant pattern (`adrp; add; umaddl; ldr [computed]`).
2. **Init text is never scanned.** `scan_references` decodes `[text_start, text_end)` only; the
   `init` flag is computed for sites that can never occur. `.init` on 6.1.138 is
   `[+0x1bc0000, +0x1c1cb00)`, entirely outside `text`. A boot-time registration such as
   `drbg_init -> crypto_register_alg` is therefore invisible — and a boot-time write leaves the
   region non-zero, which disqualifies it as an anchor.

After fixing both in a scratch scan (`examples/anchor_use_scan.rs`, evidence
`use-scan-*.txt`), on **6.1.138** no `.bss` candidate has zero references: the best clean prefix is
**2 slots** (`dev_table`, `gicv2m_pmsi_ops`, `mbi_pmsi_ops`, `quirks_param`). The earlier 67-entry
"safe" list was an artifact of the two defects.

### The shipping 5.10 anchor has references too — the criterion is a clean prefix

`dump_skip.zeroes` on 5.10.236 (the shipped anchor) has 11 live **reads** starting at `+0xa70`
inside its 4096-byte extent. It works because the allocator only takes slots from the front: slice
0..0xa60 is untouchable and the run never reaches slot 83. So the operative property is the
**stride-aligned clean prefix**, not "zero references anywhere". Writes anywhere in the prefix are
fatal; reads bound the prefix.

### A 6.1 anchor candidate exists only by dead-code reasoning

The only 6.1 region with a useful size and references confined to code that cannot execute on this
device is:

| item | value |
|---|---|
| symbol | `s3c24xx_serial_ports` |
| image offset | `+0x22484e0` |
| extent | `0x1ce0` = 12 × `0x268` (`struct s3c24xx_uart_port`) |
| slots at 32 | 231 |
| references | `s3c24xx_serial_probe`, `s3c24xx_serial_console_setup` only |
| device DTB | no `samsung,s3c*` compatible in `vendor_boot` (the only Samsung strings are the AMOLED panel) |

The Samsung S3C serial driver is built in but cannot bind on a MediaTek POCO, so the array should
stay zero. This is a **device-gate candidate, not a validated anchor**: static analysis cannot see
indirect or indexed access, and "the driver never probes" is an inference from the DTB.

## Design

### A. Anchor generation beyond 5.10

**A1 — scanner correctness (mandatory, no behaviour unlock).** Fix `anchor.rs`:

- `reg_of()` accepts both `Operand::Register` and `Operand::RegisterOrSP` for the ADRP destination,
  the ADD destination/source, LDR destinations and `clear_dest`.
- `scan_references` scans `[init_start, init_end)` as well as `[text_start, text_end)`, marking
  sites in init (`in_init()` already exists for this; it becomes live).
- `Assessment` gains `first_access` (the lowest read/write target in the candidate, rounded down to
  the stride) and `--anchor-scan` prints it next to `safe_len`. `safe_len` semantics stay as they
  are, so the 5.10 emission path is not perturbed.

This raises reference counts on 5.10 too (`adrp; add; ldr` was invisible there as well). Re-run the
228-profile audit and the 5.10.236/246/198 acceptance controls before shipping; the bundled
profiles are pinned and unchanged, but a future generation may pick a shorter prefix.

**A1b — selection/verdict safety (found 2026-10-28, mandatory before any family opens).** The
scanner's `safe` verdict tests live reads, writes and materializations but **not init references**,
and the ranked path (`select_candidate` filters non-`unsafe`, takes `max_by_key(safe_len)`;
`profile_triple` also emits `safe_len`) keys on a quantity that ignores reads and boot-time writes.
On 6.1.138 this would select `__log_buf` — the printk ring buffer — at `image +0x21d9660, bytes
131072` (verdict `safe`, clean prefix 0x0), with the live `stack_slabs` second. Fix:

- init references must disqualify `safe`, or at minimum bound the emitted bytes;
- the ranked path must key on the first access / clean prefix, not `safe_len`;
- even then the ranked path is not made safe: it cannot see indexed writes, and live `stack_slabs`
  keeps a 0x10000 clean prefix. The fixes remove only the init-written picks (`__log_buf`,
  `serial8250_ports`). A family still needs a vetted **named** candidate (the 5.10 path's
  `dump_skip.zeroes` role) and its device gate; no ranking rule substitutes for them.

The 6.1 device test used the operator-chosen `s3c24xx_serial_ports` precisely because the scanner
did not select it; the family gate is what kept the defect from producing a profile.

**A2 — pitch from BTF, with a floor.** In `main.rs`, when BTF is present, derive
`stride = btf.size("rt_mutex")`. Accept it only when it is a multiple of 32 and `rt_mutex_base`
still carries `wait_lock@0, waiters@8, owner` at 0x18; otherwise refuse and log. Without BTF keep
`ANCHOR_STRIDE = 32` for the 5.10 series. This makes a future family change fail loudly instead of
silently writing slots over a larger struct.

**A3 — a separate anchor-family gate.** Add `family::anchor_stride(release) -> Option<u64>`:

- 5.10 `android12-9` + IKCONFIG series match: `Some(32)` — current behaviour, unchanged.
- every other family: `None`. `--anchor` auto-emission does not open for 6.x. The skip is logged
  (the 2026-10-27 extractor fix already warns on a series skip; extend the message to name the
  missing family gate).

The gate opens per family only after a device-validated anchor exists, at which point the family
gets its own entry and its own acceptance control. The 5.10 template gate (IKCONFIG fingerprint)
is not loosened.

**A4 — operator-supplied triple for validation.** Add `--anchor-image`, `--anchor-bytes`,
`--anchor-stride` (all three or none). They bypass the scan and are logged as
`operator-supplied, not derived`. This is how the 6.1 candidate reaches a profile for the device
gate without pretending the tool proved it.

**A5 — refusal/fallback semantics.** One slot is the floor: `bytes < stride` refuses the triple and
the route keeps the page-based path. An incomplete triple (any two of three) is refused, never
silently completed. The route already refuses an incomplete multicast triple (step 62); the tcp
route takes the same rule.

### B. `tcp_zerocopy` lock anchor — REFUTED 2026-10-28 (do not implement)

**The route's fake lock is not a zero `rt_mutex`.** `prepare_skb_payload()`
(`src/core/support/util.cpp`) fills the payload page's lock at `LOCK_OFF` with
`waiters.rb_leftmost = fake_w0` and `owner = fake_task | 1`; those two words are what make the
walk descend and land the erase's collateral write. A zero anchor leaves `owner == NULL`, the
walk takes the uncontended arm and returns without writing.

Device evidence (MTK `duchamp` 6.1.138, build 663 with the anchored branch, profile
`lock_anchor_* = 0x22484e0/0x1ce0/32`): W1 consumed 48 anchor slots across two attempts, every
route call `clean=1/1`, every stage `route returned clean but the write did not verify`; the
page-based control on the same build/phone completed with six clean calls. Full record:
`external/port/duchamp-tcp-anchor-2026-10-28/README.md`.

The schema/native/Kotlin/golden changes were reverted on 2026-10-28; the extractor's `--anchor`
route list is back to select/sigreturn/multicast. A future tcp anchor would need the anchor slot
*populated* with the crafted words — a two-stage primitive (one page-based write to seed it, then
anchored attempts), not an emission change. Not attempted.

The original design record follows, kept because it is what the refutation is against:

- `src/core/profile/binary.cpp`: add `OPT("lock_anchor_image"/"_bytes"/"_stride")` to `kRouteTcp`,
  mapped to `geometry.select_lock_anchor_*`.
- `src/core/profile/model.h`: `TcpZerocopyLayout` gains the three optionals.
- `profile-core/.../TcpConfig.kt`: nullable fields, emitted only when present.
- `TcpZerocopyRoute::execute()`: per-attempt `acquire_lock_word()` at zc `0x30`; `prepare()`
  relaxes the `fake_lock` requirement only in the anchored path; refusal steps 62/63.

### C. Device gate on the MTK phone (`duchamp`, 6.1.138) — NO-GO, 2026-10-28

Candidate profile: `s3c24xx_serial_ports` `+0x22484e0`, bytes `0x1ce0`, stride `32` (231 slots),
supplied as a test build's bundled profile (no SAF interaction needed). Result: the anchored
route never wrote (48 slots, `clean=1/1` + `the write did not verify` on every call), while the
page-based control on the same build/phone completed. No kernel log exists (the app's late-loaded
KernelSU does not expose `su` to adb shells); the app's run store is the verdict. The phone was
restored to the normal 663 build (`d3ccb02d…`, native `1414f4f8…`) and the anchor state file
removed. Evidence and hashes: `external/port/duchamp-tcp-anchor-2026-10-28/`.

What a future attempt would need (not designed here): a way to **populate** the anchor slot with
`rb_leftmost = fake_w0`, `owner = fake_task | 1`, `rb_root = 0`, `wait_lock = 0` before the walk —
i.e. a two-stage primitive. Seeding it with one page-based write reintroduces exactly the page
dependency the anchor was meant to remove.

## Risks

- **A new scanner that finds more references may shorten a future 5.10 prefix.** The shipped
  profiles are pinned and device-verified; regeneration could emit fewer slots. Re-run the
  acceptance controls (236/246/198) and compare before the next profile generation.
- **`s3c24xx_serial_ports` is dead-code reasoning, not proof.** If the vendor kernel probes an
  s3c24xx UART (a DT node we have not seen in the vendor_boot), the anchor is live state and the
  run corrupts it. The device read-back in step 1 is the guard, and the anchored series is the
  proof.
- **Opening a family before A1b lands would emit a live region.** The ranked selection currently
  prefers `safe_len` and the verdict ignores init references, so on 6.1.138 the first generated
  profile would point the walk at `__log_buf` (131072 bytes). The gate must not open until the
  selection/verdict fixes are in, or the family must have a vetted named candidate.
- **A `lock_anchor_*` triple in a 6.6/6.12 select profile is silently inert.** The select route's
  anchored path exists only in the compact waiter branch; its non-compact branch uses the page
  `fake_lock` unconditionally (measured on myron, 2026-10-28). Do not treat such a triple as
  "emitted but ungated" — nothing reads it until the route changes.
- **The tcp route's failure modes are not the same as multicast's.** Confirmed on 2026-10-28: the
  tcp fake lock must be populated, so the zero-anchor equivalence assumed by the multicast port
  does not hold. The anchor cannot merely replace the lock *address*; it would have to replace the
  lock *contents*.
- **`tcp_zerocopy` is geometrically infeasible on 5.10**, so this work has no 5.10 device gate; its
  only device evidence is the MTK phone — and that evidence is now the refutation.

## Open questions

- ~~Does the vendor DTBO carry an `samsung,s3c*` node?~~ **Answered 2026-10-28:** the myron
  (6.12.23, OS3.0.303.0) and annibale (6.6.77, OS3.0.307.0) `dtbo` **and** `vendor_boot` both carry
  **zero** `samsung,s3c` matches; the strings in the `boot.img` are the driver's own `of_device_id`
  table. The dead-code argument holds on both devices.
- ~~Do the 6.6/6.12 families need their own anchor candidate at all?~~ **Answered 2026-10-28
  (`external/port/anchor-survey-2026-10-28/`):** yes, and the natural one is the coredump zero page
  — `__dump_skip.zeroes`, the same object as the shipped 5.10 `dump_skip.zeroes` — which exists on
  **every** sampled 5.15/6.1/6.6/6.12 image at a per-image offset (0x1000 B, references only in
  `dump_emit`/`dump_user_range`, 0 reads/writes/init). `s3c24xx_serial_ports` (0x1da0) also exists
  in every 6.6/6.12 image. The family gate stays per-family because the *device gate* is per
  family, not because the candidate is unknown.
- ~~Does a 6.6/6.12 select profile's anchor actually reach the route?~~ **Originally no; fixed and
  device-proven the same day (2026-10-28, `external/port/myron-select-anchor-2026-10-28/`).** The
  myron's first anchored run showed the triple was inert: the resolved document and the wire
  `profile.bin` both carried `lock_anchor_*` under `route.select_stack`, yet the route ran the page
  path — the anchor branch and stamp words lived only inside `if (compact)` in
  `select_stack_route.cpp`, and the non-compact branch hardcoded the page `fake_lock`. The
  non-compact branch was then wired to stamp the stack waiter's tree entry and consume the anchor
  (`select-noncompact-anchor-plan.md`); that exposed a second, family-specific effect — the value
  write's bookkeeping store lands at `init_cred+8`, which is `uid` from 6.10 on — repaired by a
  leaf write after each credential write (`w2-anchored-cred-repair-plan.md`). The repaired build
  completed the full chain on 6.12.23 through the zero-page anchor: 8/8 route calls, slots 0–7,
  `state=completed`. 5.10/5.15/6.1 (compact) are unchanged.

## Evidence

`external/port/anchor-6x-2026-10-27/`: `btf-rt-mutex.txt`, `use-scan-6.1.138…txt`,
`use-scan-5.10.236…txt` (control), `use-scan-5.10.198…txt`, `use-scan-5.15.194…txt`,
`candidate-s3c24xx.txt`. The scratch analysis programs (`examples/anchor_use_scan.rs`,
`examples/decode_at.rs`) are temporary helpers and are removed before any commit; their logic moves
into `anchor.rs` under A1.
