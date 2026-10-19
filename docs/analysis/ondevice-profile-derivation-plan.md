# On-device profile derivation for the diting 5.10 line

**Level:** L (extractor derivation path + profile field contract).

**Question.** The app can already fetch an OTA and run the bundled extractor on the phone, but a
5.10 diting image comes back as an unusable candidate: no BTF means every `task_struct` / `cred`
field is null, the three `cred.ref*_image` values are BTF-gated, `mm_struct_sz` falls back to 1024,
the route auto-picks `multicast_waiter`, and the lock anchor is not in the output. Can the extractor
produce a runnable candidate for this line from the image alone (no root, no PC)?

**Answer, measured.** Yes, because the line's profile is a family template plus 14 symbol-derived
numbers. Comparing all eight diting 5.10 profiles (81 / 101 / 136 / 177 / 198 / 209 / 226 / 236):

| block | evidence | per image? |
|---|---|---|
| `task_struct.*` (15) | byte-identical in all eight | no |
| `cred` layout (`copy_size` 168, `usage` 0/256, `caps` 40/5/0x1ffffffffff, ref offsets 128/136/144) | identical in all eight | no |
| `kernelsnitch` (`collisions` 8, `mm_struct_sz` 960) | identical in all eight | no |
| `lock_anchor_bytes/stride` | 4096 / 32 in all eight | no |
| route geometry | 136+: `select_stack` `waiter_shift=-2`, `compact_waiter=1`; 81/101: `sigreturn` `off_sve=0x150`, `off_plain=0x140` | version rule |
| `release` | image banner | yes |
| `offset.*` (10) | image kallsyms (already emitted) | yes |
| `cred.ref0/1/2_image` (3) | `init_cred` content at offsets 128/136/144 | yes (BTF-gated today) |
| `lock_anchor_image` | `dump_skip.zeroes` | yes (needs `--anchor`) |

The discriminator for the route is physical, not a version list: `do_futex`'s first stack frame is
**0x20** on 5.10.81/101 (select_stack out of band → sigreturn) and **0x70** from 5.10.136 on
(verified locally on all four).

## What changes

1. `family.rs` — the diting 5.10 constants above, keyed on `5.10.*-android12-9-*`.
2. `main.rs` — when BTF is absent and the release matches, fill `task_struct` from the family; on
   the 5.x cred path, fall back to reading the three reference pointers out of `init_cred` at the
   family offsets; emit `usage_offset` / `ref3_*` as 0 to match the bundled spelling.
3. Route selection — a family hint before the generic 5.x multicast rule, from `do_futex`'s first
   frame (`disasm::first_sp_frame`). `select_stack` gets `waiter_shift=-2` + `compact_waiter=1`;
   `sigreturn` gets `off_sve=0x150` + `off_plain=0x140` (new route entry in `CONF_ROUTE_FIELDS`).
4. `--anchor` — in `--format conf`, assess `dump_skip.zeroes` (falling back to the best non-unsafe
   candidate) and emit `lock_anchor_image/bytes/stride` inside the route branch. The stride stays
   the shipped 32; the stride derivation is not implemented (see `anchor-derivation-plan.md`).
5. `--format conf` — render geometry entries outside the route's known field list (so
   `compact_waiter` and the anchor keys appear without emitting nulls for other routes).
6. App — pass `--anchor` when parsing; no other app change.

## Non-goals

- General no-BTF derivation for other device families (the existing
  `extractor-no-btf-struct-derivation-plan.md` stays the plan for that).
- Stride derivation (register provenance across branches).
- Marking a derived profile supported: the output keeps the unverified-candidate warning; a device
  gate is still required.

## Risk

The family key is the GKI train, not the device. A non-diting 5.10 `android12-9` image could carry a
vendor-hooked `task_struct` / `cred`; the extractor cannot detect that statically. The candidate
banner, the app's pre-execution validation and the device gate are the guard. Per-image values are
unaffected (they are read from the image).

## Gates

`cargo test` (host). The anchor test's reproduction of the device-measured triple stays the control.
An env-gated integration test (`GHOSTLOCK_IMAGE_DIR`) runs the eight local images and compares the
generated profile against the bundled one: route, geometry, the ten offsets, the three refs and the
anchor. Device: the first run with a derived profile is the gate.

## Result (2026-10-19)

Implemented on `feat/extractor-ondevice` (off `document` @ `b8d350d`). Run against all eight local
images (`GHOSTLOCK_IMAGE_DIR=external/rom`), the generated profile matches the bundled one on every
block — `route`, `execution`, `task_struct`, `cred`, `kernelsnitch`, `offset` — including the
per-image values:

| release | route | anchor | cred refs |
|---|---|---|---|
| 5.10.236 | select_stack | 44279184 | rebased to `KIMAGE_TEXT_BASE` |
| 5.10.226 | select_stack | 44279184 | ✓ |
| 5.10.209 | select_stack | 44275096 | ✓ |
| 5.10.81 | sigreturn | 46577000 | ✓ |
| 5.10.101 | sigreturn | 44094824 | ✓ |
| 5.10.136 | select_stack | 44160416 | ✓ |
| 5.10.177 | select_stack | 44201368 | ✓ |
| 5.10.198 | select_stack | 44201368 | ✓ |

The cred refs needed one correction the plan did not anticipate: `init_cred`'s pointers are image
VAs based at the image's `_text` (`0xffffffc008000000`), while the native's `data_alias()` expects
the compiled `KIMAGE_TEXT_BASE` (`0xffffffc080000000`). The family path rebases by
`value - image_text_base + KIMAGE_TEXT_BASE`; without it every ref is `0x78000000` off.

The app builds with the new extractor (`GhostLock-v1.2(638)`, `libextract.so` carries the family
path).

## Device result (2026-10-19)

The gate is met, and the device run exposed one bug the host path had hidden.

- **Off-family parity.** The shipped analyzer ran on the diting against the zeus 5.10.43 `Image`.
  Its output is identical to the QEMU-verified host profile in every image-derived value: the ten
  `offset.*`, `lock_anchor_image/bytes/stride`, the route and geometry (`sigreturn`, 0x150/0x140),
  and the family `task_struct`/`cred`/`kernelsnitch` blocks. The diting 5.10.236 image, run as the
  control, matches the bundled device-verified profile in every value (only the output order of the
  three `cred.ref*_image` keys differs). The same iomem gives a byte-identical result from the host
  and Android binaries; two consecutive runs are byte-identical.
- **Bug found and fixed: `kernel_phys_load` was 0x10000 low on-device.** The first APK emitted
  `0xa7ff0000` for both images while `/proc/iomem` says `a8000000`. The old code subtracted
  `(_stext - _text)` from the `Kernel code` start; `arch/arm64/kernel/setup.c` already stores
  `__pa_symbol(_text)` there, so the subtraction is wrong on every 5.10 image. Every host run had
  passed `--iomem /dev/null` and carried `null`, which is why this stayed invisible until the
  extractor ran on the phone. `main.rs` now uses the `Kernel code` start directly.
- **A profile derived on the phone runs.** The derived 5.10.236 document was loaded as the imported
  layer. Because a bundled profile is authoritative for the device's own release, the run needed a
  builtin selected by hand — the layer policy's escape hatch; the app's log then records
  `imported=… applied`. One run completed the chain (the boot's second run; the first used the
  bundle only), with `exploit complete`, `native exited code=0`, `KernelSU ready` and digest
  `0x1ae95c6f59734bb3`; the resolved profile carried `kernel_phys_load = 0xa8000000` and
  `lock_anchor_image = 44279184`.

**Limit.** For a foreign image the two phys fields are the *analyzing phone's* environment, not
properties of the image; they are right for the phone's own kernel and an assumption elsewhere.
The `task_struct`/`cred` fields and the route geometry remain family-carried. The zeus profile has
no device run — no zeus hardware here — so it remains an unverified candidate.
