# MTK `kernel_phys_offset` from the vendor_boot DTB — plan and result

**Status: merged into `document` at `39b667d` (2026-10-26), host-gated and cross-checked on two
real MediaTek images. Tooling only; no device gate is required and no route/attack-path code
changed.** Branch `feat/extractor-mtk-phys` was cut from `document` @ `9c96125`. Supersedes the D3
open decision in [`kernel-phys-offset-plan.md`](kernel-phys-offset-plan.md) (that plan added the
profile field; this one fills it from the stock image).

**App integration (2026-10-26).** The parse flow now asks for the platform images with
mandatory/recommended semantics: `boot.img` is the input; MediaTek recommends `vendor_boot` and, if
that carries no usable `/memory`, `dtbo`; Qualcomm recommends `xbl_config` and, if that did not
supply the load, `uefi`. The extractor prints a canonical `info: phys_source=…` line the app uses
to decide the next prompt. Device-tested on the Qualcomm branch; the MediaTek prompt decision is
unit-tested. Record: `external/port/parse-phys-prompts-2026-10-26/`.

## Problem

For MediaTek the extractor had two independent physical sources:

- `--vendor-boot` read only the 20-byte header prefix and derived `kernel_phys_load` from
  `kernel_addr`. It returned `kernel_phys_offset` only for the ARM64 text-align pattern
  (`kernel_addr & 0xfffff == 0x80000`); a MiB-aligned `kernel_addr` stayed ambiguous and the
  offset was left null.
- Everything else (`--iomem`, `--phys`) needed a rooted device or an explicit answer.

That made the common case — a stock `boot.img` + `vendor_boot.img`, no root — unable to produce a
complete MediaTek profile. The vivo PD2314 `5.10.198-android12-9-gf90155818e7f-dirty` sample is
exactly this: `kernel_addr = 0x40000000`, so the header pattern proves nothing, while the image
itself names the DRAM base.

## Evidence

`vendor_boot.img` (VNDRBOOT v4, page 4096) at the PD2314 sample:

| field | value |
|---|---|
| `kernel_addr` | `0x40000000` |
| `vendor_ramdisk_size` | 85,409,708 |
| `dtb_size` / `dtb_addr` | 331,132 / `0x47c80000` |
| dtb section file offset | 85,413,888 = `align(page + ramdisk_size, page)` |
| section content | `DT_TABLE_MAGIC 0xd7b7ab1e`, one entry: `dtb_size=331,068`, `dtb_offset=0x40` |
| DTB `/memory` | `reg = <0x0 0x40000000 0x0 0x3e605000>` |

So the `dtb` section is not a bare FDT: it is the Android DTBO table format (`dtbo.img`'s
container), and the FDT starts at `dtb_offset` inside it. The previous session read the node by
scanning for the FDT magic; this change parses the container instead.

Full derivation and hashes: `external/github_error_reports/5.10.198-android12-9-gf90155818e7f-dirty/`
in the port repository (`vendor-boot-dtb-memory.txt`, `2026-10-25-profile-and-config-diff.md`).

## Design

1. **Header.** Parse the v3/v4 common prefix fully (2112 bytes): `page_size`, `kernel_addr`,
   `vendor_ramdisk_size`, `header_size`, `dtb_size`, `dtb_addr`. Validate magic, version ≥ 3,
   page size is a power of two, `2112 ≤ header_size ≤ page_size`, and a plausible `dtb_size`.
2. **Section location.** `dtb_offset = align(page_size + vendor_ramdisk_size, page_size)`
   (header page + page-aligned vendor ramdisk), bounds-checked against the file length. Only the
   header and the section are read, so a 128 MiB `vendor_boot.img` costs its ~331 KiB DTB.
3. **Container.** A section starting with `DT_TABLE_MAGIC` is parsed as a DTBO table (entries are
   `{dtb_size, dtb_offset, ...}` relative to the table start); a section starting with the FDT
   magic is parsed directly. Anything else is an error for that section only.
4. **`/memory`.** Walk one FDT (struct block, strings block, `#address-cells`/`#size-cells`,
   `reg`), select direct children of the root named `memory`/`memory@*` or with
   `device_type = "memory"`, and take the **lowest** non-empty `reg` base. Every DTB in a table
   must agree; conflicting bases are refused rather than guessed. Overlay entries without a
   `/memory` node are ignored when one entry resolves.
5. **Precedence.**
   - `kernel_phys_load`: xbl_config/uefi/`--phys` (existing) > vendor_boot `kernel_addr`.
   - `kernel_phys_offset`: `/proc/iomem` / `--iomem` (existing, still wins) > vendor_boot DTB >
     `--dtbo` > vendor_boot text-align pattern > null.
   - `--dtbo` is used exactly when the vendor_boot cannot supply an offset, which covers
     `dtb_size = 0` (the bootloader takes the DTB elsewhere) and an unparsable section.
6. **Honesty rules.** A MiB-aligned `kernel_addr` with no DTB still leaves the offset null (the
   `0x40200000`-above-`0x40000000` ambiguity is real). An unknown alignment is refused even when a
   DTB resolves: the pattern check is also the MediaTek platform check, because every Qualcomm
   vendor_boot on disk carries a small relative `kernel_addr` (`0x8000`), not an absolute load.
   When the DTB and the text-align pattern both resolve and disagree, the DTB wins and the tool
   prints a warning naming both values.

The emitted value is the DTB's DRAM base, the same quantity the existing `--iomem` path derives
from `System RAM` (including its reserved-carveout extension): on the 39-bit-VA / 4 K-page kernels
this work targets, `memstart_addr = round_down(DRAM base, 1 GiB)` and the DRAM base is already
1 GiB-aligned. No rounding is applied, so a non-aligned base would surface as a mismatch rather
than be silently changed.

## Files

| file | change |
|---|---|
| `tools/extract_rs/src/dtbo.rs` | new: DTBO table split, FDT `/memory` lookup, unit tests |
| `tools/extract_rs/src/vendor_boot.rs` | full header parse, dtb-section location and resolution, new `VendorBootPhys` result, unit tests |
| `tools/extract_rs/src/lib.rs` | register the module |
| `tools/extract_rs/src/main.rs` | `--dtbo` flag; DTB-aware vendor_boot messages; dtbo fallback |
| `docs/kernel_profiles/MEDIATEK.md` / `_ZH.md` | images-first procedure, rooted script as fallback |
| `docs/kernel_profiles/README.md` / `README_ZH.md` | MediaTek extraction note |

No app code path changed: the app already passes `--vendor-boot` for the MediaTek attach option,
so it picks the offset up with the same build. A `dtbo.img` attach option in the app is a
follow-up for images whose `vendor_boot` has no DTB (the CLI already supports it).

## Validation

- `cargo test`: 87 lib tests pass, 1 pre-existing ignored (11 new DTBO + 15 vendor_boot) plus the
  existing suite, all pass; `cargo build --release` is warning-free.
- Real PD2314 images, `--iomem /dev/null`:
  `vendor_boot DTB /memory; kernel_phys_offset=0x40000000`, and the full profile body is identical
  to the candidate profile that was previously completed by hand (`mm_struct_sz` still comes from
  the QEMU `/proc/slabinfo` measurement, not from the image).
- Synthetic end-to-end cases: text-align header (`0x40080000` → offset `0x40000000`); MiB-aligned
  header with `--dtbo` (`0x40000000` → offset from the dtbo); MiB-aligned with nothing
  (`kernel_phys_offset = null`).
- **Second real MediaTek sample (2026-10-26).** The duchamp (POCO X6 Pro 5G, Mediatek MT6897,
  `6.1.138-android14-11-g44bda9e8f6e9-ab13792638`) `vendor_boot` was fetched from the same official
  OTA as its test Image (payload manifest sha256 `d7e6952f…`, byte-exact after range extraction).
  It is the same shape as the PD2314: VNDRBOOT v4, page 4096, `kernel_addr = 0x40000000`,
  `dtb_size = 396,049`, and a one-entry DTBO table in the `dtb` section. The feature extractor
  prints `vendor_boot DTB /memory; kernel_phys_offset=0x40000000` and fills
  `kernel_phys_load`/`kernel_phys_offset = 1073741824`, both `null` in the bundled 6.1 profile.
  Record: `external/port/duchamp-gate/2026-10-26-vendor-boot-extractor.txt` (port repo).
- Cross-check against every vendor_boot on disk: eight distinct images now cover five kernels, and
  two are MediaTek (PD2314 5.10.198 and duchamp 6.1.138). The other six (PD2354 5.10.246 ×2,
  diting 5.10.236 ×3, diting 5.10.81) are Qualcomm with `kernel_addr = 0x8000` and a plain FDT that
  has no root `/memory`; they are refused, not misread. Their `dtbo.img` files are real DTBO tables
  of overlays (44 and 55 entries) with no `/memory`, so `--dtbo` refuses them too. The successful
  embedded-DTB path now rests on **two** real MediaTek images (5.10.198 and 6.1); the text-align
  and `--dtbo` success paths remain unit/synthetic coverage.
- No device gate: the output is a profile input, and the PD2314 profile remains a non-device-gated
  candidate until a 198-class device runs it.
