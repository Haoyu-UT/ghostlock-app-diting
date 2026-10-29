# Lock source: page or anchor, chosen by the user

Level: **L** (attack-critical path and profile generation). Status: **approved 2026-10-29** ("that
gate is not needed now, and instead let's give user the choice to pick one — page or anchor"); the
family gate is replaced by an explicit per-profile choice.

## Why

The anchor mechanism is device-proven on the 6.1.138 POCO (`s3c24xx_serial_ports`,
`+0x22484e0`, 7392 B), the 6.6.66 OnePlus (`+0x23019c8`, 4096 B) and the 6.12.23 myron
(`__dump_skip.zeroes`, `+0x265fa70`, 4096 B) — all select_stack, all with the anchored chain
completing. The old `family::anchor_stride` gate stayed closed because it guarded *automatic*
emission: the static scan cannot prove a region unused, so a profile should not silently carry a
region nobody accepted.

The operator's decision is to stop hiding that trade-off behind a family gate and make it an
explicit choice at profile generation:

- **Page** — the fake lock lives in the reclaimed payload page. It cannot pick a wrong kernel
  object; the success rate is the page-delivery rate (lower).
- **Anchor** — the fake lock is a zeroed `.bss` region found in the image. If the region is really
  unused the route is page-independent and the success rate is higher; if it is not, the walk can
  corrupt live kernel data.

## Design

### Extractor

- `--anchor` derives a candidate for **any** release, not only 5.10 `android12-9`. The
  `family::anchor_stride` gate (and its "gate is closed" warning) is removed; `family::matches`
  stays for the 5.10 no-BTF templates.
- Emission is still route-aware: only `select_stack`, `sigreturn` and `multicast_waiter` consume a
  lock anchor. A `tcp_zerocopy` profile gets the existing "route does not use a lock anchor"
  warning and no triple (its fake lock is a crafted object; a zero anchor cannot drive it).
- Candidate choice is restricted to the named, device-proven classes: the coredump zero page
  (`__dump_skip.zeroes` on 6.x, `dump_skip.zeroes` on 5.10; the 6.12.23 myron zero page and the
  6.6.66 CPH zero page are the device-proven ones) and, on 6.1, the dead-code
  `s3c24xx_serial_ports` array. The operator triple
  (`--anchor-image/--anchor-bytes/--anchor-stride`) still wins when supplied.
  **There is no ranked fallback.** The first implementation kept the old "largest non-unsafe
  candidate" fallback and immediately picked `__log_buf` (128 KiB, scanner verdict `safe`) on
  the 6.12.23 image — a false positive: printk writes the log buffer through indexes the static
  scan cannot see. A build whose symbols moved gets the page path with a warning (or an operator
  triple), never an unvetted region.
- The log line keeps the candidate name, offset, safe prefix, stopping reason and verdict, so the
  app can show what was picked.

### App

- The parse flow always requests the anchor (as today). If the generated document carries a
  `lock_anchor_*` triple, the app shows a **锁来源 / Lock source** dialog before the export:
  - **页面 (Page)** — "锁在回收页里；不会选错内核对象，成功率较低" (safe, lower rate).
  - **锚点 (Anchor)** — "使用镜像里的零 .bss 区域；区域正确时成功率更高，选错会破坏内核数据".
  - The candidate from the extractor line is logged; the dialog is per parse, not a global
    preference.
- Choosing page removes `lock_anchor_image/bytes/stride` from the in-memory document before the
  existing export/stride path; choosing anchor keeps it. Cancelling the dialog aborts the export.
- Page is the default in the sense that it is the safe option presented first; no profile gets an
  anchor without the user selecting it. Bundled profiles are untouched (the diting 5.10 bundle
  keeps its anchor; the 6.x bundles stay page-based).
- No wire/schema change: the keys already exist. No native change.

## Tests

- Extractor: unit tests for the removed gate (a non-5.10 release with a synthetic candidate emits
  the triple; a tcp route does not); the 5.10 `ondevice_profile` anchor assertions stay; the
  `families_ondevice` goldens are rendered without `--anchor` and stay valid.
- App: a pure document-edit test (strip the triple from a route/fallback branch; keep the rest of
  the document byte-equivalent in values).
- Device: parse a 6.1.138 image (select route) with the anchor option and run it; the page variant
  is the control. The anchored 6.1.138/6.6.66/6.12.23 select runs already on record remain the
  capability evidence.

## Open

- Default selection: page (safe). The dialog explains the trade-off; the operator can flip the
  default later without touching the extractor.
- A future refinement could rank the candidate in the dialog (show the verdict/name alongside the
  choice); the generation log already carries it.
