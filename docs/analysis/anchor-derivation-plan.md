# Anchor derivation — `ghostlock-extract --anchor-scan`

Status: **design, not implemented.** L-level: it produces the three profile keys that
bound an attack-critical write path (`route.select_stack.lock_anchor_*`). Operator asked
for the design before code, 2026-10-09.

## Problem

The anchor's three numbers are all per-kernel-build, and today all three are produced
by hand:

| key | where it came from | how it can be wrong |
|---|---|---|
| `lock_anchor_image` (=`+0x2a3a590`) | `bss_scan.rs` candidates + a by-eye xref audit | wrong region -> the walk locks a live kernel variable |
| `lock_anchor_bytes` (=`0x1000`) | **read out of `fs/coredump.c`** (`char zeroes[PAGE_SIZE]`) | **it already was**: the symbol *extent* is `0x1344`, and using it rotates into `kernfs_pr_cont_buf` |
| `lock_anchor_stride` (=`0x20`) | kprobe footprint of one used slot | too small -> two slots share a word, both corrupt |

The supported tooling is two throwaway examples, `tools/extract_rs/examples/bss_scan.rs`
and `bss_xref.rs`. `bss_scan` ranks candidates by **extent** — the distance to the next
symbol — which is an upper bound that includes linker padding, i.e. the exact quantity
that was wrong by 20%. `bss_xref` finds references and flags the ones in init sections,
but prints disassembly for a human to judge; it does not classify the access or produce a
length. The verdict is human today, and the failure of a wrong verdict is silent.

## What is derivable from `boot.img` alone

| quantity | derivable? | how |
|---|---|---|
| candidate offsets | yes | kallsyms (already parsed by the extractor) |
| writable range | yes | `[__bss_start, __bss_stop)`, past `__end_ro_after_init` |
| whether a byte is referenced | yes | disassemble `[_text, _etext)`; `adrp` + confirming `add`/`ld-st` |
| whether a reference is dead | yes | reference site inside `[_sinittext, _einittext)` (freed after boot) |
| **read vs write** | yes | classify the access that consumes the register |
| **length** | **no — not as a symbol size** | kallsyms stores no sizes; the extent is an upper bound |
| **stride** | **yes, as a lower bound** | the largest offset the kernel dereferences through a lock pointer in the PI walk |

The pivot: **do not derive "the array's size" — derive "the longest byte range starting
here that nothing live writes."** That is decidable, it subsumes the size question, and it
is self-correcting on the bug this exists to prevent: extending past one page runs into
`kernfs_pr_cont_lock`, whose live stores stop the scan at the page boundary by
construction. A tool that reports "safe length 0x1000, stopped by `kernfs_pr_cont_lock`
(+0x…, live store)" cannot make the mistake the hand-written comment did.

## Design

One new subcommand, `--anchor-scan`, on the host-side extractor. Three passes:

**1. Candidate enumeration.** kallsyms -> `_text` base, section bounds. Enumerate symbols
in `[__bss_start, __bss_stop)` at or past `__end_ro_after_init`, with extent >= a
`--min-size` (default 0x100), sorted by extent descending. This is `bss_scan` as it
stands; it ranks, it does not decide.

**2. Reference scan over the text.** Decode every 4-byte word in `[_text, _etext)`.
For each `adrp` whose page matches a candidate's page, confirm the low-12 offset in the
following few instructions (`add`-immediate or `ld/st` unsigned-immediate, `rn == rd`),
which is what `bss_xref` already does — without it every symbol sharing a page matches.
Then classify:

* **write** — the access that consumes the register is a store (`str/stp/strb/stlr/stxr`,
  and the atomics: `cas*/swp*/ldadd*`). Live writes disqualify outright.
* **read** — `ldr/ldp/ldrb/ldrs*`. A live read does not corrupt the region, but it means a
  live code path *interprets* the bytes; our fake lock would be fed to it. Allowed only
  when the read is a bulk copy whose value is not interpreted (the `dump_skip.zeroes`
  case: a memcpy source), and always reported for review.
* **init** — the site is inside `[_sinittext, _einittext)`, so it runs at boot only. Not
  disqualifying, but it must be shown to leave the region **zero**; report separately.

Also scan the read-only and data sections for 8-byte literals equal to any address inside
the candidate's range — a pointer to the region stored in a table is an alias the
`adrp` scan cannot see, and a hit downgrades the verdict to needs-review.

**3. Length, by extension.** From the candidate's start, extend byte by byte while every
byte is (a) inside `[__bss_start, __bss_stop)` and past `__end_ro_after_init`, (b) not
inside any live store's target range, and (c) not inside a *different* symbol that has any
live reference at all. Stop at the first violation and report which one stopped it. The
result is the safe length — for our anchor, one page, stopped by `kernfs_pr_cont_lock`.

**4. Stride.** Disassemble the walk's lock-relative accesses — `rt_mutex_adjust_prio_chain`,
`rt_mutex_top_waiter` (inlined), `remove_waiter`, `task_blocks_on_rt_mutex` — collect the
immediate offsets used in memory accesses off the `lock` argument, and take
`round_up(max_offset + access_width, 8)`. That is a *lower* bound on the object size, and
it is the number the stride must not go below; report the instruction that produced it
(`+0x18 owner, 8 bytes, rt_mutex_adjust_prio_chain+0x…`). Where the bound and the profile's
stride disagree, the profile is wrong.

## Output

A report, and the profile triple in copy-pasteable form. Nothing is written to a profile
automatically — the operator decides, exactly as with every other extracted value:

```
[anchor] dump_skip.zeroes  image +0x2a3a590
  writable   : yes (.bss, __end_ro_after_init at +0x241f7f0)
  references : 1 live read (dump_skip+0x…, bulk copy source), 0 live writes, 0 init
  safe length: 0x1000   (stopped by: kernfs_pr_cont_lock, live store at +0x…)
  stride     : >= 0x20  (max lock-relative access +0x18, 8 bytes, ...+0x…)
  verdict    : usable — live read is a copy source, not an interpreted value
  => route.select_stack.lock_anchor_image  = 44279184
     route.select_stack.lock_anchor_bytes  = 4096
     route.select_stack.lock_anchor_stride = 32
```

## What this does not do

* **Direct references only.** `adrp`+`add` is the normal access path for .bss statics, but a
  store through a pointer derived some other way (a pointer loaded from a table, a
  PC-relative literal holding the address) is invisible to it. The literal scan narrows
  this; it does not close it.
* **It cannot verify the region at runtime.** It verifies a static claim about the image.
  The runtime guard stays what it is: a bounded rotation that refuses past the profile's
  byte count.
* **It cannot see a write that only happens under a configuration this build does not
  select** (a driver that is present but never probed). The manual audit has the same
  blind spot; it is stated here so it is not mistaken for a proof.

## Tests

* **Reproduction**: run against `external/boot.img` and assert the known-good triple
  (`0x2a3a590`, `0x1000`, `0x20`) — including the stopping signal (`kernfs_pr_cont_lock`).
* **The bug it exists to prevent**: assert the reported length is **not** the symbol extent
  (`0x1344`). A regression to the extent is the failure this tool is for.
* **Negative**: a synthetic candidate written by live code must be rejected, and one whose
  only reference is a live store must report length 0.
* **Init handling**: a candidate whose only store is in init text must be reported as
  needs-review, not as safe.

Gates: `cargo test` in `tools/extract_rs`. The tool is host-only and touches no attack
disassembly, so `cmp_disasm` does not apply; no device gate is possible for the static
claim itself.

## Sequencing

Step 1 (the `lock_anchor_bytes` / `lock_anchor_stride` profile keys and the route's
geometry check) is **done**, so this tool now has somewhere to put its answer. Implementation
is deferred behind the open victim-child failure in `rate-fix4` runs 5-6
(`anchor-slot-persistence-plan.md`), which is what currently sets the failure rate.
