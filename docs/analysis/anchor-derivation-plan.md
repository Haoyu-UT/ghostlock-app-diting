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
| **stride** | **yes, but not as a struct size** | the largest offset any lock-relative access in the PI-walk paths touches |

The stride row is the one that is easy to state wrongly, so to be exact: what the scan derives is **the
highest offset that anything dereferences through a pointer to this region**, rounded up to the access
width. It is *not* `sizeof(struct rt_mutex)` and must never be presented as one. The two differ on any
kernel built with lockdep, where the struct grows a `dep_map` that lock_acquire/release write — and
lock_acquire is not a path our fake lock can reach, because nothing ever locks through that address
except the requeue path that put a waiter there. The derived number would be the same 0x20 in both
cases, so the failure mode of the wrong explanation is not a wrong answer today: it is a number that
looks like a struct size, gets trusted as one on the next port, and is then wrong. The tool should print
the accesses it found, not just the maximum.

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

### The verdict vocabulary, and why our own anchor is not `safe`

Three verdicts, and the middle one exists because the strict rule would reject the anchor that works:

* **`unsafe`** — any live write. Rejected, no judgement needed.
* **`safe`** — no live references at all. This is the only verdict the tool accepts on its own.
* **`needs-review`** — live reads, or a pointer to the region found in a data section. The tool names
  the reason and the operator accepts or rejects.

`dump_skip.zeroes` lands in **`needs-review`**, not `safe`: `dump_skip()` reads it as the source of a
bulk copy, so the bytes are copied out but never interpreted. That is benign for a zero source and
would stop being benign if the region were used as anything else — which is exactly the judgement a
tool should surface rather than make. The acceptance test must therefore **expect** `needs-review` for
the anchor we actually use. If a future change makes the tool call it `safe`, that is the tool having
lost a distinction, not gained one.

A report, and the profile triple in copy-pasteable form. Nothing is written to a profile
automatically — the operator decides, exactly as with every other extracted value:

```
[anchor] dump_skip.zeroes  image +0x2a3a590
  writable   : yes (.bss, __end_ro_after_init at +0x241f7f0)
  references : 1 live read (dump_skip+0x…, bulk copy source), 0 live writes, 0 init
  safe length: 0x1000   (stopped by: kernfs_pr_cont_lock, live store at +0x…)
  stride     : >= 0x20  (max lock-relative access +0x18, 8 bytes, ...+0x…)
  verdict    : needs-review — 1 live read, dump_skip+0x… (bulk copy source)
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
  (`0x2a3a590`, `0x1000`, `0x20`) — including the stopping signal (`kernfs_pr_cont_lock`) and the
  `needs-review` verdict.

  What makes this a test rather than a tautology: those three numbers were **measured on the device**,
  not produced by the tools this one absorbs. The kprobe footprint showed only `+0x08` and `+0x10`
  ever written and nothing past `+0x18` (that is where `0x20` comes from), and a one-page rotation
  reaching `kernfs_pr_cont_buf` (that is where `0x1000` comes from). `bss_scan`/`bss_xref` share the
  ancestry of the new code, so asserting against *their* output would prove nothing; asserting against
  the device does.

* **Known limitation, stated rather than papered over**: there is only **one image** to validate on.
  `external/boot.img` and the patched image differ only by an appended KernelSU `.ko` — the kernel
  proper is byte-identical — so the suite can show the tool reproduces a known answer, and cannot show
  it generalises. That is a claim for the first real port to a second build, not for this suite.
* **The bug it exists to prevent**: assert the reported length is **not** the symbol extent
  (`0x1344` as first read; the code's own comment carried it until `--anchor-scan` produced `0x1000`).
  A regression to a stale extent is the failure this tool is for.
* **Negative**: a synthetic candidate written by live code must be rejected, and one whose
  only reference is a live store must report length 0.
* **Init handling**: a candidate whose only store is in init text must be reported as
  needs-review, not as safe.

Gates: `cargo test` in `tools/extract_rs`. The tool is host-only and touches no attack
disassembly, so `cmp_disasm` does not apply; no device gate is possible for the static
claim itself.

## Implementation status (2026-10-09)

Implemented as `tools/extract_rs/src/anchor.rs` plus `--anchor-scan` and
`--anchor-symbol`, with the acceptance test in `tools/extract_rs/tests/anchor_scan.rs`.

What shipped: candidate enumeration, the reference scan with read/write/init
classification, the extend-until-something-live length rule, and the three-valued
verdict. On this build it reproduces the device measurement -- `dump_skip.zeroes`
at `+0x2a3a590`, safe length `0x1000`, verdict `needs-review` -- and it rejects
`__log_buf` as `unsafe` with its live writes named.

Two things it caught immediately, which is the argument for having built it:

* The first version filtered each reference on "is the target inside the text
  range". The target of a reference from text into .bss is a **.bss** address, so
  that discarded every reference that matters and kept 667 from function-pointer
  tables. `__log_buf` came back `safe`. The acceptance test now asserts a
  reference count in the thousands and that `__log_buf` is `unsafe`.
* The neighbour facts repeated in this file, in the route's comment and in the
  slot-persistence plan were wrong: the symbol after the page is `core_uses_pid`,
  the extent is exactly `0x1000`, and `kernfs_pr_cont_lock` sits `+0x340` past
  the end rather than immediately after it. All three are corrected. The refusal
  logic was right; only the explanation was not.

Not implemented: **the stride derivation**. It is the one part that needs
register provenance across branches -- the lock pointer moves between registers
and is spilled, and a straight-line pass loses it at the first branch, so a
naive version would report a maximum over unrelated offsets (the walk also
touches `task_struct` fields at `+0x780` and beyond). Shipping a number that
looks derived but is not is worse than shipping none: the profile's stride
remains a hand-measured value the route validates. The CLI says so in its output
rather than omitting the line.

## Sequencing

Step 1 (the `lock_anchor_bytes` / `lock_anchor_stride` profile keys and the route's
geometry check) is **done**, so this tool now has somewhere to put its answer. Implementation
is deferred behind the open victim-child failure in `rate-fix4` runs 5-6
(`anchor-slot-persistence-plan.md`), which is what currently sets the failure rate.
