# Per-image route verdicts, the complete DirtyFrag verdict, and the DirtyFrag bundle

Status: approved. The per-image verdicts and the complete DirtyFrag verdict are implemented
(2026-11-10); the DirtyFrag verdict now requires a feasible W1 route, not `select_stack`. The
store supersets are regenerated; the bundling/app steps below remain. L-level: it changes route
selection, the profile `pipeline` the bundle ships, and the meaning of the DirtyFrag gate.

## 1. What the extractor says today

`analysis::route_verdicts()` dispatches on `release_major == 5`. Inside the 5.x branch all four
routes are derived from the image; outside it `multicast_waiter` and `sigreturn` are returned as
`Unknown` with the literal reason "no non-5.10 ... derivation", without attempting the image.
`tcp_zerocopy` and `select_stack` are per-image on every release. The route suggestion
(`analysis::suggest`) then falls back to `kernel_struct_macro` families
(`STRUCT_OFFSETS_6_1/6_6/6_12`) and `major/minor` rules when the pselect derivation fails.

Stored evidence (`external/test-kernels/*/options-*.json`):

| image | select_stack | tcp | multicast | sigreturn |
|---|---|---|---|---|
| 5.10.236 (diting) | feasible | infeasible | infeasible | feasible |
| 6.1.115 | feasible | feasible | unknown | unknown |
| 6.6.102 | feasible | infeasible | unknown | unknown |
| 6.12.23 | feasible | infeasible | unknown | unknown |

The same options already carry the two pipeline verdicts (`pipeline.rs`): `kdp`, `esp_fix`
(the effective pair — the `skb_has_shared_frag` guard in `esp_input`/`esp6_input` **and** the
`SKBFL_SHARED_FRAG` send marking) and `send_path` (`skb_splice_from_iter` / `ip_append_page` /
`Copy`), with DirtyFrag feasible iff the ESP fix is ineffective, the send path attaches pages, and
at least one route is feasible for W1. The profile's own route delivers W1 — `select_stack` is not
required; the page-free routes (`select_stack`, `sigreturn`, `multicast_waiter`) are a quality
flag, not a dependency. The diting 5.10.236 and the 6.6/6.12 samples read DirtyFrag feasible; the
6.1 `Copy` samples read infeasible.

The bundling hole: `tools/ship_golden_profiles.py` renders each cut with `--route` but never
`--pipeline`. `main.rs` requires `--pipeline` when both pipelines are feasible, so the entries
above (both feasible) cannot be cut by the tool at all; and no bundled profile carries
`pipeline = dirtyfrag` even where the verdict says it is available.

## 2. Design

### 2.1 Every route verdict is derived from the image

Remove the `release_major` dispatch. `route_verdicts()` always computes all four routes; each
verdict is `Feasible`/`Infeasible` from its own derivation, or `Unknown` with the missing input
named (symbol absent, disassembly unavailable, BTF field absent).

- **select_stack** — unchanged; already the pselect/futex derivation.
- **tcp_zerocopy** — unchanged; already the getsockopt layout derivation.
- **sigreturn** — drop the 5.10 gate and call `derive_sigreturn_layout()` on every image. It is
  already per-image (frames of `__arm64_sys_rt_sigreturn` / `restore_sigframe` /
  `restore_fpsimd_context` / `restore_sve_fpsimd_context`, copy destination from the copy
  sequence). The waiter layout comes from BTF first; the 5.10 template is used only when the
  image carries no BTF at all, and only for a 5.10 image (as today). Missing symbols are
  `Unknown`, never a family default.
- **multicast_waiter** — generalize `multicast_verdict_5_10()`:
  - waiter layout from BTF / the per-image derivation (pi_tree entry, task, lock); the 5.10
    template stays the labelled no-BTF fallback for 5.10 only;
  - the setsockopt copy length is derived from the image (`ip_setsockopt`'s copy call: the
    length immediate before the `copy_from_user`/`__copy_from_user` call, or the `greqs`
    window), not the fixed `GROUP_SOURCE_REQ_SIZE` (264, `sizeof(struct group_source_req)` —
    a UAPI ABI constant, not a version fact). The constant remains the labelled fallback when
    the immediate cannot be read;
  - the chain symbol sets are probed per image (a missing name is `Unknown` with that name).

The `family.rs` struct template (`apply_structs`) remains for no-BTF `task_struct`/`cred` fields
and keeps its unverified-candidate warning; it no longer decides route verdicts or the suggestion.

### 2.2 The suggestion is a function of the verdicts

`analysis::suggest` stops reading `kernel_struct_macro`/`major`/`minor`:

- If exactly one route is `Feasible`, choose it with the derivation's own confidence.
- If several are `Feasible`, return `Ambiguous` with the set (the app/profile author chooses, as
  it does today); the tie-break order is documented but never inferred from the version.
- If none is `Feasible`, the zero-feasible fallback nominates an `Unknown` route only from the
  image's own evidence (the `do_futex` frame rule generalized beyond 5.10 plus the path probes),
  labelled `Fallback`, and the extractor prints the reason.

### 2.3 The DirtyFrag verdict is complete and kernel-side

`f4c50a4034e6` has two cooperative halves (see `dirtyfrag-stage1-static-checks.md`):

1. `ip_append_page()` marks spliced datagram frags with `SKBTX_SHARED_FRAG` (a store in the
   5.x path; the 6.5+ equivalent lives around `skb_splice_from_iter`);
2. `esp_input()`/`esp6_input()` add `!skb_has_shared_frag(skb)` to the no-COW fast path.

Today `pipeline::esp_fix` checks only (2). That is the "half-check": a kernel with the guard but
without the marking has a guard that never fires for a spliced page, so the in-place decrypt still
happens. The verdict therefore becomes:

- `EspFix::Present` (the attack's in-place decrypt is blocked) only when **both** halves are found
  in the image;
- `EspFix::Absent` when either half is missing, with the missing half named in the reason;
- `EspFix::Unknown` when a required anchor cannot be found (no `skb_cow_data`, no call to anchor
  the check, no marking site).

`pipeline::send_path` stays as the three-way class and is extended with tests against the known
images (5.10.236 `ip_append_page`; 6.6.66 `skb_splice_from_iter`; 6.1.138 `Copy`; 6.12.23
`skb_splice_from_iter`). The fact schema records the halves separately (e.g.
`esp_guard`/`send_marking`) so the option superset and the generation log say which half was
missing; the aggregate verdict is what the bundle consumes.

The verdict stays **kernel-side**: the libc++/libbase hook target and tail-page cave are ROM
properties the kernel image cannot carry. The app already plans the stage against the running
ROM; it gains a pre-flight refusal when the target/cave is absent (app line, separate change),
so a bundled DirtyFrag profile cannot fail after W1 on an unsupported ROM.

### 2.4 Bundling rule (a default, not a lock-in)

- `ship_golden_profiles.py` chooses the cut's pipeline from the stored superset:
  **`dirtyfrag` when its verdict is `feasible`; otherwise `ghostlock` when `feasible`; otherwise
  the entry is not shippable** (it already requires a feasible route). It passes
  `--pipeline <chosen>` to the extractor.
- The cut's route is chosen independently by `choose_route` (`ROUTE_PRIORITY`): a DirtyFrag cut
  on a sigreturn-only or multicast-only image takes that route. The tool does not require
  `select_stack`; the pipeline verdict only requires that some route can deliver W1.
- `--check` must stay green; the bundle counts and the `index.conf` registration are regenerated
  with `--apply`, and any profile whose verdict is not feasible keeps GhostLock.

Consequence: the diting 5.10.236, the 6.6 and the 6.12 entries above ship `pipeline =
dirtyfrag`; the 6.1 entries (send path `Copy`) keep GhostLock. This is the per-image form of the
decision already taken from the A/B: DirtyFrag is the default when the image says it can work.

**The default is not a lock-in.** The extractor always reports both pipelines with their
verdicts; the App's parse/export flow must present them and let the user choose, the same way the
route choice works today. The bundle's `pipeline` only decides what the shipped profile selects
when the user does not choose; it must never hide the other feasible pipeline. The App's
pre-flight then validates the *chosen* pipeline (for DirtyFrag, the userspace hook target/cave).

## 3. Implementation steps

1. `analysis.rs`: remove the family dispatch; generalize the multicast verdict (copy length from
   the image, per-image waiter layout and chains); call the sigreturn derivation on every image;
   rewrite `suggest` over the verdicts; keep `--no-disasm` as `Unknown` for the disassembly
   verdicts.
2. `derive.rs`: add the copy-length reader for `ip_setsockopt` (and a labelled fallback);
   generalize the chain lookups; no family constants in the verdicts.
3. `pipeline.rs`: split `esp_fix` into guard/marking facts, compute the effective verdict from
   both, and add `send_path`/`esp_fix` tests per known image.
4. `options.rs`/`report.rs`: record the split facts and render the reason that names the missing
   half; keep the aggregate `pipelines` shape.
5. `ship_golden_profiles.py`: pipeline selection + `--pipeline`;
   regenerate the bundle; `--check`.
6. App (separate, small): the DirtyFrag pre-flight (hook target/cave) and the parse advice using
   the stored per-image verdicts instead of the version family.
7. Docs: this file, plus the test-kernel store notes for the changed verdicts.

## 4. Tests and gates

- `cargo test` (unit + the store integration): the four route verdicts per image, the multicast
  copy length, the two esp halves, the send-path classes, the suggestion.
- The known-ground-truth set: 5.10.236 (multicast infeasible, sigreturn feasible, DirtyFrag
  feasible), 5.10.81 (select_stack/multicast/tcp infeasible, sigreturn feasible, ESP fix absent,
  `ip_append_page` → DirtyFrag feasible; the regression that exposed the false dependency),
  6.1.138 (`Copy` → DirtyFrag infeasible), 6.6.66/6.12.23 (skb_splice → feasible), the six
  QEMU-crosschecked 5.10 images, and the store corpus.
- `ship_golden_profiles.py --check`; the bundle index; the native/app gates unchanged.
- Device: one run with a **bundled** DirtyFrag profile on the OnePlus 6.6.66 (no debug
  override), one on the diting 5.10.236; the 6.1 devices stay on GhostLock.

## 5. Risks / open questions

- The multicast copy length on 6.x may not be a simple immediate at the call site; when it cannot
  be read the verdict must be `Unknown`, not the 5.x constant.
- The 6.5+ marking site for the send half needs its own pattern; the two known images (6.6.66,
  6.12.23) are the gate for the matcher.
- The bundling switch changes what the default bundle ships for eligible kernels; the A/B
  supports DirtyFrag, and GhostLock remains the fallback for `Copy`/KDP-blocked images. The
  debug `second_way` override only forces DirtyFrag over a GhostLock profile — there is no
  reverse override — so running GhostLock on a kernel whose bundled profile says DirtyFrag needs
  an external GhostLock profile (as the A/B harness already uses) or a new debug override.
- The userspace hook is out of the kernel image; the app-side pre-flight is required before a
  bundled DirtyFrag profile is trusted on a new ROM.
