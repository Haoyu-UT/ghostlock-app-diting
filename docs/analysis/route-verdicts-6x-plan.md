# Route verdicts beyond 5.10 — the tcp_zerocopy verdict and the 6.x route model

**Status: implemented on `feat/route-verdicts-6x` (uncommitted, for operator review), host-gated on
the local image corpus.** Tooling only: no route, wire, profile-format or native code changes. The
app needs no change — its route dialog already renders whatever `Feasible` routes the extractor
reports.

## Problem

The parse flow's route dialog (`ParseResult.Ambiguous` → `ParseDialogStage.Route`, “Both routes are
supported — choose one”) lists only routes the extractor marks `Feasible`. Only the 5.10 model
(`route_verdicts_5_10`) produces verdicts; every other family gets `verdicts = Vec::new()` and a
single `suggest()` answer applied silently. So on a 6.1 image the tool suggests `select_stack` at
High confidence (the pselect geometry derives), and the user never sees the `tcp_zerocopy` path
even though it is available and device-proven for that kernel. `tcp_zerocopy` is also `Unknown` on
5.10 by construction (“no 5.10 tcp geometry derivation”), which is currently true but for the wrong
reason: on 5.10 the route is impossible, not unproven.

## Measured facts (host, no device)

The route stamps its fake `waiter->task` / `waiter->lock` through the `getsockopt` local that the
kernel copies from the user buffer: the buffer words at 0x28/0x30 must land on `waiter+0x30` /
`waiter+0x38`. Two conditions follow, both derivable from the image:

1. **Copy cap.** `do_tcp_getsockopt` caps the copy at `sizeof(struct tcp_zerocopy_receive)`.
   The compile-time cap is visible as a pair of checks: `cmp wN, #0xc` (`offsetofend(length)`)
   followed by `cmp wN, #cap+1`. Measured: **0x18 on 5.10.81, 0x28 on 5.10.236, 0x40 on 6.1.138**
   (matches the UAPI headers of those kernels). The route's last fake word ends at 0x38, so a cap
   below 0x38 cannot deliver — **tcp_zerocopy is impossible on 5.x, independently of the stack
   layout**.
2. **Stack relation.** With depths measured from the syscall entry (negative, as the pselect
   derivation already computes them), the `zc` local must be exactly 8 bytes above the futex waiter:
   `zc_depth == waiter_depth + 8`, where
   `zc_depth = −Σ(getsockopt chain frames) + zc_local` over
   `__arm64_sys_getsockopt → __sys_getsockopt → sock_common_getsockopt → tcp_getsockopt →
   do_tcp_getsockopt`, and `waiter_depth` is the pselect layout's `futex_waiter`.

Measured on the local image corpus:

| image | cap | `zc` local | getsockopt Σ | `zc_depth` | waiter depth | Δ | verdict |
|---|---|---|---|---|---|---|---|
| 5.10.81 (launch) | 0x18 | sp+0x28 | 0x280 | −0x258 | −0x1c0 | −0xa0 | Infeasible |
| 5.10.236 (diting) | 0x28 | sp+0x28 | 0x280 | −0x258 | −0x210 | −0x50 | Infeasible |
| 6.1.138 (duchamp) | 0x40 | sp+0x40 | 0x220 | −0x1e0 | −0x1e8 | 0 | **Feasible** |

The 5.10 deltas (−0xa0 / −0x50) reproduce the earlier hand analysis exactly; the 6.1 relation
lands on zero, which is why the route is device-proven there (clean in every 6.1 gate run).

## Design

### 1. `derive_tcp_zerocopy_layout()` (new, `derive.rs`)

Inputs: kernel bytes, relative symbols, sorted offsets, and the derived `PselectLayout`.
Steps:

1. Require `do_tcp_getsockopt` and `tcp_zerocopy_receive`. Find the direct call to
   `tcp_zerocopy_receive`; take the `add x1, sp, #imm` (or `mov x1, sp`) immediately before it as
   `zc_local`. (If `tcp_zerocopy_receive` is inlined, return `Unknown`, not a guess.)
2. Scan the same function for the cap pair: `cmp wN, #0xc` followed within four instructions by
   `cmp wN, #M`, `M > 0xc`, `M−1` in 0x10..0x100. Require exactly one candidate; `cap = M−1`.
3. Sum the getsockopt chain frames with the existing `first_sp_frame`/`sum_chain_frames`
   (`__arm64_sys_getsockopt`, `__sys_getsockopt`, `sock_common_getsockopt`, `tcp_getsockopt`,
   `do_tcp_getsockopt`). The two middle links are indirect (`blr` through the proto-ops table), so
   the chain is a named list, not a call-graph walk; the direct links (`__arm64_sys_getsockopt →
   __sys_getsockopt`, `tcp_getsockopt → do_tcp_getsockopt`) are validated.
4. Compute `zc_depth`, `delta = zc_depth − (waiter_depth + 8)`, and return
   `{ cap, zc_local, chain_sum, zc_depth, waiter_depth, delta }`.

Feasible iff `delta == 0 && cap >= 0x38`. Infeasible otherwise, with the numbers. Missing symbols
or an ambiguous cap pattern → `Unknown` with the reason — never a guessed verdict.

### 2. Verdict model

- **5.10**: keep `route_verdicts_5_10`; replace the hardcoded `tcp_zerocopy = Unknown` entry with
  the derived verdict. On 5.10 it is `Infeasible` (cap < 0x38), with the cap and delta as evidence;
  the change does not alter the diting's ambiguity set (`select_stack` + `sigreturn` stay Feasible).
- **Other families** (5.15, 6.x): build verdicts instead of an empty list —
  `select_stack` from the pselect outcome (`Derived` → Feasible with the existing numbers;
  `Infeasible` → Infeasible; `Failed`/`NotAttempted` → Unknown), `tcp_zerocopy` from the derivation
  above, `multicast_waiter` / `sigreturn` → `Unknown` (“no non-5.10 geometry derivation”).
- **Selection** (non-5.10): forced route validated like 5.10 (Infeasible → exit 3; Unknown → warn);
  otherwise 1 Feasible → chosen, >1 Feasible → `Ambiguous` (exit 7, `--feasible-out` carries the
  list), 0 Feasible → the existing family suggestion only when it is not `Infeasible`, labelled as a
  heuristic; otherwise `None`. The 5.10 selection path is untouched.

Outcome on the 6.1.138 image: `select_stack` Feasible + `tcp_zerocopy` Feasible → **exit 7**, and
the app asks the user — exactly the missing behavior.

## Tests

- Unit: selection with synthetic verdicts (0/1/2 feasible; suggestion Infeasible/Unknown); cap-pair
  and zc-local parsers against instruction snippets.
- Host, over the local image corpus (`tests/route_verdicts_ondevice.rs`, 39 images): every 5.10
  image must report tcp `Infeasible` (cap < 0x38), every 6.1 image `Feasible`, every 6.6/6.12
  image `Infeasible`; a 6.1.138 image must additionally exit 7 with both routes feasible; a family
  whose derivation cannot run must report `Unknown`.
- No device gate: no native code changes. The 6.1 export profile's route choice then becomes the
  user's; the device-proven route (`tcp_zerocopy`) remains the recommendation in the dialog reason.

## Implementation result (2026-10-26)

- `derive.rs`: `TcpZerocopyLayout` + `derive_tcp_zerocopy_layout()` (call-site `zc` local, the
  0xc/cap check pair, chain frame sum, delta), with three unit tests for the scanners.
- `analysis.rs`: `select_stack_verdict()` extracted; `tcp_zerocopy_verdict()` added;
  `route_verdicts_5_10()` reports the derived tcp verdict instead of the constant `Unknown`;
  `route_verdicts_other()` and the `route_verdicts()` dispatcher added; `select_route_5_10`
  renamed to `select_route` and reused for every family.
- `main.rs`: one route-selection path for all families (forced-route validation, ambiguity → exit
  7, zero-feasible fallback nomination).
- `tests/route_verdicts_ondevice.rs`: image-store test (2/2 passing).

Host gates: `cargo test --release` 91 tests (90 + 1 pre-existing ignored), no failures; release
build warning-free; `:app:assembleDebug`; the image tests run against the expanded store (both
`route_verdicts_ondevice` and `families_ondevice` pass; the exact run is in the evidence record).

Corpus results (`--analysis`; the 20 official-OTA Xiaomi ROMs added on 2026-10-26 are listed in
`external/port/route-verdicts-2026-10-26/upstream-6x-xiaomi.md`):

| train / images | tcp_zerocopy | cap / delta |
|---|---|---|
| 5.10 (43, 81×2, 101×3, 136×2, 177, 198, 209, 226, 236, 246 + custom 236×2) | Infeasible | 0x18/0x28; −0x50 (236), −0xa0 (81) |
| 5.15.194 | Unknown | futex waiter local not unique |
| 6.1 (25×2, 57, 75, 78, 115, 118×2, 138×2) | **Feasible** | cap 0x40, delta 0 |
| 6.6 (30, 56, 77) | **Infeasible** | cap 0x40, +0x10…+0x30 |
| 6.12 (23×3 builds, 30, 38, 69) | **Infeasible** | cap 0x40, +0x18 (23/30/38), −0x38 (69) |

Every 6.1 build sampled is Feasible and every 6.6/6.12 build is Infeasible — matching upstream's
route choice (`tcp_zerocopy` on 6.1, `select_stack` on 6.6/6.12). The 6.12.69 image exposed a
compiler shape where the 0xc bound and the cap check are split apart; a fallback (a single
plausible struct-size comparison in a function that carries the 0xc bound) resolves it to cap
0x40, with a unit test pinning the shape. 6.12.69 is also the corpus's first zero-feasible kernel
(select_stack is infeasible too: the futex waiter sits 18 qwords above the fd_set buffer), which is
reported honestly rather than silently picked.

One honest limitation: when the futex waiter local is ambiguous (the 5.15.194 image), the tcp
verdict is `Unknown` rather than derived — the pselect/futex derivation is a prerequisite.

**Device export (2026-10-27).** On the K90 Pro Max (`myron`, 6.12.23-g5a0e85, OS3.0.301.0.WPMMIXM)
the combined test build (this change + the parse advice) parsed the official-OTA `boot.img` +
`xbl_config.img` and exported a config. The QC xbl prompt fired; `select_stack` was the sole
Feasible route (tcp +0x18) and was selected without a dialog (`generation.meta`: `route_basis =
derived`); the stride picker measured 1280 (8/9, `/proc/slabinfo` 1280); the export is byte-identical
to the host generation from the same images except the picker's `mm_struct_sz`. Record:
`external/port/myron-6.12.23-export-2026-10-27/`.

## Non-goals

- Making `tcp_zerocopy` work on 5.x — impossible with this route (copy cap below the first fake
  word); a different delivery syscall would be a new route.
- 6.x derivations for `multicast_waiter` / `sigreturn` (they stay `Unknown` until evaluated).
- App changes.
