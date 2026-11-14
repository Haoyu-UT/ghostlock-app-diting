# The route × carrier matrix in the option superset (plan)

Level: **L** — the superset is the app's public option document, and a runnable compat
variant adds a profile key (`compat_futex_abi` under `route.select_stack`), a wire/schema
change with the re-frozen digest and native-document golden. Plan first, then code
(`AGENTS.md`).

Status: **slices 1–4 implemented and device-gated 2026-11-14** (extractor + store, the
profile ABI path, the app carrier picker, the measured ship precedence, and the 6.1.138
compat-select device run). Operator requirement: *the extractor should be able to give
carrier × route combinations.* The motivating case is the 6.1.138 image, whose 64-bit
`select_stack` is feasible and whose AArch32 compat select also fits.

## The problem

`RouteVerdict` (`tools/extract_rs/src/analysis.rs`) carries one verdict per route name
(`select_stack`, `multicast_waiter`, `sigreturn`, `tcp_zerocopy`). A carrier variant is
folded into that entry as `numbers.compat_carrier = 1`, and
`apply_compat_select()`/`apply_compat_multicast()` **substitute** it only when the native
verdict is `Infeasible`:

```rust
let Some(select) = routes.iter_mut()
    .find(|v| v.route == "select_stack" && v.verdict == Feasibility::Infeasible)
else { return; };
```

So on 6.1.138 the compat select is never derived, and on 6.1.134 the derivation is
attempted but refused by the stale `waiter.wake_state.is_some()` gate before its geometry
is measured. The profile can already express either carrier — `route.select_stack` carries
`compat_carrier`, `waiter_home`, `select_dst_depth` — the superset simply does not
enumerate both.

## The model

Keep one **primary** entry per route; add the carrier dimension inside it. This is
additive and keeps every existing consumer's route-name lookup working.

```json
{
  "route": "select_stack",
  "carrier": "native",
  "verdict": "feasible",
  "reason": "...",
  "numbers": { ... },
  "anchor_capable": true,
  "geometry": { ... },
  "alternatives": [
    {
      "carrier": "compat",
      "verdict": "feasible",
      "reason": "...",
      "numbers": { "compat_carrier": 1, "waiter_home": 432,
                   "select_dst_depth": 480, "compat_futex_abi": 0 },
      "geometry": { "compat_carrier": 1, "waiter_home": 432,
                    "select_dst_depth": 480, "compat_futex_abi": 0 }
    }
  ]
}
```

- `carrier` is `native` or `compat` (the sigreturn and tcp routes are native only).
- The **primary** is the default and preserves today's bundle behavior: native when
  feasible, otherwise the compat variant (the current substitution).
- `alternatives` lists every other **feasible** carrier, each with its own numbers and
  geometry. An infeasible derivation is not listed; its reason stays in the primary's
  `reason` (today's behavior).
- The app's parser ignores unknown keys, and the ship script's `choose_route()` reads
  `route`/`verdict`, so slice 1 below is inert until a consumer opts in.

## Derivation

- For `select_stack` and `multicast_waiter`, derive the compat layout **in addition to**
  the native verdict whenever the geometry fits. Today the call sits behind two gates:
  the `find(... Infeasible)` guard and a `sigreturn`-feasible check in both
  `apply_compat_*()` functions; both go. The `sigreturn` pairing is not a runtime
  requirement: `carrier_requested()` is a profile flag and the middleware routes every
  write (W1, W2, W3, the repair) to the helper when it is set, the era G4 series carried
  the full chain on the compat select (10/10), and the bundled compat profiles set
  `fallback.to = "none"`. If a profile wants sigreturn as a fallback route, that is an
  explicit `fallback.to` policy, not a derivation gate.
- Fix the 6.x refusals in the same change:
  - `derive_compat_carrier_layout()`: drop the `waiter.wake_state.is_some()` refusal. The
    5.15/6.1 compact shape is the same eleven-word strip; `waiter_prio_word(...,
    compact_waiter_has_wake_state())` already builds its +0x40 word, and the 64-bit select
    and sigreturn routes use that fact.
  - `compat_carrier_coverage()`: take the ABI as an input from the futex entry that
    produced the home, not a `match home { 0x1b0, 0x1c0 }`. The ABI is a derivation
    result; the home is a depth.
  - The select compat geometry gains `compat_futex_abi` (the multicast compat block
    already carries it). This is the key that makes a 6.x variant runnable, because the
    runtime cannot recover the ABI from a novel home value.
- Geometry: `all_geometry` in `main.rs` is keyed by route; key it by `(route, carrier)`,
  or let each alternative carry its own geometry as above.

## Implementation status (slice 1, 2026-11-14)

The extractor slice is implemented and the store regenerated:

- `RouteVerdict` carries `alternatives: Vec<RouteVariant>`; `RouteOption` carries
  `carrier` and `alternatives[]`, each with its own `numbers` and `geometry`. The primary
  keeps today's meaning — native when feasible, the compat carrier when the native route
  is infeasible — so existing consumers and the bundle are unchanged.
- `apply_compat_select()`/`apply_compat_multicast()` no longer gate on `sigreturn` and no
  longer require the native verdict to be infeasible. The compat derivation runs
  independently, becomes the primary only when the native route is infeasible, and is an
  alternative otherwise. The select gate now refuses the non-compact `rt_waiter_node`
  shape (not the compact `wake_state` word), and the ABI is a derivation output carried as
  `compat_futex_abi`.
- Store (60 entries regenerated): **6.1.138** carries `select_stack` native + a `compat`
  alternative — home 0x1e8, `_newselect` dst 0x1f0, time64, packed at 0x8. **6.1.134**
  keeps `select_stack` infeasible; its reason now names the geometry (`futex_time32 home
  0x1e8` / `futex_time64 0x198` vs dst 0x1e0) instead of `wake_state`.
- The superset's compat multicast geometry now emits the compat keys
  (`compat_carrier`/`compat_*`), so an app cut of that route is runnable; it previously
  carried the native keys.
- Gates: 150 unit tests; `options_ondevice`, `route_verdicts_ondevice` and
  `cut_ondevice` pass on the regenerated store; `ship_golden_profiles.py --check` reads
  60 bundled / 0 missing / 11 exempt; the full release suite passes.

Slice 2 (the profile path) landed the same day: `compat_futex_abi` is a declared
`route.select_stack` key (`SelectStackLayout`/`kRouteSelect`); the bitmap planner takes it
and keeps the legacy home table only when absent; profile-core's `SelectConfig`, the
resolver's native-value map and the app's controller validation carry it. The schema digest
moved to `0x275387e01fa41b2a` (the native and Kotlin constants updated together), and the
native-document golden was re-frozen — bytes only, because the bundled profiles omit the
key. Gates: the native host suite, `make -C src ghostlock` (zero warnings), `lint-tidy`,
profile-core 60 and app 233 tests, all green.

Slice 3 (app picker) and slice 4 (precedence) landed the same day. `OptionSuperset` parses
`carrier`/`alternatives`; the parse-flow route picker offers every feasible carrier
(`RouteDisplay` already labels the ABI); the choice rides `ParseResult.Parsed.carrier` into
the plan cuts, and `cut(..., carrier = ...)` renders the chosen variant's geometry;
`OptionSupersetTest` covers the parse and the compat cut. The ship precedence is now the
measured `select_stack > tcp_zerocopy > multicast_waiter > sigreturn`; the one entry it
moves, 6.1.134, ships the compact AArch32 multicast (`compat_carrier = 1`,
`compat_futex_abi = 1`) instead of `sigreturn`. `ship --check` reads 60 bundled / 0 missing
/ 11 exempt; the app suite is 234 tests, profile-core 60.

Device gate (2026-11-14): the duchamp 6.1.138 ran the compat select from an external profile
with the derived home/ABI — **4/4 fresh boots** (one smoke + three series), **8/8 `compat
route` calls clean** per run, `exploit complete` T+14.5–14.9 s, `KernelSU ready`, store
completed. The profile's `compat_futex_abi = 1` is what the packer needs for 0x1e8; the
legacy home table would return `UnknownHome`. Evidence:
`external/port/route-carrier-duchamp-2026-11-14/`.

## Profile path (the runnable variant)

The compat select block currently carries `compat_carrier`, `waiter_home`,
`select_dst_depth`; the ABI is inferred at runtime by
`compat_bitmap.cpp::abi_for_waiter_home()` from the home constant. A 6.x home can be a
novel depth, so the ABI must travel:

- native: `SelectStackLayout` (`src/core/profile/model.h`) gains `compat_futex_abi`;
  `binary.cpp`'s `kRouteSelect` parses it; `plan_compat_bitmap()` uses it (the old
  home table stays as the legacy fallback when the key is absent);
- schema: the wire digest and the native-document golden are re-frozen;
- profile-core/app: `SelectConfig` carries the key and the validator accepts it;
- the extractor's `conf_compat_route_geometry()` emits it with the geometry.

No native route logic changes: the helper already takes `futex_abi` in its protocol.

## Consumers

- **App** (`OptionSuperset.kt`): parse `carrier`/`alternatives`; `route(name)` stays the
  primary; add a carrier-aware lookup and show both in the parse-flow route picker
  (`select_stack · 64-bit`, `select_stack · 32-bit compat`); `cut()` uses the chosen
  variant's geometry. Until this slice lands the new fields are inert.
- **Ship script**: no selection change. The bundle keeps the primary (native first, the
  compat substitution otherwise), so no asset moves.
- **Store**: regenerate the supersets; the new fields are serialized. `route_verdicts_ondevice`
  gains the alternatives expectations.

## Route order (measured, 2026-11-14)

The 2026-11-13/14 A/B series gives a route order that the carrier dimension does not change:

| route | current evidence | reading |
|---|---|---|
| `select_stack` | 10/10 on 5.10.236, 6.12.23 and 6.6.66; 10/10 compat on the era 5.10.81 | best |
| `tcp_zerocopy` | 8/10 + 10/10 on 6.1.138 (the A failures are a W2 cred miss and a page-W1 rejection); historical 3/5 and 5/10 | good |
| `multicast_waiter` | 10/10 on 6.1.138 (compat) + 4/5 on 5.10.236 ksun (native) with the drain fix; the no-fix arms read 8/10 and 0/5 | fine |
| `sigreturn` | 6/10 A / 2/10 B on 5.10.236; historical 8/15 and 5/12 | worst |

The carrier is a variant of a route, not a rank: a route uses its feasible carrier
(`select_stack` compat on 5.10.81, `multicast_waiter` compat on 6.1.134), and the matrix
exposes the others. Where a carrier is the only feasible one it decides feasibility, not
precedence; the measured differences between a route's two carriers are not large enough to
reorder the routes.

**Store scan (2026-11-14):** changing the ship precedence from
`select_stack > sigreturn > tcp_zerocopy > multicast_waiter` to the measured
`select_stack > tcp_zerocopy > multicast_waiter > sigreturn` changes exactly **one** bundled
route: 6.1.134 moves from `sigreturn` to the compact compat `multicast_waiter`. The other 59
entries keep `select_stack` (the 5.10 sigreturn-only kernels through the compat select). The
tcp/multicast order is a close call (18/20 vs 14/15) and changes no entry today.

Decision: the ship precedence should be the measured order with `sigreturn` last; 6.1.134's
first unit run becomes the compact multicast, with the dead-frame caveat recorded.

## Expected store outcome (2026-11-14)

| entry | primary | alternative | why |
|---|---|---|---|
| 6.1.138 (`…-g44bda9e8f6e9…`) | `select_stack` native | `select_stack` compat — **confirmed**: home 0x1e8, dst 0x1f0, time64 | the compat derivation now runs beside the native one; the ABI is derived, not matched on the home |
| 6.1.134 (`…-gd252f36df142`) | `select_stack` infeasible | none — **confirmed**: the reason names home 0x1e8/0x198 vs dst 0x1e0 | `_newselect` dst 0x1e0; time32 home 0x1e8 (base word not copied), time64 0x198 (needs [0x48,0xa0], copy ends ≤0x7e) |
| 5.10.81 | `select_stack` compat | none | unchanged; the native is infeasible |
| 5.10.236 | `select_stack` native | none | compat homes 0x200/0x210 are deeper than the 0x1e0 buffer |
| 6.6/6.12 | `select_stack` native | none | non-compact `rt_waiter_node`; the eleven-word stamp does not represent it |

No bundle moves: the ship script keeps the primary, and a compat primary is today's
substitution.

## Slices

1. **Extractor** — `carrier`/`alternatives` on `RouteOption`, the independent compat
   derivations, the 6.x gate fixes, the `compat_futex_abi` number/geometry, and the host
   tests; regenerate the 6.1.134/6.1.138 supersets first. Existing app/ship consumers
   ignore the new fields; the primary is unchanged.
2. **Profile path** — the `compat_futex_abi` key in the select block: native model/binary,
   the digest/golden re-freeze, `compat_bitmap` reading it, profile-core and the app
   validator.
3. **App picker** — parse the alternatives, show the carrier choice, cut the selected
   variant; `OptionSupersetTest`/`OptionSupersetDeviceCutTest`.
4. **Store and ship** — regenerate the corpus, `ship_golden_profiles.py --check`; no
   bundle change.

## Gates

- Extractor: `cargo test`, the unit tests for both carriers, and
  `route_verdicts_ondevice` with `GHOSTLOCK_IMAGE_DIR` set (the store tests still fail
  open without it — PORT-PLAN item).
- Native/profile: zero-warning build, `lint-tidy`, the native host suite, the wire digest
  and native-document golden re-frozen only for the new optional key.
- App: profile-core and app tests; a cut of the 6.1.138 compat alternative renders the
  compat block with the ABI.
- Device: **done 2026-11-14** — the duchamp (6.1.138) ran the external compat select 4/4
  (smoke + 3 series), 8/8 route calls clean per run; the 6.1.134 has no unit, so QEMU/host
  derivation remains its gate.

## Risks

- Duplicate route names in `routes` would break `route(name)`/`choose_route`; the
  primary-plus-alternatives shape avoids that.
- The geometry must be per carrier, or a cut renders the wrong block.
- The primary ordering must stay native-first for bundle stability and `--check`.
- The store tests' fail-open skip can hide a missing alternative.
