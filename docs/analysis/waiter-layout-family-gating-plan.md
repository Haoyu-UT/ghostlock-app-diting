# Waiter layout vs kernel family — the 5.10 fix breaks 5.15 and 6.1 (plan, 2026-10-09)

Level: **L** (attack-critical path: payload layout, and it touches the profile→layout contract).
Audit findings first, plan second, code only after operator approval.

Status: **audit complete, no code changed.** This document is the record of the finding; the fix
is unstarted.

## Summary

The port corrected the fake waiter's priority word for 5.10 by rewriting a **shared, unguarded**
line in the page builder. That line is the encoding for *every* kernel that takes the compact
path, and `compact_waiter` is a **document-global boolean** covering three different
`struct rt_mutex_waiter` layouts. Consequence: **19 shipped 6.1 profiles and 5 shipped 5.15
profiles now build a waiter whose `prio` reads 0 (highest) on their kernels**, plus a second,
independent hit on the 6.1 profiles' `select_stack` fallback.

No 5.15 or 6.1 device was exercised in this audit. The field layout is **measured** (upstream
kernel headers); the consequence is **derived** from that layout plus the code, and is stated with
the falsification test in *Open questions*.

## The defect

`src/core/support/util.cpp`, in `prepare_skb_payload`, inside `if (compact)`:

```cpp
/* upstream — the word pair every compact family was written against */
put32(p, kernel::W0_OFF + 0x40, 0);                        /* wake_state */
put32(p, kernel::W0_OFF + 0x44, kernel::FAKE_WAITER_PRIO); /* prio  = 140 */

/* ours, 9acf2f1 — correct for 5.10, wrong for everyone else */
put32(p, kernel::W0_OFF + 0x40, kernel::FAKE_WAITER_PRIO); /* "prio" = 140      */
put32(p, kernel::W0_OFF + 0x44, 0);                        /* "5.10 padding"    */
```

The gate is a single global flag (`util.cpp:372`):

```cpp
int32_t compact = session::g_exploit_session.profile.has_compact_waiter();
```

and `model.h:278-280`:

```cpp
bool has_compact_waiter() const noexcept {
    return loaded_ && values_.misc.compact_waiter.value_or(0) != 0;
}
```

### Measured layouts

Source: `include/linux/rtmutex.h` / `kernel/locking/rtmutex_common.h`, mainline **v5.15** and
**v6.1** (both fetched and read field by field during the audit); 5.10 from the vendor tree
(`external/kernel-bsp/kernel/locking/rtmutex_common.h:27-39`) and confirmed live on diting.

| offset | 5.10 (diting) | 5.15 / 6.1 |
|---|---|---|
| 0x00 | `tree_entry` | `tree_entry` |
| 0x18 | `pi_tree_entry` | `pi_tree_entry` |
| 0x30 | `task` | `task` |
| 0x38 | `lock` | `lock` |
| **0x40** | **`int prio`** | **`unsigned int wake_state`** |
| **0x44** | *(padding)* | **`int prio`** |
| 0x48 | `u64 deadline` | `u64 deadline` |
| 0x50 | `ww_ctx` | `ww_ctx` |

`wake_state` was added ahead of `prio` and fills exactly the 4 bytes 5.10 uses as padding. So one
word pair cannot serve both, and the byte at 0x44 is a **different field** in each family.

### Why it is fatal, not cosmetic

`util.cpp` plants the same page waiter as the lock's cached leftmost:

```cpp
put64(p, kernel::LOCK_OFF + 0x08, 0);                          /* waiters.rb_root.rb_node = NULL */
put64(p, kernel::LOCK_OFF + 0x10, fake_w0);                    /* waiters.rb_leftmost = page waiter */
put64(p, kernel::LOCK_OFF + 0x18, fake_task | 1);              /* owner */
```

`rt_mutex_top_waiter()` is `rb_first_cached(&lock->waiters)`, i.e. that `rb_leftmost`. So on
5.15/6.1 the walk's top waiter **is this page waiter**, and its `prio` is compared by
`rt_mutex_waiter_less` against every real waiter. Our word at 0x44 reads **0** → highest priority
→ it wins every comparison.

That is precisely the defect this port fixed for 5.10 (`docs/analysis/` history, and the
mechanism restated in the comment now sitting at `util.cpp:473-478`):

> Writing the 6.6 pair here left prio = 0, so `rt_mutex_top_waiter()` returned this page waiter
> (prio 0 = highest) instead of the requeued stack waiter, and the "prio > 120 gates this erase"
> arm never ran.

We replaced a 5.10-shaped bug with the same bug aimed at 5.15/6.1.

Honest caveat: upstream also wrote `wake_state = 0`, which is not `TASK_NORMAL` (3) either — so
`wake_state` is evidently not consumed on this path and **`prio` is the load-bearing word**. The
route's stack stamp is inconsistent with the page builder upstream too (`(140 << 32) | 3` packs
`wake_state = 3`, `prio = 140`). Any fix should preserve upstream's `prio` semantics and not
speculatively "fix" `wake_state`.

## How it reached the other families

Three hops, none of them route-scoped:

1. **The flag is global.** `ProfileResolver.kt:36-61` resolves the native field `compact_waiter`
   to `route.<active-route>.compact_waiter` — *whatever* the active route is — which lands in the
   flat key `compact_waiter`, becomes `NativeProfileDocument.compactWaiter`
   (`profile-core/.../NativeProfile.kt:30`), and is emitted into the wire's **`kernel`** section
   (`NativeProfile.kt:212-216`). Native `kKernel[]` (`binary.cpp:115`) maps it to
   `misc.compact_waiter` — the same field `has_compact_waiter()` reads.
2. **The route's flag is the same global.** `model.h:305`:
   `.compact_waiter = values_.misc.compact_waiter`. So `select_stack_build_fdsets`'s `compact`
   (`select_stack_route.cpp:394`) is true for any profile that set the flag anywhere — including
   profiles whose *primary* route is something else.
3. **The fallback inherits it.** Every 6.1 `tcp_zerocopy` profile declares
   `fallback { to = "select_stack" }`. That fallback therefore enters the compact branch of the
   select route too.

The first and third hops are upstream's design; the port did not create the conflation. What the
port did was make the conflation **dangerous**, because before `9acf2f1` the compact branch was
written for the union of compact families.

## Blast radius

Builtin assets, `app/src/main/assets/kernel_profiles/` (73 files incl. templates):

| family | profiles | route | `compact_waiter` | verdict |
|---|---|---|---|---|
| **6.1** | **19** | tcp_zerocopy | `1` | **broken** — page builder (`util.cpp:479`); `select_stack` fallback additionally takes the 5.10 word table |
| **5.15** | **5** | multicast_waiter | `1` | **broken** — page builder (`util.cpp:479`) |
| 6.1 | 1 | select_stack (Meizu 21) | not set | safe — non-compact |
| 6.6 | 24 | select_stack | not set | safe — non-compact |
| 6.12 | 13 | select_stack | not set | safe — non-compact |

The 19 × 6.1 breakdown: 6.1.115 ×1, 6.1.118 ×2, 6.1.138 ×6, 6.1.145 ×5, 6.1.157 ×2, 6.1.162 ×3.
The 5 × 5.15: 5.15.41, 5.15.119, 5.15.167, 5.15.189 ×2.

Both defect lines are ours (`git blame` → `9acf2f1`):
`util.cpp:479-480` and `select_stack_route.cpp:511`.

### Second hit — the 6.1 fallback's stack stamp

`select_stack_route.cpp:511`, in the compact word table:

```cpp
/* ours */
{10, static_cast<uint64_t>(kernel::FAKE_WAITER_PRIO), "prio"},

/* upstream */
{10, (static_cast<uint64_t>(kernel::FAKE_WAITER_PRIO) << 32) | 3, "wake_prio"},
```

Word 10 is `waiter + 0x40` — `prio` on 5.10, `wake_state` on 5.15/6.1. Same conflation, second
site. Word 4 (`stamp.left`) and the tree/pi words are also 5.10-shaped for leaf requests, but
those offsets (0x00/0x08/0x10, 0x18/0x20/0x28) are **identical** across the three families — so
the only cross-family divergence in the table is word 10 and the *values* placed in the tree/pi
triple, which is a separate question tracked below.

## What is NOT affected

- **6.6 (24) / 6.12 (13) / Meizu 6.1 (1)** — non-compact `select_stack`. The port's changes on
  that path are the fd snapshot/restore (`765b137`) and the `pselect_put_waiter_word` read-back,
  which only logs; the write still happens. Both safe.
- **`route_policy.hpp`** — `if (profile.kernel_major() == 5) return true;` is 5.x-gated. The 5.15
  profiles already returned true via the multicast capability; 6.x is untouched.
- **`lock_anchor_image`** (Kotlin + `binary.cpp` + `model.h`) — optional and additive. Upstream
  profiles do not set it, so `lock_word` falls back to `fake_lock`, i.e. the previous behaviour.
- **`victim_process.cpp`** fd move (`c1b8569`) — a genuine cross-kernel fix; helps every device.

## Fix options

The discriminator, not the word pair, is the design question. `compact_waiter` currently stands in
for "which of three waiter layouts", and the three consumers (`prepare_skb_payload`,
`select_stack_build_fdsets`, the fake-task offset block at `util.cpp:502-521`) all need the same
answer.

**Option A — derive the family from the profile, keep one boolean.**
Branch the two words on `kernel_major`/release inside `util.cpp` and `select_stack_route.cpp`.
Small and local, no schema change, no Kotlin. Costs: the profile's release string becomes
load-bearing for a payload decision, which is the kind of implicit coupling that produced this
bug; a 5.15-vs-6.1 divergence later would re-open it.

**Option B — make the discriminator explicit in the profile.**
Add a waiter-layout enum (or a `waiter_wake_state` field) to the schema, defaulting to the current
compact meaning so existing profiles keep working, and have both call sites read it. Costs: a new
profile key is an L-level contract change on its own, with the documented silent-drop hazard
(`SelectConfig.from` / `ProfileResolver` / `SelectConfig.entries` — three sites can drop a route
key without a word; see the `lock_anchor_image` incident). Needs the round-trip test to go with
it.

**Option C — stop sharing the encoding.**
Keep `encode_compact_waiter`/`waiter_tree_stamp` as the single definition of the triple, but give
the *priority word* its own function taking the family, so no call site writes 0x40/0x44 by hand.
Best hygiene, but it is a refactor of the attack path and should not be bundled with the fix.

**Recommendation: A for the regression fix, then C as a follow-up**, with B only if a fourth
family appears. Rationale: the fix's job is to restore 5.15/6.1 to their upstream behaviour without
touching diting — the smallest change that does that is to make the two words family-dependent at
the two sites, and the port already has `kernel_major()` on the profile (`model.h:286`).
Whichever option is chosen, the rule to encode is: **`prio` is the load-bearing word; `wake_state`
keeps upstream's value; the byte at 0x44 is a different field per family.**

## Must be resolved before any upstream PR (found during the same audit, separate from the fix)

None of these are kernel-family-gated, so they affect **every** device:

1. **`threads.cpp`** — the new `futex_lock_pi` fallback guard
   (`!race->consumer_stop.load() && race->consumer_go.load() == seq`) applies to all kernels. It
   was justified on diting; it needs either 6.x evidence or a narrower scope.
2. **W3-0 `leaf` 1 → 0** (`cve_2026_43499_backend.cpp`) — changes that probe's write value on
   every device running the path. The comment argues the probe's observable branches are
   unchanged; that argument needs to be in the PR text.
3. **Diagnostics marked `LOCAL DIAGNOSTIC (not for upstream)` that are in the committed tree:**
   - the self-locating page fill (`0x7A5C…` tags over `[0, LOCK_OFF)` and `[0x2000, ORDER3_SIZE)`,
     `util.cpp`)
   - the `0xdeadbeefcafe` page-identity marker (`LOCK_OFF + 0x80`)
   - the detached `leaf watch` `/proc/<pid>/comm` poller thread (`cve_2026_43499_backend.cpp`)

   These run on every kernel and write into the payload page / spawn a thread. They are proven
   benign on diting (runs Q3 and Q4 completed end-to-end with them armed), but the fill leaves
   tags in page regions the payload does not explicitly overwrite, and the fake task/waiter
   structs are only partly written field by field — so on another family the unwritten remainder
   is tags rather than zeros. Remove all three before a PR, or gate them behind an explicit
   debug flag.

## Gates before the fix ships

Per `AGENTS.md`, this is an attack-path change:

- `make -C src ghostlock` — zero warnings
- `make -C src lint-tidy` — exit 0
- `tools/cmp_disasm.py` over the eight functions — **required this time**; the payload stamp
  changes
- `src/core/tests/` — `payload_builder_test` must extend to cover both word pairs, and
  `profile_binary_test` if the schema changes
- A real-device gate on **5.10** (diting) proving no regression, since that is the family the
  original fix served — plus, for the 5.15/6.1 claim, device evidence on at least one of them,
  which this port does not currently have.

## Open questions / falsification

- **The derived consequence is testable.** On a 5.15 or 6.1 device, read the page waiter's `prio`
  live (the diting kprobe rig already reads `W0_OFF + 0x40`-shaped words via
  `+offs(%reg)` derefs). Prediction: with the current tree it reads 0; with upstream's word pair
  it reads 140. That is the cheapest confirmation and it needs no attack run.
- **Does any shipped profile actually reach the compact branch at runtime?** Established by
  reading the resolver chain, not measured. The `lock_anchor_image` incident showed this pipeline
  can carry a key correctly to a *correct, active* document and still lose it later, so the
  remaining doubt is real. A round-trip test that asserts
  `route.tcp_zerocopy.compact_waiter` → `misc.compact_waiter` would close it, and is the same
  schema-driven test the earlier session flagged as missing.
- **How long has this been broken?** `9acf2f1` (2026-10-09) introduced it. Every 6.1/5.15 finding
  in this port predates it, so no earlier result is invalidated.

## Related

- `zero-write-odd-pc-plan.md`, `w3-descent-options.md` — the 5.10 prio defect and its fix; this
  document is the blast radius of that fix.
- `payload-page-option2-plan.md`, `payload-page-identity-plan.md` — the page builder this line
  lives in.
- `stale-waiter-lifetime-plan.md` — waiter lifetime, adjacent but a different mechanism.
