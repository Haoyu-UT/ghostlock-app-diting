# W2 credential repair for the anchored select route (6.10+ cred layout)

Level: **L** (attack-critical path). Operator approval: "Just do it", 2026-10-28.
Status: implemented, host-gated, **device-gated on 6.12.23** (myron, 2026-10-28). The repaired
run's W2 verified on attempt 1 (`child uid = 0`, `child is root!`) and the chain completed with
8/8 anchored route calls (`state=completed`).

**Second device (OnePlus CPH2723, stock 6.6.66, 2026-10-28):** the anchored W1 and both W1p
writes verified, but W2 failed 15/15 with `child uid` = the low half of the W2 target — the same
bookkeeping-store signature as 6.12, on a 6.6 kernel, because this vendor kernel backports the
8-byte `cred.usage`. The release-gated repair was therefore off; the gate is now the anchored
route itself (see Design). **Re-run after the re-gate: full chain through the anchor** — 8/8 route
calls (slots 0–7), zero unverified, W2 attempt 1 with the repair at `init_cred+8`, `child uid =
0`, `exploit complete` T+49.9 s, `state=completed`, `KernelSU ready`
(`external/port/cph2723-stock-kernel-2026-10-28/run-5/`).

## Finding

The non-compact anchored `select_stack` route now carries W1 and W1p on 6.12, but W2 fails:

```
=== W2: cred === target=0xffffff8a1312e200 mode=2 leaf=0
[route] tree stamp pc=0xffffff8049c02a68 right=0x0 left=0xffffff8a1312e200
pselect route done calls=1 success=1 status=0 clean=1/1
child uid = 320004608            # 0x1312e200
```

`0x1312e200` is the low half of the W2 target: the child's `cred` *did* become
`init_cred`, but `init_cred.uid` now holds the target pointer's low half.

Mechanism (documented in `payload_builder.h` and the W1p comment): a value write
`{pc = value, left = target}` makes the erase perform **two** stores —

- `rb_set_parent_color(child = target, parent = value)` → `*(target) = value` (the
  credential switch, intended);
- `__rb_change_child(node, child = target, parent = value)` → `child` stored in the
  parent's child slot, i.e. **inside `value`**, at `value + 8`.

For W2 `value` is `init_cred`, so the second store lands at `init_cred+8`. Up to 6.6
`struct cred.usage` is `atomic_t` (4 bytes) and `uid` sits at +4, so the store hits
`gid` and the `getuid()` verify cannot see it (this is why 5.10/6.1/6.6 anchors pass
W2). From 6.10 `usage` is `atomic_long_t` (8 bytes): `uid` moves to +8, exactly the
store's landing site.

The page-based route does not perform that stack-tree erase (its vehicle is the
page's pi node), which is why the same phone passed W2 on the page path.

## Design

- `Profile::cred_usage_is_long()`: release-derived (major > 6, or 6.10+), mirroring
  `compact_waiter_has_wake_state()`'s parsing; an unparseable release returns false.
- `retry_write_stage()` gains an optional post-write request, issued after a
  successful route write and before the settle/verify. It is a normal
  `attack_write()` through the same route.
- `w2()` computes that request only when the active route is `select_stack` and its layout
  carries a `lock_anchor_image`. The request is
  `WriteRequest::make(data_alias(init_cred) + 8, WriteMode::Zero, leaf = 1)`.
  **The release test was dropped** (2026-10-28, OnePlus 6.6.66 device): the 8-byte
  `atomic_long_t` usage is a vendor backport, not a 6.10-only property — the stock 6.6.66 kernel
  has `uid` at +8 and produced exactly the 6.12 signature (`child uid` = low half of the W2
  target) while the version gate kept the repair off. The repair is inert on the 4-byte form
  (it zeroes `gid`/`suid` of `init_cred`, all zero), so gating on the route is both safer and
  more correct than any release predicate.
- The leaf write has **one** store (`child == NULL`, so `rb_set_parent_color()` is
  never called): `__rb_change_child(node, NULL, parent = target-8)` writes NULL at
  `parent+8 = target`. It zeroes `[uid, gid]`, which is `init_cred`'s pristine
  value, and is idempotent, so running it after every attempt is harmless.

Deliberately **not** changed: the W1p uid repair stays at `init_cred+4`. On 6.10+
that zeroes the usage pin's high half (usage keeps the 5.x positive shape,
~1e9) and leaves `uid` untouched (it is already 0 there); moving it to +8 would
leave the full 64-bit page address as `usage`, a negative `atomic_long_t`, which
is a different, untested pin shape.

## Risks

- The repair is one more route call per W2 attempt: ~2x anchor slots and time per
  ladder (15 attempts → 30 slots of 128 on the 6.12 zero page).
- A missed repair is treated like a missed write: the attempt is retried, the stage
  still fails closed.
- Gated off the page path and off 5.x/6.1/6.6, so no shipped family changes
  behaviour.

## Gate

Host: `make -C src ghostlock` (zero warnings), `make -C src lint-tidy`,
`make -C src native-host-tests`, `cmp_disasm` against a HEAD build.
Device: myron, same anchored profile, fresh boot; success = W2 verifies
(`child is root!`) and the chain continues past W2.
