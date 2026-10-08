# Zero-write erase: odd pc + one-byte leaf backoff — plan (2026-10-09)

Level: **L** (attack-critical path: payload layout). Plan first, code after — approved by the
operator in session.

## Problem (measured, not inferred)

Every stage whose write value is a literal **zero** dies in the walk that performs it. W1 and W2
live; W3-0 dies; W3's real writes (`TIF_SECCOMP`, `seccomp.mode`) and the VR tag clears are the
same shape and would die next.

The split is in the request, not in the stage:

| stage | `leaf` arg | `preserve_child` | `layout.right` = pc | collateral `__rb_change_child` arm | survives? |
|---|---|---|---|---|---|
| W1 SELinux, W2 cred | 0 | true | `page+0x100` / `init_cred` | `parent = pc & ~3` ≠ 0 → into the pointer's child slot | **yes** |
| W3-0, W3 flags/mode, VR tags | 1 | false | **0** | `parent == 0` → `root->rb_node = leaf` | **no** |

`WriteRequest::make(target, mode, leaf)` sets `preserve_child = !leaf` (`payload_builder.h:32-36`),
and `payload_builder_fixed_vector_test`'s vectors confirm the polarity. The erase path
(`include/linux/rbtree_augmented.h:224-227`, verified in the vendor tree):

```c
tmp->__rb_parent_color = pc = node->__rb_parent_color;   /* *(leaf) = pc        */
parent = __rb_parent(pc);                                /* = pc & ~3           */
__rb_change_child(node, tmp, parent, root);              /* parent == 0 -> root->rb_node = leaf */
```

`pc` is *both* the value written and the parent pointer, so a zero write cannot have a parent:
`pc ∈ {0,1,2,3}` ⇒ `parent = 0` ⇒ **the successful write is what plants `leaf` in the lock's tree
root.** The walk then continues `[7] dequeue → enqueue`, and the enqueue's `rb_insert_color`
dereferences that root (`lib/rbtree.c`, `__rb_insert`):

```c
if (unlikely(!parent)) { ...; break; }      /* root NULL: safe */
if (rb_is_black(parent)) break;             /* reads *(leaf) & 1 */
gparent = rb_red_parent(parent);            /* *(leaf) & ~3 */
tmp = gparent->rb_right;                    /* read at 8 -> captured oops */
```

With `*(leaf) = 0`: even ⇒ RED ⇒ `gparent = 0` ⇒ fault at address 8. Captured 2026-10-09 run 8 as
`pc : rb_insert_color+0x48`, `x1 = anchor+8`, fault at `8`. It is **deterministic** — the dequeue
and the enqueue are inside one walk, so there is no userspace ordering primitive that can separate
them (the "IPC/lock" and "timing" routes are closed by measurement, `w3-post-descent-wedge-plan.md`).

## Fix

Two coupled changes, both in the stamped triple `{pc, right, left}`:

1. **`pc = 1`** (`kZeroWritePc`) instead of `0`, for every `!preserve_child` zero write. Bit 0 of the
   word at the leaf is then set, so `rb_is_black(parent)` is true and `__rb_insert` breaks on its
   first test — before any grandparent dereference.
2. **Leaf backed off one byte** (`kZeroWriteBackoff`): the erase writes at `target - 1` instead of
   `target`, so the eight written bytes are `01 00 00 00 00 00 00 00` starting one byte early. The
   field's low seven bytes are zeroed exactly as before, and the `0x01` lands on the byte before it.

The two are inseparable: `pc` is the value written, so `pc = 1` alone would leave `0x01` in the
field's own low byte — `comm[0] = 1` (probe fails), `seccomp.mode = 1` = `SECCOMP_MODE_STRICT`
(catastrophic for the child), `thread_info.flags = 1` (sets a live flag). Backing the write off one
byte keeps every field reading zero.

### Why this preserves the leaf-direction probe

`verify_leaf_dir_stage` branches on `strlen(comm)` and the write is 8 bytes at the leaf:

| leaf direction | before | after (leaf = comm−1) |
|---|---|---|
| kernel writes at `[leaf]` | `comm[0..7]=0` → `len 0`, `c0=00` | `comm[-1]=1`, `comm[0..6]=0` → **`len 0`, `c0=00`** |
| kernel writes at `[leaf+8]` | `comm[8..15]=0` → `len 8` | `comm[7]=1`, `comm[8..14]=0` → **`len 8`** |

Both branches are reproduced exactly, `c0` included, so the probe's meaning and the downstream
`leaf_to_target8` contract are untouched. `comm[7]` (and `comm[15]`) are left as they were.

### Scope

Only `!preserve_child`. The pointer-valued layouts must **not** be touched: W1's semantics depend on
byte 0 of the written word being `0x00` (`selinux_state.enforcing = 0` → permissive) and byte 2's bit
0 being set (the page-reclaim retry in `payload_write_layout_accepts_page` exists for exactly that).
Flipping their low bit would set `enforcing = 1`.

Single source of truth: `memory::write_destination(request)` in `payload_builder.h`, used by
`payload_write_layout()` (which stores it in `layout.left`) and by the route's stamp, so the two
cannot drift.

## Files

- `src/core/memory/payload_builder.h` — `kZeroWritePc`, `kZeroWriteBackoff`, `write_destination()`,
  the mechanism comment.
- `src/core/memory/payload_builder.cpp` — `payload_write_layout()` sets `left`/`right` per the table;
  `encode_compact_waiter()`'s payload branch uses `layout.left` (was `request.target`, identical for
  the pointer layouts); `payload_write_layout_matches_request()` states the new invariant; the fixed
  vectors are updated and gain an odd-pc check.
- `src/core/route/select_stack_route.cpp` — compact waiter word 4 (`tree_left`) becomes the
  destination; the stamp is logged (`pc`, `left`, `target`) so the run's app log carries the
  falsifiable values.
- `src/core/support/util.cpp` — the payload page's pi node `left` follows `write_layout.left` (was
  `request->target`), so the page-side vehicle and the stack stamp carry the same leaf.

## Known limitation (state it, do not paper over it)

`rb_is_black()` protects the insert **only if the descent stops at the root**. The descent
(`rb_add_cached`'s `while (*link)`) starts at the root word — now `target-1`, holding `1` — so it
enters, then reads the "node's" children at `target+7` and `target+0xf`, which are task_struct words
we do not control. Run 8's oops showed the descent terminating on this build (the fault was later,
in `rb_insert_color`), but the backoff moves those two reads by one byte, so this is an
observation to re-confirm, not an invariant. Both probes for it are already armed (`el` +0x544,
`en` +0x56c) and the run's trace decides it.

## Gates

- `make -C src ghostlock` — 0 warnings.
- `make -C src lint-tidy` — exit 0.
- `payload_builder_test` compiled and run **on the host** (its sources are freestanding C++; the
  full `native-host-tests` target cannot build on x86_64 — unguarded ARM64 `"yield"` asm in
  `tcp_zerocopy_route.cpp`).
- `tools/cmp_disasm.py` — required before any upstream PR (no attack *disassembly* changed here, but
  the stamp layout did; run it before opening one).

## Predictions for the next run (all falsifiable)

1. App log: W1 lands, `child uid = 0` / `child is root!` — unchanged (pointer layouts untouched).
2. App log: `[route] tree stamp pc=0x1 left=<target-1> target=<target>` for the W3-0 attempts.
3. Trace: `rz`/`rx`'s `root` == **target − 1** (not `target`) and `at` == anchor + 8 — the write's
   collateral now holds an odd word.
4. Trace: the fatal walk's `ei` (`rb_insert_color`) returns — `ak` follows the walk, and `el`/`en`
   do not spin.
5. App log: the first-ever `leaf dir probe comm_len=0 comm[0]=00` + `leaf=1 write lands on [target]`
   (the verifier ran before only when the route survived).
6. No wedge, no reboot; the run proceeds to `W3: TIF_SECCOMP+mode attempt 1/…`.

If (4) fails with `el` looping, the descent is the remaining hazard and the next iteration attacks it
directly (the two words at `leaf+7` / `leaf+0xf`).

## Rollback

The change is **uncommitted** (working tree, on top of `765b137`), as everything else in this port is.
Revert the five files with `git checkout -- src/core/memory/payload_builder.h
src/core/memory/payload_builder.cpp src/core/route/select_stack_route.cpp src/core/support/util.cpp
src/core/session/backend/cve_2026_43499_backend.cpp` — note this also reverts the earlier uncommitted
batch D/E payload work in `util.cpp` and `select_stack_route.cpp`, so prefer a targeted reverse-patch.
The previous behaviour is `kZeroWritePc = 0` with no backoff; the previously installed APK is
`external/port/GhostLock-P4-leafwatch.apk`.
