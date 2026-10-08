# The descent hazard after run Q1 — option register + option 1 plan (2026-10-09)

Level: **L** (attack-critical payload layout). Option 1 approved by the operator in session; the
register records all four so nothing is lost.

## What run Q1 established

The odd-pc + backoff fix (`zero-write-odd-pc-plan.md`) did exactly what it was built for — `pc = 1`,
write at `target-1`, `comm` still reads empty, the polluted root holds `target-1`, `rb_insert_color`
no longer faults, W1 ✓ and W2 ✓ (`child is root!`). The walk then died one step earlier, in the
enqueue's descent:

```
Unable to handle kernel paging request at virtual address 00333231305f66a1   (= garbage + 0x40)
pc : rt_mutex_adjust_prio_chain+0x548/0x1948     lr : +0x4f4
x12 = x11 = 34333231305f6661  <- ASCII "af_01234", read from comm+7, treated as an rb_node
x1  = ffffff802aa3a798        <- &anchor->waiters.rb_root
x8  = 0x78                    <- our stamped prio (the less() left operand)
```

Trace `ew → ee → rz/ry/rx → el → el → oops`: the descent entered the root (= `target-1`), took
`parent = leaf`, `less()` chose `rb_right` = `*(leaf+8)` = `*(comm+7)` ≠ 0, descended into that word as
a node, and `rt_mutex_waiter_less` faulted at `garbage + 0x40`. Artifacts:
`external/port/q1/{oops.txt,kmsg.txt,trace.log,applog.log}`.

**The structural statement.** A write whose value has no parent pointer (`pc & ~3 == 0`, i.e. any
literal zero or one) necessarily takes the erase's `parent == NULL` arm, which stores the write
destination into the lock's tree root — and the walk's `[7] dequeue → enqueue` then descends *through
the write target* as if it were an `rb_node`. The previous session's rule — *a node with
`left = target` must never be descended from* — is therefore violated by construction for every
zero-valued write. The layouts that survive are exactly the ones whose collateral lands somewhere
else, which is why W1/W2 (pointer-valued `pc`) have landed in every run.

The descent's branch is `less(ins, parent)` = our stamped `prio` vs `*(leaf + 0x40)` — a task word we
do not control. Run 8 (unshifted leaf) read `*(comm+0x40)`, went **left** to `*(comm+0x10) = 0`, and
exited — which is why its fault was later, in `rb_insert_color`. Run Q1 (backed-off leaf) read
`*(comm+0x3f)`, went **right** into ASCII. **Run 8's survival was luck on one word, not structure.**

## Option register

| # | option | what it changes | cost / risk | status |
|---|---|---|---|---|
| **1** | **Make W3-0 a pointer-value write** (`leaf=0`: `pc = page+0x100`, `left = target`) | the probe's payload value only | one argument; observables provably identical | **approved, implementing now** |
| 2 | Flip the descent branch deliberately (`prio = 0` ⇒ prefer `rb_left`) | the stamped `prio` word | which of the two child words is zero is unknown — 50/50, and a wrong guess costs a reboot | held |
| 3 | Measure the neighbourhood first (read-only probe on `__sched_setscheduler`, `x0` = task, fetching `+comm_off+7 / +0xf / +0x3f`) | nothing in the payload | one recon run; no new hazard | **next after 1**, before any flags/mode work |
| 4 | Carry the zero write on a node whose tree root lives in the payload page (fake task's `pi_waiters`) | which node is the vehicle | re-opens the geometry the anchor replaced; build N's stack-pi failure came from `rb_link_node` wiping children — the *page* waiter's pi node is never re-linked, so it is untested rather than known-bad | held |

Options 2–4 are recorded here so a future session does not re-derive them.

## Option 1 — design

W3-0 is a *probe*: it only needs to learn whether the pselect route's erase stores at `[target]` or
`[target+8]`. That is a property of the erase arm, not of the value stored, so the value can be any
value whose low byte is `0x00` — and the layout already has one: `page_base + 0x100` (the value W1
writes), whose low byte is zero by construction and whose parent pointer is real, so the collateral
lands **inside the payload page** instead of on the lock's tree root.

The descent then behaves like W1/W2's — the shape that has survived every run:

1. The erase stores `page+0x100` at `target` (so `comm[0] = 0x00`), and `__rb_change_child` writes
   `target` into `*(page+0x100 + 8 or 0x10)` — inside our page, harmless.
2. The lock's tree root still holds the node (the waiter), so the enqueue's descent reads the node's
   own stamped children `{right = 0, left = target}` with `ins == parent` (the same waiter) ⇒
   `less()` is false ⇒ `rb_right` ⇒ `*link = 0` ⇒ **the descent exits on its first test.**
3. `rb_link_node(node, node, &node->rb_right)` makes the node its own parent, and `rb_insert_color`
   rotates among `{node, node, node}` and `root` — every address valid, no chase.

### Observable equivalence (why the probe stays honest)

`verify_leaf_dir_stage` branches on `strlen(comm)` and `comm[0]`:

| leaf direction | value 0 (leaf=1, before) | `page+0x100` (leaf=0, option 1) |
|---|---|---|
| stores at `[target]` | `comm[0..7] = 0` → `len 0`, `c0=00` | `comm[0] = 0x00`, rest = pointer bytes → **`len 0`, `c0=00`** |
| stores at `[target+8]` | `comm[8..15] = 0` → `len 8` | `comm[8] = 0x00` → **`len 8`** |

Identical branches, identical `c0` for the `[target]` case. `leaf_to_target8` and everything
downstream of it are unaffected.

### What does *not* change

- The real W3 writes (`TIF_SECCOMP`, `seccomp.mode`) stay `leaf=1` zero writes. The odd-pc fix stays:
  it removed a real fault (the insert) and is a strict improvement for them — if their descent stops at
  the leaf, `rb_is_black()` now ends the insert cleanly. Their descent remains the coin flip this
  register's option 3 exists to settle.
- The W1/W2 pointer layouts, the anchor rotation, the stamp read-back, the leaf-watch diagnostic.

## Implementation

One argument: `retry_write_stage<M>(…, victim::verify_leaf_dir_stage, &w3_context, 1)` → `0`, with a
comment recording why. `leaf` maps to `preserve_child = !leaf` (`payload_builder.h:32-36`), so `0`
selects the pointer-value layout and `left = target` (unshifted) via `write_destination()`.

## Gates

`make -C src ghostlock` 0 warnings · `make -C src lint-tidy` exit 0 · `payload_builder_test` on the
host. `cmp_disasm` before any PR.

## Predictions for the next run

1. `=== W3-0: leaf dir === target=… mode=1 leaf=0` and
   `[route] tree stamp pc=0xffffff89…0100 left=<target> target=<target>` (pointer pc, **left == target**).
2. Trace `rz`/`rx`: `root` is a **stack address** (the waiter), not the target — the collateral left
   the anchor's root alone.
3. The descent exits: `el` once, no chase, `ak` follows the walk and the walk returns.
4. **First ever**: `leaf dir probe comm_len=0 comm[0]=00` + `leaf=1 write lands on [target]`, and the
   route returns → `W3: TIF_SECCOMP+mode attempt 1/…`.
5. W1 and W2 unchanged.

If (3) fails the same way, the descent-from-the-node path is not what saves W1/W2 and option 3 (measure
first) becomes mandatory before anything else.

---

# Run Q2 (2026-10-09 ~02:00) — option 1 worked, and the descent hazard is now fully characterised

## Result: the probe passed for the first time ever

```
[+] child is root!                                   <- W2 ✓ (third run in a row)
=== W3-0: leaf dir === target=0xffffff8980e75190 mode=1 leaf=0     <- option 1 ✓
[route] tree stamp pc=0xffffff897b898100 left=0xffffff8980e75190 target=…5190   <- pointer pc, left == target ✓
leaf watch: comm=""
[route] tree stamp pc=0xffffff897efd8100 left=… left=…          <- attempt 2 (fresh page)
leaf dir probe comm_len=0 comm[0]=00                 <- ★ the verifier ran, first time ever
W3: TIF_SECCOMP+mode attempt 1/6                     <- ★ reached the real W3 writes, new ground
=== W3: TIF_SECCOMP === target=0xffffff8980e74a00 mode=1 leaf=1
[route] tree stamp pc=0x1 left=0xffffff8980e749ff target=…4a00   <- the zero write, odd pc + backoff
```

W3-0 verified (`comm_len 0` → `leaf_to_target8 = 0`), the route returned, and the run advanced into
`W3: TIF_SECCOMP` — the first time this port has ever got past the probe.

## The death, and what it settles

Same hospital, different patient (`external/port/q2/oops.txt`):

```
Unable to handle kernel paging request at virtual address 000000aa47e00040
pc : rt_mutex_adjust_prio_chain+0x548/0x1948
x12 = x11 = 000000aa47e00000   <- the "node" word the descent chased
x26 = 1                        <- our pc, live
x8  = 0x78                     <- our prio
x1  = ffffff802aa3a898         <- &anchor->waiters.rb_root (slot 6, +0x300 — matches the app log)
```

`x13 = 0x10` (Q1 had `x13 = 8`) — so this time `less()` chose **rb_left** (`*(leaf+0x10)` =
`*(task+0xf)`) and the word there was `0x000000aa47e00000`, a **page-table/physical** value (the target
was `thread_info.flags` at `task+0`; `task+0xf` lands in `thread_info.ttbr0`). Chased as a node, faulted
at `+0x40` in `rt_mutex_waiter_less`.

**Two data points, two targets, two different branches, both nonzero:**
- comm, `less()` → right → `*(comm+7)` = ASCII `"af_01234"` (Q1)
- flags, `less()` → left → `*(task+0xf)` = a TTBR0 physical value (Q2)

⇒ **Option 2 (flip the branch with `prio`) is dead**, and **option 3 (measure the neighbourhood first)
is answered**: both child words are nonzero for both targets, so measuring only confirms the chase. The
descent always enters the fake node and always chases.

## The real answer — option 5: make the erase childless and steer it with a *parent*

Re-read `__rb_erase_augmented`'s first arm in the vendor tree
(`include/linux/rbtree_augmented.h:205-222`):

```c
	struct rb_node *child = node->rb_right;
	struct rb_node *tmp = node->rb_left;
	...
	if (!tmp) {                        /* rb_left == 0 */
		pc = node->__rb_parent_color;
		parent = __rb_parent(pc);      /* = pc & ~3 */
		__rb_change_child(node, child, parent, root);
		if (child) { child->__rb_parent_color = pc; rebalance = NULL; }
		else rebalance = __rb_is_black(pc) ? parent : NULL;
```

**`pc` is not stored anywhere as a value in this arm.** With `rb_left == rb_right == 0` the erase is
pure collateral, and `__rb_change_child(node, NULL, parent, root)` is:

```c
	if (parent) {
		if (parent->rb_left == old) WRITE_ONCE(parent->rb_left, new);   /* parent+0 */
		else                        WRITE_ONCE(parent->rb_right, new);  /* parent+8 */
	} else                          WRITE_ONCE(root->rb_node, new);
```

So a **childless node whose `pc` is a real pointer** writes **NULL** into `parent+0` or `parent+8` —
and never touches the tree root. Choose `pc = target - 8`:

- `parent = target - 8`; `parent->rb_left` is the task word at `target-8`, which will not equal the
  waiter's stack address ⇒ the **else** branch ⇒ NULL written at `parent+8` = **`*(target)`** ✓ — the
  zero write the stages need.
- `parent != 0` ⇒ **the lock's tree root is never polluted** ⇒ the enqueue's descent reads the node's
  own children — both stamped `0` ⇒ **it exits on its first test regardless of `less()`** ⇒
  `rb_link_node(node, NULL, &root)` ⇒ `rb_insert_color` breaks on `!parent` ✓✓.
- `pc` is 8-aligned ⇒ `__rb_is_black(pc)` false ⇒ `rebalance = NULL` ⇒ no `__rb_erase_color()` pass.
- Worst case (the word at `target-8` happens to equal the node): the write lands at `target-8`, the
  stage's verifier sees no change and reports "comm untouched" — a clean retry, not a crash.

**This is the working CPH2521 reference's shape** (`external/ghostlock-oneplus`: `{pc = target-8,
right = value, left = 0}`) with `value = 0`, and it is what upstream's own `encode_compact_waiter()`
second branch emits for a leaf request (`{parent, 0, 0}`). The port's route replaced it with the
tree-entry payload (`{pc = value, right = 0, left = target}`) — *that substitution is the root cause of
the entire descent saga*, and it also explains why the port had to bolt the payload onto a node whose
tree the kernel re-enqueues.

### Implementation sketch

1. `payload_builder.{h,cpp}`: for the leaf/zero layout set `right = 0`, `left = 0`, keep
   `parent = target - 8`; **revert `kZeroWritePc`/`kZeroWriteBackoff`** (no value is written in this
   arm, so the odd-bit workaround is obsolete — the insert is safe by construction).
2. `select_stack_route.cpp`: for a leaf request stamp `{tree_pc = fake_parent, tree_right = 0,
   tree_left = 0}`; keep `{fake_right, 0, target}` for the pointer layouts. Expose the choice as one
   helper in `payload_builder` so the route and the encoder cannot drift.
3. `util.cpp`: the page's **pi** node follows the same rule for leaf requests; its **tree** node stays
   `{1, 0, 0}` (the deliberate root-clear parking node).
4. Gates: NDK 0 warnings · `lint-tidy` · `payload_builder_test` on the host · `cmp_disasm` before PR.

### Predictions

1. `tree stamp pc=<target-8> left=0x0 target=<target>` for the zero-write stages.
2. Trace `rz`/`rx`: `root` is a **stack** address (the waiter) — the anchor's root is untouched.
3. `el` once, no chase, `ak` follows; the walk returns.
4. `W3: TIF_SECCOMP … attempt 1/6` reports the write landed (`verify_seccomp_probe_stage` → the child's
   `finit_module` probe returns a normal errno) and the run continues to `seccomp.mode`.
5. W1/W2 unchanged.
