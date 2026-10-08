# W3-0 post-descent wedge — plan (2026-10-09)

Level: **L** (attack-critical path). Plan first, code after.

## What is measured (run 6, `GhostLock-P3-slots`)

- W1 ✓ (`SELinux permissive`), **W2 ✓ (`child uid = 0` → `child is root!`)**, then W3-0's dance.
- The log stops after `waiter parked; owner started` — the requeue (`CMP_REQUEUE_PI`) that W2
  reported immediately was never reached.
- The final walk, in order, with nothing after `ei`:

```
ks → rp(pi_bo=0xffffffc055bc3c30) → ka → rt_top d=0x1 → ew(+0x504) → ee(+0x51c)
   → r3/rz/ry/rx(+0x520) → el(+0x544) → en(+0x56c) → ei(+0x59c) → STOP
```

  Counts: 9 `ka`, 8 `ak` — one walk never returned.
- The descent read `root=0xffffff89da68d190` from `at=0xffffff802aa3a798`
  (= anchor slot 4 + 8). **That root value equals W3-0's target**, which is
  `child_task + task_comm_off` — the child's `comm` field.
- The death is a **wedge**: `kmsg.txt` empty, no oops markers, box hard-resets. (Run 5 behaved the
  same; the abrupt reset loses the unflushed kmsg.)
- The instructions after the descent are only two calls: `rb_insert_color()` at `+0x5a4` (resolved
  via `sym_at`, image offset `0xa77984`) and `__put_task_struct()` at `+0x5f0` (`0x125f38`).
- Inferred, not certain (the kretprobe pairing is LIFO): an earlier walk in the same run reached `ei`
  at 179.231723 and its `ak` came at 179.530273 — **298 ms later**, flags `dN.3`, i.e. interrupts
  disabled with need_resched set. Run 1's clean walk showed the same ~300 ms (`ka` → `ak` 304 ms).

## Hypothesis

The descent (the enqueue's search + link) completes. `rb_insert_color()` then rebalances by walking
**up** through `__rb_parent_color` — the loop at `+0x630` (`ands x9, x9, #~3; b.eq stop`) terminates
only when the masked parent is zero. The anchor's tree root is not NULL *and does not point at a
well-formed node*: it is the W3-0 target address, i.e. a **task field**, not an `rb_node`. Walking up
from there reads task memory as `rb_node` words, and the walk does not terminate — a spin with
interrupts disabled, which produces exactly what we see: no oops, no kernel text, watchdog reset.

This is the same family as the earlier finding in `CLAUDE.md` — *"a payload's child slots survive to
their erase only if the kernel re-links that node; a node with a live kernel pointer in a child slot
is fatal the moment the rb code descends through it"* — with one extension: **the rebalance walks
parents**, so a bogus *root* is as dangerous as a bogus child.

## Hints worth acting on

1. **The upward walk terminates on a zero parent.** So if the node the root points at has
   `__rb_parent_color == 0`, `rb_insert_color` breaks immediately on its `!parent` arm. That is the
   cheapest invariant to guarantee, and it is checkable with one probe.
2. **The tree should have been empty.** The anchor is now fresh per stamp, so at insert time
   `rb_insert_color` ought to degenerate to "this node becomes the root, no parent → break". It does
   not. **So something populates `rb_root` before the insert** — and the answer to *what* decides
   whether the fix is "stop populating it" or "make what it points at terminate".
3. Both candidate answers are consistent with the observed value, so this must be settled by reading
   the code, not guessed:
   - the stamped node itself becomes the root, and `0xffffff89da68d190` is the *node address*
     (plausible: word 2 is stamped `heap.current.fake_right`, i.e. a payload-page address, under the
     name `tree_pc`);
   - or the route deliberately stores the write target in the root, because the erase is the write
     vehicle that needs the target reachable from the tree.

## Step 1 RESULT (offline, no run) — the write itself plants the bogus root

- `util.cpp:397-418` writes a lock's tree fields, but it writes the **page** lock
  (`fake_lock = payload_base + LOCK_OFF`) — the option-1 object, with `rb_root = NULL`,
  `rb_leftmost = fake_w0`, `owner = fake_task | 1`. **Nothing writes the anchor's fields**; it is
  zeroed .bss and the route only points the waiter's `lock` word at it.
- So the `rb_root = 0xffffff89da68d190` seen at the descent cannot be configuration. It is a side
  effect of the walk: `__rb_erase_augmented`'s case 1 calls
  `__rb_change_child(node, child, parent, root)`, and with `parent == NULL` that is
  `WRITE_ONCE(root->rb_node, child)`. The compact table stamps `word 4 = request->target` as the
  node's `rb_left`, so `child == target` and **the write stores the target into the anchor's
  `rb_root`**.
- That fits the death exactly: a dance runs two walks (`task_blocks_on_rt_mutex`, then
  `remove_waiter`). The first performs the write and leaves `rb_root = target`; the second calls
  `rb_insert_color`, walks *up* from that "root" reading a task field as an `rb_node`, and spins.
- It also explains run 6's progress: per-stamp rotation gave each dance's **first** walk a clean
  tree, so the descent completed and the write landed — W2 included. The remaining hole is
  **intra-attempt**, between the two walks of one dance, which rotation cannot cover.

## Plan (revised)
2. **Probe, one run:** `ew` (+0x504) already fires on every walk that gets that far. Add fetches for
   `x27` (the lock), `*(x27+0x8)` (`rb_node`) and `*(x27+0x10)` (`rb_leftmost`). That gives the tree
   state at the descent on *every* walk, fatal or not — enough to tell "root is always the target"
   from "root became the target this time".
3. **Then the fix**, one of:
   - if the root is populated by accident: stop populating it (or clear it once per stamp);
   - if it is the write vehicle: make the node it points at terminate the upward walk — a clean
     `__rb_parent_color` of 0 at that address, which is a payload/stamp change, not a route change.
4. **Gates:** `make -C src ghostlock` 0 warnings + `lint-tidy` exit 0. `cmp_disasm` before any PR.

## ROOT CAUSE (run 8, 2026-10-09) — captured oops: `rb_insert_color+0x48`, NULL+8

The `sync` loop in `prep-oops-run.sh` made the capture durable and the oops finally survived the
reset:

```
Unable to handle kernel NULL pointer dereference at virtual address 0000000000000008
ESR = 0x96000005   (level-1 translation fault, read)
pc : rb_insert_color+0x48/0x164
lr : rt_mutex_adjust_prio_chain+0x5a8/0x1948     <- right after the bl at +0x5a4
x27: ffffff802aa3a790    the anchor (slot 4)
x1 : ffffff802aa3a798    = anchor + 8 = &waiters.rb_root
x0 : ffffffc058fdbc30    = x28 = the waiter (the node just linked)
```

**The write landing is what arms the fault.** In order:

1. The write's erase sets `anchor->rb_root = target` — the `__rb_change_child` side effect from step 1.
2. A later insert in the same stage links its node under that "parent" and calls `rb_insert_color`.
3. `__rb_insert`'s first test is `rb_is_black(parent)` = `*(target) & 1`. **W3-0 writes 0**, so bit 0
   is clear and the fake parent reads as **RED**.
4. Red parent ⇒ `gparent = rb_red_parent(parent) = *(target) & ~3 = 0`, then it reads
   `gparent->rb_right` (offset 8) ⇒ NULL + 8 ⇒ the fault.

So the probe's own success is what produces the crash — which is why the wedge followed every
successful W3-0 write and why nothing in the walk's descent was ever at fault.

### The fix

`rb_is_black(parent)` is the *first* test in `__rb_insert`. If the word the write leaves at the target
has **bit 0 set**, the parent reads BLACK and the insert breaks immediately — no grandparent read, no
fault. So the minimal fix is to make the written value odd.

Trade-off to weigh before coding: W3-0 writes 0 precisely to zero `comm` (the observed
`comm="ghostleaf_01234"` → `comm=""`), and `verify_leaf_dir_stage` branches on `comm_len == 8` vs
`== 0`. Writing 1 instead keeps it a detectable change but lands in a different branch of that
verifier. The alternative is route-level: never let an insert follow a write on the same anchor
within one stage — which is the intra-attempt hole the per-stamp rotation cannot close.

Note the rotation did its job: W2's write also leaves an even value, but W3-0 runs on a fresh slot, so
the pollution never crossed the stage boundary. The hole really is intra-stage.

## Fallback: skip W3-0 entirely (user's call, 2026-10-09)

`w3_exact_target` is a route capability — `route_policy.hpp:55` defaults it false, `:91` sets it true
for `TcpPolicy` — and `cve_2026_43499_backend.cpp:265` branches on it:

```cpp
constexpr bool exact_target = M::w3_exact_target;
if (!exact_target) { /* W3-0: leaf dir probe */ } else { run_state::complete("w3a"); }
```

So a route that already knows the exact target **skips W3-0** — the very stage that wedges here. The
app surfaces it as **Shizuku** (`runExploitWithShizuku`, strings "Run via Shizuku" / "Skip Seccomp
bypass", and `GhostlockViewModel.kt:119 maybeSuggestShizukuForW3()`, which offers it when W3 stalls).

**Use this if the post-descent wedge resists.** It does not fix the wedge; it routes around the stage,
which is enough to prove W3→handoff and to get the child's root propagated — and the app recommends it
for exactly this symptom.

Not a one-flag change: it is a different policy instantiation with its own prerequisites. Shizuku must
be installed and authorised on the device, and the TCP/`tcp_zerocopy` route is heap-staged — `CLAUDE.md`
records it as "needs its own window analysis", and this profile's `tcp_zerocopy` settings are all zero
(`attempts=0, arm_sequence=0, post_receive_hold_iterations=0`). So budget it as its own port, not a
switch.

## How this is judged

Next run: W1 and W2 still land, and the `ei → no ak` pattern is gone (either the walk returns or the
box stops somewhere else). If the walk still never returns but the trace now shows the root fetched
as the *node* address, the hypothesis is confirmed and step 3's second branch is the fix.
