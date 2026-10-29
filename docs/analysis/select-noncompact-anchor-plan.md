# `select_stack` lock anchor on non-compact families (6.6 / 6.12)

Level: **L** (attack-critical path). Operator approval: "fix it and test again", 2026-10-28.
Status: implemented, host-gated, **device-gated on 6.12.23** (myron, 2026-10-28). Run-2 showed the
anchor live in the non-compact branch (`lock anchor:` lines, the anchor slot in the waiter's lock
word) and W1 verifying on attempt 1; run-3 completed the whole chain through it (8/8 anchored route
calls, `state=completed`), after the separate W2 repair (`w2-anchored-cred-repair-plan.md`).

## Finding

The anchored `select_stack` path exists only in the compact waiter branch:

- `src/core/route/select_stack_route.cpp`: the anchor acquisition and the stack-waiter stamp
  words live inside `if (compact)` (line 427, anchor at 473-499, words at 526-551).
- The non-compact branch (`else`, 566-582) hardcodes `heap.current.fake_lock` as the waiter's
  `lock` word and writes zero tree words. It never reads `layout.lock_anchor_image`.

Consequence: on 6.6/6.12 a `lock_anchor_*` triple is silently inert. Measured on the myron
(6.12.23) 2026-10-28: the anchored profile was applied and selected, the resolved document and
the wire `profile.bin` both carried the triple, and the route ran the page path with no anchor
line (`external/port/myron-select-anchor-2026-10-28/`).

## Design

Mirror the compact anchored design into the non-compact branch. The anchored select mechanism is
not compact-specific: the anchor only decides **where the walk's `rt_mutex` tree lives**
(`payload-page-option2-plan.md`: the W1 write comes from the stack waiter's tree entry and is
independent of the lock's address; the page is still prepared for W2/W3).

Changes in `select_stack_build_fdsets()`:

1. Hoist `lock_word` and the `anchor::acquire_lock_word()` call out of `if (compact)` so both
   branches share one acquisition and one slot serial.
2. Hoist `stamp_layout` likewise.
3. In the non-compact branch, when an anchor is present:
   - words 2/3/4 (tree `rb_parent_color`/`right`/`left`) = `memory::waiter_tree_stamp(...)`,
     exactly the triple the compact branch and the page builder's pi node use;
   - word 13 (`lock`) = the anchor slot;
   - words 7-9 (pi entry) stay zero ("a zero pi node stays out of every erase and every
     descent"), words 5/6 and 10/11 (tree/pi prio and deadline) keep their current values;
   - `task` (word 12) stays `slide_init_task()`, `wake_state` (word 14) stays 3.
   Without an anchor, the branch is byte-identical to today: zero tree words, page `fake_lock`,
   the page's crafted pi-node stamp remains the only write vehicle.

The 6.6+ waiter stores its sort keys in `rt_waiter_node.prio/deadline` and the kernel overwrites
them from the task on enqueue (`waiter_update_prio()`), so the stamped 1/0 prio words are not
load-bearing for the write; the rb_node triple at offset 0x00 is the same three words on every
family.

## Risks

- **The enqueue may clobber the stamp** (`rb_link_node()` rewrites parent/left/right). If it
  does, the anchored non-compact run ends as a clean-but-unverified write — the same signature as
  a zero anchor that does not drive the walk — with no crash, because the anchor's descent exits
  on its first test either way. The device run decides; the fallback is the page's pi-node stamp
  with a populated two-stage anchor, which is out of scope here.
- **Wrong pointer → oops.** The stamp is the same one the compact path uses; on 6.6 it would be
  consumed by the same `rb_erase`. A bad walk is visible as a reset, and the phone recovers.
- No wire/Kotlin change: the transport already carries the triple (verified on the 6.12 run), so
  this is native-only and the same profile is the test artifact.

## Gate

- Host: `make -C src ghostlock` (zero warnings), `make -C src lint-tidy`,
  `make -C src native-host-tests`, `tools/cmp_disasm.py` (attack path; the fd_set builder is not
  one of its eight functions, record the counts anyway).
- Device: myron (`a096aa12`, 6.12.23-g5a0e85, app build 663 + this change), the same
  `myron-6.12.23-select-anchored.conf` (`+0x265fa70 / 0x1000 / 32`), one fresh-boot run.
  Success = the run log shows the route's `lock anchor:` lines **and** W1's write verifies
  (`[+] SELinux permissive`). A clean-but-unverified W1 with the anchor lines present means the
  stamp did not survive the enqueue; no anchor lines at all means the profile did not reach the
  layout (a regression to investigate).
