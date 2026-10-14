# The payload page's residue after destroy() — audit and plan (2026-10-12)

Level: **L** (attack-critical: the payload page's lifecycle, and what a later `fork()` may inherit).
Status: **audit complete, no code changed.** Owed by `PORT-PLAN.md`, the scrub item; the identity plan defers it
explicitly ("不动 reap / quarantine（Wall 2 残留另立计划）").

## The defect

`PayloadPage::destroy()` (`src/core/memory/heap_context.cpp:38`) closes the two reclaim fds and
then calls `clear_page()`. `clear_page()` is **bookkeeping only**: it zeroes the C++ fields
(`base`, `fake_*`, `reclaim.fd`, `state`). Nothing writes the *kernel page* those fds were holding.

That page is a reclaimed order-3 allocation carrying a fake `mm_struct` — plus the fake
`rt_mutex_waiter`, the fake lock and the fake fops table the walk and the write vehicle depend on.
When the fds close, the kernel returns the page to its slab **with every byte still in place**, and
the next allocation from that slab inherits them. The process that inherits is usually ours: the W2
victim `fork()`, the 272-child reap spray, the `slab_drain` waves — all of them allocate
`mm_struct`s in this same boot.

Two call sites release pages mid-boot:

| site | when |
|---|---|
| `release_quarantined_reclaim_sockets()` (`src/core/support/util.cpp:278`) | after a scratch-page repair succeeds — the page is released *because* the repair worked |
| the failure paths that destroy `current`/`prebuilt` | a lost race, a refused attempt, a new attempt's respray |

`HeapContext::init()` destroys `current`, `prebuilt` and `quarantine` outright
(`heap_context.cpp:93-95`).

## Why it does not show up in the port's series, and where it does

Every series in this repo reboots between runs, so each run starts on a fresh slab. A *user*
device does not: runs 2..N in one boot fork onto pages run N-1 released. The symptom is the
family of deaths already attributed to "the page was not what the walk thought it was"
(`payload-page-identity-plan.md` is the read-only instrument for exactly this question: the `ry`
probe reads `root`/`leftmost`/`owner`/`wait_lock` through the walk, `rz` reads the inert
`0xdeadbeefcafe` marker the payload writes at `LOCK_OFF + 0x80`, and neither can be rewritten by
the kernel).

## Fix options

**A — scrub through the reclaim socket before closing.**
The page's data is owned by the reclaim socket pair's skb; that relationship is *how* the page was
reclaimed (`SKB_SEND_SIZE = ORDER3_SIZE * 2`, `SKB_RECLAIM_SENDS = 4`). A final `send()` of a
zeroed buffer of the same shape, immediately before the fds close, should overwrite the fake
structures in place. One send/recv pair at teardown, no new kernel interaction, no change to the
write vehicle.
Risk: if the skb no longer references the page (a repack, a zerocopy decision, a different frag),
the send allocates a *new* page and the old one leaves dirty — so the fix ships with a falsifier,
not with a belief: after the scrub, read the page's `rz` marker through a probe; all-zero means the
scrub landed on the page we meant. (The same probe set answers it; no new primitive.)

**B — do not release: keep every page quarantined for the process's life.**
The `Quarantined` state and `quarantine` slot already exist. Make the release path a no-op (or
release only a page whose payload was never armed). The page then never returns to the slab while
the process lives; at exit the process is done and the reboot story takes over.
Cost: 2 fds + 32 KiB per orphaned page; a boot's ~8 runs × 2-4 pages ≈ 10 pages ≈ 320 KiB and ~20
fds — affordable, and bounded by the boot, not by the session.

**C — document and do nothing.** Honest, and wrong for users on a device that stays up for weeks.

**Recommendation: B first.** It is a lifecycle change with no new kernel interaction and no
falsifier risk; A is the follow-up if the fd/memory cost ever matters (a long-lived process with
many failed attempts). C is only acceptable if the port's README says "reboot between runs", which
it deliberately does not.

## Gates

- Native: `make -C src ghostlock` (0 warnings), `lint-tidy` (exit 0), and `heap_context_test`
  extended for whichever semantics are chosen (a quarantined page must not be destructible on
  scope exit — the trivial-destructor `static_assert` at `heap_context.h:83` already pins that).
- Device falsifier for A: one failed attempt with `rz` armed, read before and after the scrub.
- For B: one run series (the same 8-run/boot budget) plus an fd count per run
  (`/proc/<pid>/fd`), to show the cost is the bounded one above.
- Then the usual: a real-device gate on 5.10, and the record in `docs/analysis/`.

## Open questions

- Does a page still referenced by an skb ever return to the slab while the fds are open? (No by
  construction — but the identity probe can confirm it, and it is the assumption B rests on.)
- How many pages does one boot actually orphan today? Measure `release_quarantined_reclaim_sockets`
  calls per run before sizing anything.
- Is the W2 victim's `mm_struct` allocation (the child that must inherit a *real* mm) exposed to the
  same slab in practice, or does the spray's ordering keep it clear? This decides the priority, not
  the fix.
