# Anchor slots: give the clean ones back — audit and plan (2026-10-12)

Level: **L** (attack-critical: the anchor allocator hands out the addresses the walk dereferences).
Status: **audit complete, no code changed.** PORT-PLAN items 11 and 11d; item 11c is fixed and
device-verified, and this plan must not weaken it.

## What the allocator does today

`route/anchor::acquire_lock_word()` (`src/core/route/lock_anchor.h`, implementation in
`lock_anchor.cpp`) is the single drawing point for both stack-stamp routes. It:

1. validates the profile's grid (`bytes` / `stride` / `slots` from the region the walk's fake
   `rt_mutex` lives in — `dump_skip.zeroes`, 128 slots of 32 bytes on diting);
2. reads the boot-scoped state file (`files/.ghostlock_anchor`, `<boot-id> <spent> <total>`),
   starting at 0 when the boot id differs (the region is zeroed again every boot);
3. reserves a **chunk of 8 slots** for the call and hands out slot indices from it, one per attempt.

So the budget is spent in chunks, not per attempt: a route call that ends on attempt 1 with
`calls=2 success=1` has still consumed its whole chunk (`anchor slots: reserved 0..7 of 128`), and a
run spends ~2 chunks per write × 3 writes ≈ 6-8 chunks ≈ 48-64 slots of the boot's 128. The
measured ceiling is **~8 runs per boot** (`external/port/rate-fix6/`).

Only a slot the walk actually read is *poisoned* (its content is no longer a pristine zero word).
The app knows which attempts that is: the consumer's counters (`consumer_calls`,
`consumer_success`) are non-zero exactly when the walk ran.

## The change

**Return the slots of attempts the consumer never called.** At the end of a route call, the number
of poisoned slots is known (`attempts_used` minus the trailing attempts with `calls == 0`), so the
allocator can persist `spent = chunk_start + poisoned` instead of `chunk_start + 8`. The next call
in the same boot draws from the returned range.

Design constraints:

- **The union rule stays.** Slots are handed out in increasing order and the file's `spent` is the
  high-water mark; returning means *lowering* it, so the file must be rewritten atomically
  (write a temp file in the same directory, then `rename`). A crash between the two leaves the old
  (more conservative) value.
- **A slot may only be returned if no walk could have read it** — i.e. the attempt never had a
  consumer call. "The attempt failed but the consumer did call" is NOT clean: the walk read the
  slot (that is what a failed write looks like) and left its tree pointers in it. The rule must be
  conservative in exactly one direction.
- **`acquire_lock_word`'s refusal path is unchanged**: a spent budget or an unrecordable
  reservation still returns 0 and fails the route. The new release API only ever lowers `spent`.
- The release must be persisted **before** the next route call can draw (same process, same
  call site ordering), and the log line should say what was returned (`anchor slots: returned
  N as clean; spent M/128`), because that is the number the next series measures.

Expected effect: a run that today spends ~48-64 slots would spend roughly half that (the winning
attempt is usually the second, and its chunk is fully clean beyond that), taking the per-boot
budget from ~8 runs to ~15 — which is what item 11 promised.

## 11d — one state file, two paths

The direct path keeps its state in `files/.ghostlock_anchor`; the Shizuku path runs the binary with
`GHOSTLOCK_HOME=/data/local/tmp/ghostlock-app` and keeps a *second* file there. Both spend slots in
the **same** kernel region, and the boot-id logic cannot see the other's spending — switching paths
inside one boot can hand out a slot the other already used. It also makes 11c's trust argument
unsound on the Shizuku path (its "no file + install predates the boot ⇒ region is zeroed" assumes
the file is the sole record).

Shape of the fix (same as PORT-PLAN 11d records): **one state file, chosen by the app and passed to
both paths** — `GHOSTLOCK_ANCHOR_STATE=<path>` in the environment, defaulting to the current
`files/.ghostlock_anchor` when unset. The Shizuku service passes the same value it would use
directly. Until that lands, the conservative interim is to stop passing
`GHOSTLOCK_ANCHOR_TRUSTED` across the AIDL (one line), which costs at most one reboot on a
first-ever Shizuku run.

## Gates

- A device series on 5.10 with the current build as the control: slots spent per run, from the
  log's `anchor slots:` lines, before and after (`external/port/rate-fix6/` is the baseline's
  8-runs-per-boot record).
- The failure side: a run whose attempts die must **not** return those slots — the falsifier is a
  run that fails twice and then completes, with the log's `returned N as clean` lines showing 0
  for the failed calls.
- 11c's three device cases re-run (install-after-boot refused; reboot then start at 0; next run
  reads the spent count) — the trusted-start path reads the same file this change rewrites.
- Native gates + host tests: `lock_anchor` has no host test today (the implementation is
  Android-only); the accounting logic that can be host-tested is the "how many trailing attempts
  were clean" rule, which should get one.

## Open questions

- Is the chunk size (8) load-bearing anywhere else — e.g. does any analysis assume
  `spent` only ever increases within a boot? (Grep the records for `already spent` before
  changing the semantics.)
- Does the walk ever read a *later* attempt's slot during an earlier attempt's stamp? The stamp
  writes only the slot it was given; the anchor is reached through `waiter->lock`, which is per
  attempt. The conservative rule above is safe either way, but the answer decides whether the
  release can be per-attempt rather than trailing-only.
