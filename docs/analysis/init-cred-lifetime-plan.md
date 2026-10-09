# `init_cred` lifetime — the residual W2 failure, root-caused

Status: **root cause identified, fix designed, not implemented.** L-level (it adds a write on the
attack path and a new profile key). 2026-10-09.

## Symptom

In two independent series (`external/port/rate-fix4`, `external/port/rate-fix5`) the same shape:
**the first ~4 runs of a boot pass, then every later run fails W2** and is retried 15 times before
the stage gives up. A reboot restores it. Each failure costs ~30 of the boot's 128 anchor slots,
which is why the series then ends in budget refusals.

## What was measured

**The write lands, even in the failing runs.** `scripts/watch-victim-cred.sh` samples the victim's
`real_cred`/`cred` fields through a kprobe for the whole run. Passing run (run 2 of `rate-fix5`):

```
3919.193131:  rc=0xffffff89a4891d80  cred=0xffffff89a4891d80     <- forked, shares the app's cred
3920.416033:  rc=0xffffff89a4891d80  cred=0xffffff802a7b0a60     <- init_cred: the write landed
```

Failing run (run 5) — **identical**:

```
4061.923670:  rc=0xffffff878c619840  cred=0xffffff878c619840
4063.031513:  rc=0xffffff878c619840  cred=0xffffff802a7b0a60
```

So the leaf-layout vehicle works. What fails is what happens *after*: the child, now rooted, oopses
~1.6 s later in `selinux_file_permission+0x58`, and W2's verifier (whose two silent returns now log,
`victim_process.cpp`) reports `reply read 0 of 4 bytes (errno=0)` — EOF — then `errno=32` (EPIPE)
for all 14 remaining rounds. The child is dead, not mute.

**And `init_cred` itself is corrupted.** Same address (`image +0x27b0a60`, `+0x78` = `security`),
read live at two times in one boot:

| uptime | `usage` | `security` |
|---|---|---|
| 2949 s | `4` | `0xffffff87b7bc9600` (valid blob) |
| 4226 s | `0xfffffffe` (**-2**) | `0` |
| 67 s (after the run-8 reboot) | `4` | `0xffffff87b7bc9d80` (valid, **different** pointer) |

The third row is the theory's own prediction, tested: a reboot repairs it because `init_cred` is a
re-initialized static. The blob pointer differs per boot (it is an allocated object), which is why a
damaged boot can never be repaired in place — the address that belonged in `security` is gone.

`init_cred.usage` is `ATOMIC_INIT(4)` pristine (`kernel/cred.c:44`). It has been decremented six
times — four to reach zero, then two more past it.

## Mechanism

`victim_process.cpp` already states the hazard: *"rooted exits kfree the static init_cred (w2 stores
it with no get_cred). park forever"*. W2 stores `init_cred` into `task->cred` as a raw pointer with
**no reference taken**. Every task that inherits that cred and then exits calls `put_cred()` on it —
`exit_creds()` puts both `real_cred` and `cred`. When the count reaches zero:

```c
void __put_cred(struct cred *cred)
{
	BUG_ON(atomic_read(&cred->usage) != 0);
	...
	kmem_cache_free(cred_jar, cred);      /* a STATIC object, into a slab */
}
```

`init_cred` is now on the `cred_jar` freelist. Its contents are zeroed (the `security` field went
to 0 — consistent with `init_on_free`), and further puts drive `usage` negative. **From that point
on, every child we root faults on its first file operation**, because
`selinux_file_permission` dereferences `current->cred->security` unconditionally. That is exactly
the captured oops (`cred->security == NULL`, fault at `[0 + lbs_cred + 4]`; `lbs_cred` measured 0).

This is why the failure is **cumulative within a boot and cleared by a reboot**, and why the same
runs pass on a fresh boot.

## Fix — design

### The puts cannot be removed

Parking more aggressively does not work, and this is worth stating because it is the obvious first
idea. Every task that inherits the rooted cred puts it on exit, and two of them must exit:

* the **seccomp probe child** (`victim_process.cpp:64`) — the parent `waitpid()`s it, so parking it
  hangs the protocol;
* the **root-shell worker** (`victim_process.cpp:143`) — it `execl`s `/system/bin/sh`, and every
  process the root script spawns inherits the cred and exits.

So the cred must be **immortal**, not unused.

### Why the obvious pin does not work

A 4-byte write of a large count is not expressible. The erase's store is 8 bytes — case 1 with
`rb_left = target` executes `tmp->__rb_parent_color = pc` with `tmp = node->rb_left`, i.e.
`*(target) = pc` — and `pc` doubles as the collateral's parent pointer (`__rb_change_child` reads
`parent->rb_left` at `parent = pc & ~3`), so `pc` must be a **mapped address**. Writing at
`init_cred + 0` therefore sets `usage = low32(pc)` *and* `uid = high32(pc)`, and no kernel pointer
has a zero high half.

The one address that would leave `uid` alone, `init_cred - 4`, is inside **`rcu_normal_attr`**
(image `+0x27b0a40`, extent 0x20 — its `store` function pointer's upper half). Corrupting a live
sysfs attribute is the class of mistake that already cost this port a page boundary
(`kernfs_pr_cont_buf`), so it is not acceptable.

### The pin that does work — two writes, net-neutral except for `usage`

```
write A   target = init_cred + 0x00   pc = <scratch slot>   (pointer layout)
          *(init_cred) = scratch      -> usage = low32(scratch)   [huge]
                                         uid   = high32(scratch)  [garbage]
          collateral: init_cred written at scratch+0 or +8 -- inside OUR anchor page.

write B   target = init_cred + 0x04   leaf layout (pc = target - 8 = init_cred - 4)
          collateral writes NULL at (init_cred-4)+8 = init_cred+4
                                      -> [uid, gid] = 0,0  [their pristine values]
          `usage` is not in range and keeps write A's value.
```

Both collateral arms are deterministic in practice: they branch on `*(parent) == node`, and the
left-hand sides are a zeroed anchor slot and a value spanning a data pointer — neither can equal a
live fake-waiter address on the stack. Net effect on the cred: **`usage` huge, everything else
byte-identical to pristine** (`suid`/`euid`/caps/`security` are never in range).

The scratch slot must be one the rotation never hands to a walk, since write A's collateral writes
`init_cred` into it — reserve the last slot (`kLockAnchorSlots - 1`) for it and shorten the rotation
by one.

Cost: two extra dances, either once per boot (`usage` gains ~7×10⁸ decrements, more than a boot can
spend) or per run as self-healing. `init_cred` is already a profile key (`offsets.init_cred`,
`= 41618016`), so this needs no new schema.

### The alternative, and why it is deferred

The reference design points the child's cred at a **forged cred in the payload page**
(`fill_profile_cred_copy`, `util.cpp:191`) with `usage = 256` — immortal by construction, and the
collateral lands in our own page. Our port does not use it because the forged copy cannot carry a
valid `security` blob: that pointer is a per-boot allocation, and the profile's `ref*_image` fields
can only name statics. Closing that would mean forging a SELinux blob too (a `task_security_struct`
whose `sid` is acceptable under permissive SELinux, which W1 has already established). That is the
cleaner design and it removes the collateral corruption of `init_cred` entirely — but it is a
larger change, and it is deferred behind the two-write pin, which is small and uses mechanisms
already proven on this device.

### Measured effect of the pin (2026-10-09, `GhostLock-V1-credpin.apk`)

`init_cred` read live one run into a fresh boot, before and after the pin:

| | `usage` | `uid` | `gid` | `security` |
|---|---|---|---|---|
| pristine | `4` | `0` | `0` | valid blob |
| after one pinned run | `0x9ffd00ff` | `0` | `0x3bda0780` | valid blob |

Two things to read out of that row. `usage`'s low byte is `ff`, not the `00` write A put there —
a real `put_cred` has already decremented it, so the counter is live and the free is now
unreachable. And `uid` is back to 0, so write B landed.

**Series `rate-fix6` (2026-10-09, `GhostLock-V1-credpin.apk`)** — eight runs on one fresh boot,
against `init_cred` verified pristine beforehand:

```
runs=8  completed=8  crashed=0  other=0     (rate-fix4: 4/8; rate-fix5: 4 pass, 2 fail, 2 refusals)
exploit writes landed : 8/8      handoff reached : 8/8      end to end : 8/8
```

Runs 5 and 6 — the two that died in *both* earlier series — completed, and runs 7-8, which were
budget refusals before, completed too. `usage` afterwards was `0x48370101`: still ~1.2e9, i.e. the
static stayed alive through a full series. The budget was spent exactly (128/128), so the series
ended at the wall rather than at a failure.

One observation worth keeping: `usage` had fallen to `…0101` from `…0200`, i.e. ~255 puts landed
during the series. That is far above the ~1-per-run estimated from a *failing* series, and it makes
sense — the put source is the root script's process tree, so the more runs that reach the handoff,
the faster the count falls. A healthy series would therefore have killed `init_cred` *sooner* than
a failing one, not later. The pin is not a workaround for a rare case; without it the count has no
chance.

`gid` is **not** from the pin: W2's own collateral lands at `init_cred + 8`. The collateral writes
at `pc+0` or `pc+8` and takes `+8` because `*(init_cred) != node`, so `gid`/`suid` have been
clobbered with a task address on every W2 since the port began — including the runs that passed.
It is a pre-existing wart, recorded here so it is not rediscovered as a regression; `uid`, `euid`,
`fsuid` and the capabilities are the fields that matter for rooting, and none of them are in range
of either store.

### Not repairable in-boot

Once `security` has been zeroed the blob address that belonged there is gone (the pointer differs
every boot), so a damaged boot must be rebooted. The fix is preventive.

## Open

* **Which exits actually do the puts** is not yet attributed. Candidates in a run: the rooted child
  itself when it dies, the handoff root-shell worker, and the secless forked workers. A run with a
  per-task probe on `put_cred` would attribute them, but the fix does not depend on the answer.
* A read after `rate-fix4` (uptime 2949 s) showed `init_cred` **pristine**, while that series' runs
  5-6 failed with the identical oops. Either its failures had a second cause, or the freed object
  had been recycled into a live cred at that moment (it is on a slab freelist, so its contents are
  whatever the last allocation left). Deciding this needs a series that samples `usage` after every
  run rather than once.
