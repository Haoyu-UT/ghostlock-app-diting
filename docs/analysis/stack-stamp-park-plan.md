# The copy-time park for stack-stamp carriers (plan)

Level: **L** — attack-critical carrier behavior on the route path (the waiter's stack lifetime
during the consumer's walk). Plan first, then code (`AGENTS.md`); this document is the
operator-approval artifact.

Status: **closed for cause (2026-11-13); the park code is reverted (2026-11-14).** Slice 1
(the sigreturn gate) failed per the give-up rule, and the 2026-11-13 revisit settled the
mechanism: the arm64 sigreturn copy cannot be parked — the frame parser reads the next context
record's header at `vregs+0x200` before `restore_fpsimd_context` copies, so the parser's fault
is always the first one and the copy never blocks (F14; record
`external/port/compat-multicast-2026-11-12/deadframe-carrier/fault-park/sigreturn-revisit-2026-11-13.txt`).
Slices 2–5 (the helper park; protocol v4 + the pre-flight smoke; the G1 QEMU gate; the G2 device
smoke) and slice 7's implementation + G1n (the native park, its QEMU gate, and the
drain-handshake fix the gate exposed) ran; 7b (the split-page re-arm), 7c/7d (the QEMU bench and
the cgroup-BPF finding that blocks the **native** park on the diting) and 7e (the hook is
native-only: a 32-bit compat `setsockopt` bypasses it) are recorded. Slice 6 (the compat A/B)
ran 2026-11-13 — 10/10 runs and 80/80 calls in both arms, 0 strip-clobber, inconclusive by the
pre-registered rule — and **the park is not required for the multicast routes (see *Outcome*).**
Nothing shipped. The 2026-11-14 cleanup reverted the helper and native park, protocol v4, the
`GL_PARK_OFF`/`GL_PARK_TEST` switches and the park test, keeping only the drain-handshake fix.
The earlier test patch
(`external/port/compat-multicast-2026-11-12/deadframe-carrier/fault-park/park-mode.patch`,
reverted); the slice records are `fault-park/slice2-host-gates.txt`,
`fault-park/slice3-protocol-v4.txt`, `fault-park/slice4-g1.txt`,
`external/port/compat-multicast-2026-11-12/g2-v4/` and `fault-park/slice7-native-g1n.txt`.
The existing carriers, the profile/wire, and the shipped bundle are unchanged.

**Device caveat (2026-11-13, slices 7d/7e):** on Android, a cgroup `BPF_CGROUP_SETSOCKOPT`
program makes the **native 64-bit** setsockopt carrier's parked copy the hook's heap copy (the
protocol stack copy never runs), so the native park does not apply on a device with an effective
hook. The hook is **native-only on 5.10.236**: `__sys_setsockopt` guards it with
`!in_compat_syscall()` (`net/socket.c:2128`), so a 32-bit (compat) `setsockopt` never enters it
and the AArch32 helper's `copy_from_user` of the compat `group_source_req` remains the first
copy — the compat park's premise is hook-free (7e, with its own scope caveats). The park's
remaining scope is a device/runtime property (see 7d/7e).

## Outcome (2026-11-13): the park is not required for the multicast routes

**Decision: close the copy-time park item. The multicast route's measured improvement comes
from the drain-handshake ordering fix, not from the park; the park has no measurable
contribution in the record.**

- **Native 64-bit — the loss class never appeared.** ksun `-Os` 5.10.236 anchored A/B: 4/4
  completed runs whenever the route was reached (4/6 overall; the 2 failures were the shared
  page-prep check), **36 anchored calls, 0 strip-clobber deaths**; the page-based control read
  0/6. vivo 5.10.246: **13/13 clean anchored calls**, W1 verified 2/2, both runs then stop at
  W2 (cred). The stock 5.10.236 diting cannot run this carrier (the 64-bit geometry is short
  by 0x88), so the only in-hand kernel where it fits is the unshipped ksun Image; the one
  shipped native-multicast profile (fuxi 5.15.194, `profile_provenance = qemu`) has no device
  gate. There is no measured native-route loss for a park to remove.
- **Compat — the ceiling was reached without the park.** The historical baseline
  (`rate-10/`) is 7/10 runs and 65/68 calls (95.6 %/call) with 3 strip-clobber deaths
  (4.4 %/call). The G3 A/B (2026-11-13, `g3-v4/README.md`) read **10/10 runs and 80/80 route
  calls in both arms, 0 strip-clobber, with arm A parked 80/80**; by the pre-registered rule
  the series is **inconclusive (baseline drift)** because the control is also 0. The most
  plausible source is the **drain-handshake ordering fix** (`inflight` before `calls` in
  `threads.cpp` / `carrier_engine.cpp`), present in both arms and sharing the failure shape
  of the historical strip deaths (the waiter's `close(fd)` under the walk). The G3 cannot
  separate the fix from the park (no arm lacks the fix); what it establishes is that the park
  adds nothing measurable on top of it.

**Consequences.** Keep the drain-handshake fix and commit it on its own merits — a latent
defect in every route's consumer, not park code. Revert the park-specific work when closing:
the helper holder/split/trigger, protocol v4 and its smoke slots, the native park, the
slice-7b re-arm, and the `GL_PARK_OFF` scaffolding. 7e stays as a recorded fact, not a park
justification: on 5.10 the compat copy is hook-free, the surviving lead if a future device
ever needs the compat carrier. The fuxi 5.15.194 select-derivation item remains the cheaper
fix for the one bundled native-multicast profile. If the park is ever reopened, the missing
experiment is a compat control that **lacks** the drain-handshake fix; native device runs
must start from a page-free profile.

Not claimed: that the park is proven useless. The G3 is inconclusive by its own rule, and
0/36 native calls is not statistically strong on its own. The claim that supports the
decision is narrower: **no measured multicast loss remains for the park to remove, and the
one measured improvement coincides with a fix that ships without it.**

Scope: the park is a property of the carrier's **copy**, not of one ABI. It applies to every
stack-stamp carrier whose stamp is written by a `copy_from_user` whose source page can be split
after the stamp. The compat multicast is the leading case (fully gated, device-ready); the
native 64-bit multicast is the same mechanism in the native route; sigreturn is a test-first
item that may be dropped. `select_stack` and `tcp_zerocopy` are excluded (see the scope table).

## The problem

The AArch32 compat `MCAST_BLOCK_SOURCE` carrier works: G1 QEMU on both 6.1 Images, G2 device
smoke, and the standard device series reads **7/10 runs, 65/68 route calls (95.6 % per
call)** on the duchamp (`rate-10/`). The three lost calls are the **strip-clobber class**
(W1, W2 and the W3 TIF write), captured as two full oopses in `rooted-oops/`:
`rt_mutex_adjust_prio_chain` reads a corrupted `waiter->lock`. This ROM has
`panic_on_oops=1` and the mrdump die-notifier, so every such oops is a device reboot.

The mechanism, from the same session: after the `setsockopt` copy returns, the waiter thread
returns to EL0 and **spins on its own stack** with the eleven waiter words stamped there. The
consumer's `sched_setattr` walk runs during that spin; a context switch / EL0 preemption on
the waiter's CPU writes the scheduler's frames over the strip, and the walk reads them. The
select carrier is immune because its waiter *blocks* inside `_newselect`; the multicast has no
such syscall behind the copy. The static parked-carrier study (`parked-carrier/`) found no
app-reachable syscall that could park the waiter over the strip without writing it.

The missing park is **inside the carrier's own copy**: a page fault in the `copy_from_user`
that writes the stamp takes the `mmap_lock` slow path (kernel uaccess faults carry no
`FAULT_FLAG_USER`; the per-VMA fast path is gated on it) and blocks on another thread's
`mmap_lock.write`. The stamp is already stored when the fault happens — the source page split
sits in the copy's sequential tail, after the last stamp byte — so the waiter parks *with the
stamp in a live frame*, its stack quiescent, and the consumer's walk runs inside the park.
This is exactly the select carrier's immunity, built from the carrier that writes the stamp.

Measured:

- **Device (duchamp, 6.1.138)**: the real `setsockopt(MCAST_BLOCK_SOURCE)` copy blocks for
  the holder's whole lock hold — native 14.8 → 2672.6 µs under a 2774.5 µs hold; AArch32
  compat 9.1 → 1153.3 µs under a 1530.5 µs hold; the un-split control stays 18–48 µs
  (`fault-park/measurements.txt` §2; `setsockopt_park.c`).
- **QEMU G1 park gate (6.1.138, the real armv7 engine)**: `park hold ms 10` / `park copy ms
  11` / `calls 64 successes 64` / `enforce 1→0 PASS`; the holder-disabled control reports
  calls 0 and oopses at the attempt deadline (`fault-park/g1-park-138-hold.txt`,
  `-nohold.txt`; harness `g1-park-init.cpp`, patch `park-mode.patch`).

So the park is device-proven for the carrier's copy and QEMU-proven for the full
stamp + walk + write. What remains is productizing it and measuring the rate change.

## Scope: the carriers this applies to

The park needs three properties: the stamp is written by a **uaccess copy** (no
`FAULT_FLAG_USER`), the source page can be **split after the last stamp byte**, and a thread in
the carrier's mm can hold **`mmap_lock.write`**. Every stack-stamp carrier with a
`copy_from_user` satisfies them; the differences are the copy site, the split offset, and
where the holder lives.

| carrier | where it runs | the copy / split | park state | in this plan |
|---|---|---|---|---|
| **compat multicast** (AArch32 `MCAST_BLOCK_SOURCE`) | armv7 helper (6.1.134/6.1.138) | 0x104 to `sp+0x120`; split 0x100 (last 4 B) | device Test A (carrier) + QEMU full gate | **implement + device A/B** (slices 2–6) |
| **native multicast** (64-bit `MCAST_BLOCK_SOURCE`) | native route (5.15.194 fuxi bundled; 5.10.246, 5.10.236 ksun) | 0x108 to `sp+0x18`; split 0x100 (last 8 B) | the same copy shape; no native-carrier harness yet | **the same park in the native route + a QEMU 5.15.194 gate and a diting device read on the ksun `-Os` 5.10.236 Image** (slice 7) |
| **sigreturn** | native (`rt_sigreturn` fpsimd) | 0x200; split 0x1e0/0x1f0 | carrier parks (Test A); parked walk unproven | **test-first QEMU gate, abandonable** (slice 1 — run 2026-11-12, not passed; **dropped**) |
| **select_stack** | native + compat | fd_set copy, then the syscall *blocks* | already a live-frame block — the immune baseline | no park needed |
| **tcp_zerocopy** | native | no stack stamp (crafted lock page) | not applicable | no park |

The per-carrier numbers are in the design sections below. The window arithmetic and the
holder/split mechanics are shared; each implementation only owns its copy site, its split
offset, and its trigger.

## The window arithmetic

The park is a timing window, not a new primitive. With `R` = the ramp from arming the holder
to the copy, `D` = the consumer's delay, `H` = the holder's `mprotect` hold:

```
park_go ──R──> setsockopt copy ──ε──> fault (stamp stored) ──(H−R)──> copy returns
                        consumer_go ──D──> first sched_setattr
```

The walk is inside the park iff `R + D < H` (and the copy's fault is after the holder entered
the `mprotect`). The device's measured hold for a populated 512 MiB, 4K-page region is
1.5–2.8 ms (`measurements.txt` §1–§2); the provisional constants are **R = 200 µs, D = 600 µs**
(margin ≥ 0.7 ms at the worst hold), calibrated per device with the Test A harness before the
A/B. The QEMU gate used a 1 GiB region (10 ms) and R = 2 ms, D = 1 ms; the G1 re-run uses the
device constants so both benches exercise the same code path.

The split is `buffer_size − 4` = **0x100** on both images: the copy's final 4 bytes are
sequential (the 64-byte store lag does not reach the last chunk), so the stamp's last word is
stored before the fault — the stamp end (exclusive) is 0x100 on the 6.1.134 time64 placement,
0xb0 time32, and 0xa0 on 6.1.138. The second page's zero fill lands outside the stamp. Nothing
else in the geometry changes: the strip stays at `compat_waiter_off`, the lock at the anchor
slot, the task at `init_task`.

## What the park does and does not change

- It removes the EL0 exposure during the walk: the waiter is blocked in the kernel, so the
  scheduler cannot write its stack; the walk sees the stamp for the whole park.
- It changes **no** profile/wire key, no stamp word, no anchor, no route geometry, and no
  result mapping. The parked copy fails (`-EADDRNOTAVAIL` on the measured images — the fault is
  serviced after the holder releases and the handler then fails semantically, as the QEMU gate
  logged) and the route already accepts a failed `setsockopt` (`status=Ok` on
  `calls>0 && successes>0`); the G1 logs show the same acceptance for `EADDRNOTAVAIL`.
- It does not park the consumer; the walk's own frames are on the consumer's stack.
- It does not remove the non-strip failure classes (pre-route `CMP_REQUEUE_PI` hang, W2 cred
  miss, the helper's delivery failures); the A/B measures only the class it targets.

## Design

### 1. The compat helper (`src/core/compat/carrier_engine.cpp`, armv7)

The park is **unconditional for `CarrierMode::Multicast`** — the only mode it applies to. The
test env knobs (`GL_PARK`, `GL_PARK_NO_HOLD`) do not ship; a compile-time test constant
(`GL_PARK_OFF`) builds the control arm for the A/B.

- **Engine state**: `park_ready`, `park_go`, `park_stop`, `park_t0_us`, `park_copy_us`, `park_hold_us` (the same shape
  as the test patch).
- **Holder thread**: created first (before consumer/owner/waiter) so its `mmap` + `memset`
  overlaps the fd setup and the dance. It pins to a CPU distinct from the waiter's and the
  consumer's (the test used `consumer_cpu + 1`; take the next CPU in the profile's pair space,
  validated against `sched_getaffinity`), maps a populated 4K-page region
  (`MAP_PRIVATE|MAP_ANONYMOUS`, `MADV_NOHUGEPAGE`, `memset`), sets `park_ready`, then on each
  `park_go` runs one `mprotect(PROT_NONE)` / `mprotect(PROT_READ|WRITE)` cycle.
- **The route step** (the multicast branch, replacing the current socket→setsockopt block):
  1. build the split buffer: map two pages, `MADV_NOHUGEPAGE`, copy the first 0x100 stamp
     bytes to `page_end − 0x100`; the second page is left untouched (not resident);
  2. wait for `park_ready`;
  3. `park_go = 1`; sleep `R`; `consumer_go = 1`; `setsockopt(fd, IPPROTO_IP,
     MCAST_BLOCK_SOURCE, split, 0x104)`;
  4. record `park_copy_us` (the copy's duration) and the hold; the parked copy returns
     `-EADDRNOTAVAIL` on the measured images — the fault is serviced once the holder releases
     and the option handler then fails its semantic check (the QEMU gate logged this shape) —
     so the metric times every parked call;
  5. drain, disarm, log. **No syscall between the copy and the walk** — the waiter is blocked
     in the fault for the whole walk, so the existing rule is automatic.
- **Diagnostics**: `park hold us`, `park copy us`, and a `parked` flag (copy span ≥ 500 µs)
  after the drain — microseconds so the half-millisecond threshold is meaningful; the
  QEMU/device checks read the flag. The pre-copy diagnostics stay deferred as today (they are
  before the copy, so they are safe, but the existing log order is kept).
- **Failure modes**, all logged and non-fatal: the split page somehow resident (the copy does
  not fault; `park_copy_us ≈ 0`, the old behavior), the holder not yet in `mprotect` at the copy
  (the fault completes), a killed holder (the fault unblocks). The route's success condition
  is unchanged.

### 2. The compat driver and protocol (`src/core/route/compat_carrier.cpp`, `carrier_protocol.h`)

- `run_multicast_carrier`: `command.delay_us = 0` is replaced by the park delay
  (`kParkDelayUs = 600` with the calibration; the select ladder is untouched). No other
  command change; the attempt loop (4 attempts, one helper per attempt) is unchanged, and each
  attempt's helper owns its holder and split buffer, so the memset/hold cost is per attempt
  (see Risks). The result mapping is unchanged (`Ok` on calls>0 && successes>0; `route_errno`
  logged).
- The park needs **no new command field** (the mode selects it; `delay_us` is already
  carried). The one protocol change is the **G2 pre-flight**: the smoke grows three slots —
  `mmap`, `mprotect`, `madvise` — so the app's seccomp policy is proven to allow the park's
  syscalls before a run. That is a protocol version bump (v4); native and helper ship together
  and a stale helper refuses by version. The result's smoke array grows 11 → 14. If the
  operator prefers no protocol bump in this slice, the fallback is the G3 route run itself (a
  denied syscall kills the helper on the first attempt, which the driver already reports as a
  delivery failure); the smoke is the cheaper, pre-flight refusal.

### 3. The native 64-bit multicast route (`src/core/route/multicast_waiter_route.cpp`)

The same park, in the native process, for the 64-bit `MCAST_BLOCK_SOURCE` carrier — the fuxi
5.15.194 bundled profile and the images where the 64-bit geometry is feasible (5.10.246,
5.10.236 ksun). The copy is the same uaccess copy (0x108 to `sp+0x18`), so the mechanism is
identical; only the site and the process differ.

- **The route**: `do_kernel5_fake_lock_route` builds the VLA stamp and calls `setsockopt`;
  the park changes mirror the helper's — a split buffer (two pages; the first 0x100 stamp
  bytes at `page_end − 0x100`, the last 8 bytes in the untouched page), `route_delay_usec` set
  to the park delay (the native consumer already honours it) and `consumer_go` stored
  **before** the `setsockopt`, and a `park copy us` / `parked` metric. The one-shot W1 path and the
  W2/W2b re-entries take the same route; the anchor, the stamp words and the result mapping
  are unchanged.
- **The holder**: a thread in the native process (the same 512 MiB, 4K-page region), created
  lazily and **reused across route calls** — the native lives the whole run, so the memset is
  paid once, unlike the helper's per-attempt process. The waiter/consumer CPU pair stays; the
  holder takes the next CPU, validated against `sched_getaffinity`.
- **The gate**: a QEMU native-carrier harness on the 5.15.194 Image. The aarch64 dance
  already exists — the sigreturn probe harness (`sigret-park-init.c`) implements the native
  futex/owner/consumer dance; the gate reuses it with the `setsockopt` carrier and the park,
  builds the stamp from the guest's own symbols and the profile's 5.15.194 geometry
  (`waiter_off 0x60`, buffer 0x108, strip end 0xb8 < 0x100), and verifies the write by
  `selinuxfs` `enforce 1 → 0`. This is the native-carrier harness the earlier record said
  was missing.
- **The device (diting, ksun `-Os` 5.10.236 Image).** No fuxi unit exists, but the 64-bit
  carrier is feasible on one in-hand kernel: the diting's preserved ksun `-Os` 5.10.236 Image
  (`external/test-kernels/5.10.236-…-ab14313284-ksun-osize/`; UTS string identical to stock,
  KMI byte-identical; `waiter_off 0xa8`, buffer 0x108, so the eleven-word stamp ends exactly
  at the 0x100 split — the same zero-margin placement as the planned 6.1.134 time64 G1 arm;
  the copy template aligns the source once and then stores the last full 64-byte block before
  the tail load faults). The stock 5.10.236 Image cannot take this route (the store derivation
  records the family short by 0x88: the strip home lands past the 0x108 copy). The device read
  is a RAM boot (`external/port/ksun-ab/ramboot-ksun-osize-192M.img`, md5
  `f1c82be544b0a3d17251b6026dd511dd`, stock ramdisk; `fastboot boot`, no partition written —
  in-turn approval); the 2026-10-22 A/B ran 12 fresh boots this way. Its ksun arm read
  route-level 4/4 with **0 strip-clobber deaths in 36 route calls**, so the G3n read is park
  engagement + no regression, not a powered rate claim — a 0-vs-0 A/B is inconclusive by
  design (see G3n). The fuxi 5.15.194 unit remains the one to add when it appears.

### 4. Profile, wire, app

- **No new keys.** `compat_carrier`, `compat_waiter_off`, `compat_buffer_size`,
  `compat_futex_abi` and the anchor trio stay; the split offset is the carrier's own
  `buffer_size − 4`, validated against the stamp end at run time.
- **No app change** beyond the native/helper build; the validator and the profile picker are
  untouched. The park is a route implementation detail, not a profile capability.
- **No bundle change in this change.** The route priority stays (`sigreturn` 6.1.134,
  `select_stack` 6.1.138); the bundle question is a separate operator decision after the A/B.

## Test plan

**G0 — host.** armv7 helper and arm64 native at zero warnings; `lint-tidy`; the full native
host suite; a unit test for the split arithmetic (`split == buffer_size − 4`, the stamp end
inside the first page) and for the protocol v4 layout/version; `cmp_disasm.py` read, not
verdict (the known missing-`multicast_*` control). No extractor change.

**G1 — QEMU, both 6.1 Images.** The product helper with the park unconditional and the device
constants (R = 200 µs, D = 600 µs, 512 MiB hold), on the 6.1.134 (time64 `0xa8`; time32
`0x58` in a second boot) and 6.1.138 (`0x48`) Images: verify `enforce 1 → 0`, `parked 1` (copy span
≥ 0.5 ms) on every route call, and the `GL_PARK_OFF` control reproducing the old behavior
(the walk races; no park metrics). Reuse `g1-park-init.cpp`'s guest init with the product
helper binary.

**Result (2026-11-12): passed.** Three product-helper runs — 6.1.138 (0x48), 6.1.134 time64
(0xa8) and time32 (0x58) — each read `parked 1` with the copy's span equal to the holder's
lock hold (4.9-6.0 ms under TCG), 32/44/51 walks all clean inside it (`drain 0`,
`clean=1/1`, `disarmed=1`), and `enforce 1 → 0`. The two `GL_PARK_OFF` controls (6.1.138,
6.1.134 time64) log no park metrics and repeat the pre-park shape (`setsockopt -1/99`,
calls 1/1, `enforce 1 → 0` — the old single walk won its race as in `qemu/g1-138.txt`), so
the park metrics are not a harness artifact. The holder-readiness bound moved 5 s → 30 s after
the first run outran it inside TCG's 512 MiB memset; the device holder is ready in tens of ms,
so the bound stays a never-started-holder guard. Logs and the harness:
`fault-park/slice4-g1.txt` and `fault-park/g1-park-product-*.txt`.

**G1n — native carrier QEMU (5.15.194, slice 7).** The native park build in the guest with
the aarch64 dance from `sigret-park-init.c` and the `setsockopt` carrier, on the store
5.15.194 Image: the same verification (`enforce 1 → 0`, `parked 1` = copy span ≥ 0.5 ms, the
`GL_PARK_OFF` control). This is the first full-dance gate for the *native* multicast carrier;
no fuxi device run follows here (no unit) — the native device read is G3n on the diting's
ksun Image.

**Result (2026-11-13): passed.** Three park runs read `parked 1` with the copy's span equal to
the holder's 5.0–5.7 ms hold, one walk each, `enforce 1 → 0`; the `GL_PARK_OFF` control kept
the pre-park order (copy then trigger, delay 0), its copy took ~0.84 ms, and its walk oopsed
in `rt_mutex_adjust_prio_chain` — the race the park removes. A kprobe read-back proved the
geometry (`walk pi − copy dst = 0x60`). The gate exposed a **drain-handshake race** (the
consumer set `calls` before `inflight`; the waiter could miss the in-flight call, run
`close(fd)` and clobber the stamp) — fixed in `threads.cpp` and `carrier_engine.cpp` — and
showed that repeated walks on the 5.15 zero anchor wedge after ~4 (the product's one-call
cadence, injected from the select-stack preset, avoids it). Harness:
`qemu/mcast-native-park-init.c`; record: `fault-park/slice7-native-g1n.txt`.

**G2 — device smoke (duchamp).** The v4 smoke under `untrusted_app` and the app's single
filter: all 14 slots return 0 (`mmap`, `mprotect`, `madvise` new). The geometry check then
refuses or proceeds. The diting 236 stays the armv7 control if needed.

**Result (2026-11-12): passed.** On the duchamp with the build-741 APK (the v4 park helper),
the smoke read `exit=0 signal=0 … socket=0 setsockopt=0 mmap=0 mprotect=0 madvise=0` — all 14
slots 0 under `untrusted_app` with the app's single filter. The same run is the park build's
first device read: **8/8 route calls parked** (`park hold us` 5175–6341, `park copy us`
5072–6262, `parked 1`), every call `clean=1/1`, and the chain completed (`exploit complete`
T+15.3 s, `KernelSU ready`, store `completed`, no oops) — n = 1, not a rate claim. One
device-side finding: the app's external SAF selection was unreadable (the known 2026-11-12
document state), which the app fails closed on — home `不支持`, the layer notice naming the
unreadable profile; re-selecting the same file through the picker repaired it. Record:
`external/port/compat-multicast-2026-11-12/g2-v4/`.

**G3 — device A/B (duchamp).**
- **Arms**: A = the park build; B = the same branch with `GL_PARK_OFF` (a test-only build, not
  shipped). The historical `rate-10/` (7/10, 65/68) is the prior, not the control.
- **Protocol**: `scripts/series-run.sh` fresh boot per run, interleaved blocks (the `rate-ab`
  precedent; the APK swapped with `adb install -r -d`), the external compat-multicast profile
  (`6.1.138-compat-multicast.conf`, digest `0xc47fb9a8…`), the run store as the verdict, the
  crash capture armed (`RECOVERY_PROFILE`; the selection document must be repaired to the
  same-inode restore first — the `rate-10-capture` failure note).
- **n**: **10 fresh boots per arm** (≈ 65–70 route calls/arm at the current shape). The
  primary endpoint is the **strip-clobber death per parked call**; the secondary is the run
  completion (7/10 → ?).
- **Manipulation check**: a route call counts as parked iff its helper log shows
  `parked 1` (the copy span, logged in µs, ≥ 0.5 ms); the arm is void if the park engaged on < 90 % of calls.
- **Pre-registered rule**: the park passes if arm A reads **0 strip-clobber deaths over ≥ 60
  parked calls** (one-sided binomial against the 3/68 = 4.4 % baseline: p ≈ 0.05 at 68
  calls, p < 0.01 at ~105 calls) **and** its completion rate is not worse than arm B's. If B
  also reads 0 deaths, the series is inconclusive (baseline drift) and is extended. A dirty
  stop counts as a failure. A different ROM/kernel voids the pair.
- **Result (2026-11-13)**: `g3-v4/README.md` — **10/10 runs and 80/80 route calls in both
  arms, 0 strip-clobber; arm A parked 80/80.** Arm B also reads 0, so by the rule the series
  is **inconclusive (baseline drift)**; the drain-handshake fix (present in both arms) is the
  most plausible source. The park's contribution is not measurable — see *Outcome*.
- **Non-goals**: the 6.1.134 device result (the Realme unit remains the reporter's/borrowed;
  its geometry is QEMU-covered); the fuxi 5.15.194 device (no unit); the 6.1.138 bundle choice
  (select stays).

**G3n — native device (diting, ksun 236 Image).** The native park build with the ksun multicast
profile (`waiter_off 168`, buffer 264, anchor `dump_skip.zeroes +0x222b590`, 4096/32) on a RAM
boot of `external/port/ksun-ab/ramboot-ksun-osize-192M.img` (md5
`f1c82be544b0a3d17251b6026dd511dd`; `fastboot boot`, no partition written; in-turn approval).
**3 fresh boots arm A (park) and 3 arm B (a compile-time `GL_PARK_OFF` native control)**,
interleaved: the manipulation check (`parked 1` on ≥ 90 % of route calls), the
write verification on a parked call (`enforce 1→0`), and completion. The endpoint is **not** a
powered rate claim: the ksun's multicast record is 0 strip-clobber deaths in 36 route calls
(2026-10-22), so a 0-vs-0 read is expected and counts as inconclusive; extend the A/B only if
the compat G3 shows a park effect worth carrying to the native route. The stock 5.10.236 Image
cannot be the native unit (the 64-bit geometry is short by 0x88); the fuxi 5.15.194 unit
remains the one to add when it appears.

**G4 — evidence.** `external/port/compat-multicast-<date>/` (the QEMU logs, the A/B run
stores, the helper park metrics, the crash excerpts); plan result section and `PORT-PLAN.md`.

## Risks

- **Holder memory and time per attempt.** A populated 512 MiB region costs ~30–60 ms of
  `memset` and is resident for the helper's life; the route has up to 4 attempts per write and
  ~8 writes per run. The holder starts before the dance so the cost overlaps, but the
  `route_done_timeout_ms` and the helper's wall-clock timeout must cover it. If the device
  hold is too tight, 1 GiB doubles the hold *and* the cost; the calibration chooses the
  smallest region that gives the window with ≥ 0.5 ms margin. The native route's holder is
  persistent, so it pays the memset once per process; its cost is the 512 MiB resident for the
  whole run (the app-native process, not a per-attempt child).
- **The 6.1 POCO's phantom-process trimmer.** The helper is an untracked child of the app and
  the trimmer killed the native in 40 % of runs on that device in the 2026-10-17 series. The
  existing mitigation (the monitor setting / `oom_score_adj -1000`, which the helper
  inherits) must be in place for the A/B; a larger resident mapping raises the exposure. A
  trimmer kill is a delivery failure, not a route death, and is excluded from the endpoints.
- **The window is timing, not correctness.** If `R` is too small the holder is not yet in
  `mprotect` and the fault completes (the old behavior, `park_copy_us ≈ 0`); if `D` is too
  large the walk falls past the hold. Both are measured per call; the A/B's manipulation
  check rejects an arm that never parked.
- **The split page must stay non-resident.** The second page is mapped but untouched; nothing
  in the helper may touch it. A future compiler/libc change that pre-faults the mapping would
  silently disable the park — the `park_copy_us` metric and `parked` flag are the guard.
- **`-EFAULT` from the copy.** The parked `setsockopt` returns `-EFAULT` (the faulted read),
  not `EADDRNOTAVAIL`. The engine already accepts any failed call when the walk succeeds; the
  smoke's `setsockopt` slot (a separate path, no park) keeps its semantic-error list. The
  driver's logs must not classify the parked call as a route failure.
- **The holder's CPU.** The helper is a 32-bit process on an 8-core device; the holder must
  not share the waiter's or the consumer's CPU (the pinned pair), and the chosen CPU must be
  in `sched_getaffinity` (the core_ctl rotation hazard from the run harness).
- **Protocol v4.** The smoke slots change the helper/native layout together. Both ship in the
  APK; the version check refuses a stale helper. Only the internal carrier protocol changes —
  the user profile/wire schema is untouched.
- **The A/B's small effect size.** The baseline is 95.6 % per call; the park targets the
  remaining 4.4 %. Ten runs (≈ 68 calls) give p ≈ 0.05 for 0 deaths; a 15-run arm is the
  stronger read. The run-completion endpoint alone cannot separate the arms at n = 10 — the
  per-call endpoint is the designed sensitivity, and the rule above is pre-registered.

## Out of scope

- **`select_stack` and `tcp_zerocopy`** are not park candidates: select already blocks inside
  the syscall (the immune baseline the park emulates), and the tcp route has no stack stamp —
  its write vehicle is the crafted lock page. See the scope table.
- **The 6.6/6.12 non-compact images.** Refused by the existing route×waiter-shape guard.

## The sigreturn park (planned, abandonable)

The sigreturn half is on this plan as a **test-first, give-up-allowed** item. It is the weakest
carrier (`+0x188` class; 5/12 and 8/15 device rates; no kernel needs it as the only viable route
after the compat select), so it gets one cheap test and no more if that test fails.

- **What is already proven**: the carrier's copy parks on both in-hand kernels (Test A:
  1.9–2.1 ms duchamp, 1.69–1.70 ms diting under ~1.9 ms holds), and the guest read-back
  measured the geometry exactly (`copy dst + 0x98 = pi_blocked_on`) and showed the walk reaches
  the waiter. The parked **walk** is the unproven piece; the QEMU trigger timing is the blocker
  (the `tgkill` signal delivery lags 3–13 ms under TCG, and after the copy the disarm's own
  `futex_lock_pi` reuses the same stack home and overwrites the stamp within ~1 ms).
- **The first test (the gate) — the plan's first slice**: one QEMU-only run on the existing
  probe harness (`external/port/compat-multicast-2026-11-12/qemu/sigret-park-probe-init.c`):
  a consumer thread blocks on `/sys/kernel/tracing/trace_pipe` and fires the `sched_setattr`
  when the `gl_copy` event reports the fpsimd copy (`len=0x200`) — within µs of the copy entry
  and therefore inside the park. **Pass** = `enforce 1 → 0` with the trace showing the walk
  read the stamp at the home (`next_lock == anchor`) while the victim is parked; the no-hold
  and no-trigger controls must fail. No route, native, or profile changes in this run; no
  device run.
- **The decision**: on a pass, the next step would be a separate L-level slice for the route
  choreography (the handler/loop + a holder thread in the native route) and a device viability
  test, with its own approval — the candidate units in hand are the diting stock 5.10.236
  (store offset 0xF0; the unit with the sigreturn history, 8/15) and the duchamp 6.1.138
  (store offset 0x98; the image the QEMU gate runs). On a fail — or if the pass does not
  justify the route — the item is **dropped** and the sigreturn route stays exactly as it is.
  The give-up is pre-authorized; no further sigreturn park work follows either way in this
  plan.
- **Result (2026-11-12): the gate did not pass; the item is dropped.** The trace_pipe trigger
  surfaced the copy event ~20 ms late; a perf ring on the same kprobe fires promptly, but every
  walk at 200 µs / 3 ms / 10 ms after the event still read the waiter before the copy's stores
  (the canary shows the stamped lock word was never observed) and died in the chain walk; the
  fault-entry probe points that would bracket the stores (`rwsem_down_read_slowpath`,
  `do_mem_abort`) are not registerable on the 6.1.138 GKI. The no-trigger control failed as
  required. Evidence: `fault-park/measurements.txt`, "The trace_pipe / perf trigger", and
  `g1-sigret-tracepipe-138-r{1..9}*.txt`. The sigreturn route stays exactly as it is; no route,
  native, profile or bundle change followed from this plan.
- **Revisit (2026-11-13, operator request): the QEMU diagnostic found instrument defects, not a
  kernel mechanism.** Two harness bugs were found and fixed: the perf ring could fire on a
  stale calibration copy (the consumer now skips to the explicit arm head), and the tracepipe
  consumer did a printf/mark between the trigger and the walk (the diag consumer's first
  syscall is the walk). The copy can be parked inside the hold (prearm5: copy 12.773385 inside
  12.7621–12.7744), but the TCG signal-return delay (up to ~40 ms) makes the copy/walk
  alignment uncontrollable with user-space delays; `do_mem_abort` remains unregisterable, so
  the copy-entry `gl_copy` is the only trigger. The r4 `w38 = init_task` is the earlier
  calibration copy / user-register state, not a one-word stamp shift; the geometry read-back
  stands. One run wedged in the chain without the pre-stamp BUG (consistent with a stamped
  walk, not proof); another still hit the pre-stamp BUG. The "harness timing" verdict stands,
  now with the defects named. The `-icount` follow-up did not stabilize the signal delivery
  (the handler did not fire; `drops=0`), and the pattern across the runs leaves the copy's
  **store order/visibility** as the strongest remaining mechanism candidate: the walk reads
  the waiter pre-stamp even while the copy is parked, and the `dst+0x98 = pi` read-back does
  not prove the stores committed. Next instrument: a **BPF kprobe on `handle_mm_fault`**
  reading `current->pi_blocked_on` (kprobe fetchargs cannot reach `current`; BPF can); a
  pre-stamp waiter there confirms the mechanism and closes the item for cause, a stamped one
  leaves the timing verdict and the `-icount` + long-hold tuning. The BPF program is built and
  attaches (`qemu/sigret-park-bpf-init.c`): the dance's fault reads the standard waiter fields
  (task +0x30, lock +0x38), but the one-entry map cannot isolate the carrier's split-page fault
  (a `pi = 0` later fault overwrites it, or the dance's `pi != 0` value persists). Next:
  address-filter the program on `handle_mm_fault`'s fault address versus the handler's split
  page, or use a small ring of fault records, so the carrier's fault is captured
  deterministically. That address-filtered variant also attaches, but the map stays zero
  because the carrier's uaccess fault **does not pass through `handle_mm_fault`** (the
  victim's trace has no `gl_fault` line; only the boot/holder user-mode faults do). A
  multi-probe attempt at `__handle_mm_fault`/`do_translation_fault`/`do_page_fault` failed
  (the internal symbol is absent; the `do_*` handlers are `__kprobes`), so the next probe
  is the uaccess fixup handler (`fixup_exception`/`ex_handler_uaccess`), which runs on the
  copy's faulted access and is not `__kprobes`; the same BPF program reads
  `current->pi_blocked_on` and the waiter there. That probe also fires nothing for the
  victim. A bare kretprobe on `__arch_copy_from_user` with the BPF attached then reads
  `pi = 0` at the copy's **return** (the waiter is live only during the park), while the
  in-park r6 walk at +0.676 ms still read `pi` non-zero and **pre-stamp** fields. The
  source audit then fixes what the geometry is: the store offset is `waiter_home −
  copy_dst`, derived per image (0x98 on 6.1.138; 0xe8 on 6.1.134; 0xf0/0x100 on
  5.10.136..236; 0x140/0x150 on 5.10.43..101), because both are compiler frames — and
  within one image the futex entry alone moves the home (6.1.134: `futex_time32` 0x1e8
  vs native `futex` 0x198, 0x50 apart; prearm5 even shows the disarm's `futex_lock_pi`
  waiter 8 bytes below the `futex_wait_requeue_pi` home). The +0x38 sample is **not**
  the stamp: every pre-copy walk precedes the carrier's copy entry (r6 12.034989 vs
  12.038600; r4 12.217440 vs 12.226401; prearm5 12.766904 vs 12.773385), the same
  pre-copy words recur across four runs (w30=0x…a180000, w38=init_task, w40=0, w48=the
  victim task) with the anchor absent, and the post-copy samples are the disarm's
  `futex_lock_pi` frames at the same home. So the 0xd0/0x110 arithmetic is withdrawn.
  The in-park read then settled it (F14): the `mmap_lock_start_locking` tracepoint BPF
  (victim-tid filter + a user flag set after the handler's madvise) fires at the
  split-page fault with the pre-copy waiter words, and the trace shows the fault is at
  **vregs+0x200 — the next context record's header, which `parse_user_sigframe` reads
  before `restore_fpsimd_context`** — 92 us *before* the vregs copy entry; the copy
  returns in 37 us and never parks. The syscall block the device Test A measured is that
  read's fault: during it the copy — and the stamp — has not run, so the walk reads the
  pre-stamp waiter; the copy runs after the park and the disarm then reuses the home.
  F10/F11's "the uaccess fault does not reach `handle_mm_fault`" was the address filter
  comparing the split page base (0x…d000), not the fault address (0x…d010). The sigreturn
  copy-time park is structurally impossible for the arm64 sigreturn carrier (the parser
  reads the record header at vregs+0x200 before the copy, and any split page that could
  fault the copy after the strip's stores contains it); the item closes for cause and the
  sigreturn route stays as it is. No device run; no route/product
  change.
  Record: `fault-park/sigreturn-revisit-2026-11-13.txt`; harnesses:
  `qemu/sigret-park-{diag,prearm,mmklock}-init.c`.

## Implementation slices

1. **Sigreturn gate (abandonable, QEMU-only) — the first slice — run 2026-11-12, not passed;
   the item is dropped.** The `trace_pipe`/perf-triggered parked walk in the QEMU guest: the
   trigger fires, but the walk cannot be bracketed between the copy's stores and the park; the
   fault-entry probe points are not registerable. See "The sigreturn park" Result bullet and
   `fault-park/measurements.txt`. Slices 2–8 proceed unchanged.
2. **Helper park** (`carrier_engine.cpp`): engine state, holder thread, split buffer, pre-copy
   trigger, park metrics; the native's `delay_us` constant; a `GL_PARK_OFF` test build. Host
   builds, lint, the split unit test. — **implemented 2026-11-12; host gates green: armv7
   helper and arm64 native zero warnings, `lint-tidy`, the full native host suite plus the new
   `compat_park_test`, the `GL_PARK_OFF` control build, and the `cmp_disasm.py` read (identical
   instruction shapes; `do_one_write` shows a 0x94-byte layout shift and one nearest-symbol
   annotation difference caused by the driver's added warning, not a code change; the FAIL is
   the known missing-symbol control).
   Record: `external/port/compat-multicast-2026-11-12/deadframe-carrier/fault-park/slice2-host-gates.txt`.
   The wire stays v3 (no layout change); slice 3 bumps it.**
3. **Protocol v4 + smoke** (three new slots) and the native smoke path. — **implemented
   2026-11-12; host gates green: zero-warning helper/native, `lint-tidy`, the full host suite
   (the park test now also pins the v4 version and the 116-byte result layout), and the
   `cmp_disasm.py` read unchanged from slice 2. The device G2 (slice 5) ran 2026-11-12 and
   passed. Record:
   `external/port/compat-multicast-2026-11-12/deadframe-carrier/fault-park/slice3-protocol-v4.txt`.**
4. **G1 QEMU** on both 6.1 Images (both futex ABIs on 6.1.134) with the device constants, plus
   the `GL_PARK_OFF` control. — **run 2026-11-12, passed on all three arms**: 6.1.138
   `parked 1` (hold 4957 µs / copy 4886 µs, 32/32 walks) and 6.1.134 time64/time32
   (`5439/5672`, 44/44; `5697/5961`, 51/51), every run `enforce 1 → 0`; the two `GL_PARK_OFF`
   controls show no park metrics and the pre-park shape (calls 1/1, `enforce 1 → 0`). One code
   change from the gate: the holder-readiness bound widened 5 s → 30 s (TCG's 512 MiB memset
   outran 5 s; the device holder is ready in tens of ms). Record:
   `external/port/compat-multicast-2026-11-12/deadframe-carrier/fault-park/slice4-g1.txt`.
5. **G2** device smoke on the duchamp (the app's filter). — **run 2026-11-12, passed**: all
   14 slots 0 under `untrusted_app`/`Seccomp=2 Seccomp_filters=1`, and the same run is the
   park build's first device read (8/8 calls parked, hold 5175–6341 µs, copy 5072–6262 µs,
   `parked 1`; chain completed, `KernelSU ready`, store `completed`; n = 1). The app's
   unreadable external SAF selection was repaired by re-selecting the file (fail-closed layer
   notice). Record: `external/port/compat-multicast-2026-11-12/g2-v4/`.
6. **G3** the device A/B on the duchamp with the pre-registered rule. — **run 2026-11-13;
   inconclusive by the rule.** Both arms were rebuilt with the drain-handshake fix (APK 741)
   and read **10/10 runs, 80/80 route calls, 0 strip-clobber**; arm A parked 80/80. The
   baseline drift (both arms at the ceiling) is most plausibly the drain-handshake fix, which
   is present in both arms; the park's own contribution is unmeasured. Record:
   `external/port/compat-multicast-2026-11-12/g3-v4/README.md`. This result, with the native
   rates above, closes the park item — see *Outcome*.
7. **Native multicast park**: the park in `multicast_waiter_route.cpp` (split buffer,
   persistent holder, pre-copy trigger, metrics) + the G1n QEMU gate on the 5.15.194 Image,
   then the G3n device read on the diting's ksun 236 Image (RAM boot; its own in-turn
   approval). Host builds and the existing native host suite. — **implemented 2026-11-13;
   G1n run and passed.** The harness `qemu/mcast-native-park-init.c` (the native aarch64
   dance; the store entry is a boot image, the kernel is extracted at 0x1000) reads the park
   PASS on three runs (copy = the holder's 5.0–5.7 ms hold, `parked 1`, one walk, `enforce
   1 → 0`) and the `GL_PARK_OFF` control oopses in `rt_mutex_adjust_prio_chain` (the pre-park
   race). The probe read-back measured `walk pi − copy dst = 0x60` exactly. The gate also
   exposed a **drain-handshake race** (calls before inflight) in both consumers — fixed in
   `threads.cpp` and `carrier_engine.cpp` — and showed the product's one-call cadence (the
   app's injected select-stack preset) is what keeps repeated walks off the 5.15 zero anchor
   (5+ walks wedge there). Host gates green; cmp_disasm read carries the expected
   `consumer_thread` store-swap and the 386 → 664-instruction route. Record:
   `fault-park/slice7-native-g1n.txt`. **G3n (the diting ksun 236 Image) ran 2026-11-13;
   the park engages and the failure is the cgroup setsockopt BPF hook, not the kernel or the
   anchor — see 7d and `g3n-v4/park-run-{1,3,4}/`.** **7b (2026-11-13): the split-page re-arm.** The native holder
   and split mapping are created once and outlive the call (the helper runs one process per
   attempt), so the first copy's fault left the tail page resident: every later call copied
   unparked while still setting the 600 us delay and triggering the walk first — the `odly`
   strip-clobber shape. Fixed with `madvise(MADV_DONTNEED)` on the tail page after the drain;
   G1n now does a second copy on the same mapping (park 2/2: call 2 5198/4542 us; the
   `-DNO_REARM` control: 80 us, parked2=0), and the diting's carrier micro-test reproduces
   both sides on 5.10.236 (2.5 ms vs 19-162 us). Record: `fault-park/slice7b-rearm.txt`.
   **7c (2026-11-13): the ksun Image in QEMU passes — but the bench is not faithful.** The
   same ksun Image, booted under `qemu-system-aarch64` with the ksun profile geometry, runs
   the product-shaped park at 4 and 8 CPUs: the copy parks (3812/4054 us), the walk lands the
   write (`enforce 1 -> 0`), and the second call's copy parks after the re-arm (3244/3196 us).
   The first QEMU attempts' oops was the harness's own post-copy `printf` (a syscall between
   the copy and the walk), and a missing `-smp 4` made a one-CPU hang — neither is the kernel.
   So the kernel does execute the walk; the pass does **not** transfer to the device, because
   the initramfs guest attaches no cgroup setsockopt BPF program and the diting does (7d).
   Record: `external/port/compat-multicast-2026-11-12/g3n-v4/qemu-ksun-park.txt`.
   **7d (2026-11-13): the cgroup setsockopt BPF hook is the device blocker.** The device
   re-runs (page-free profile, `panic_on_oops=0`, the symbol kit) show the park engages but
   the walk dies in the [7] requeue: a `bpf` (`__cgroup_bpf_run_filter_setsockopt`) entry with
   **no return**, then ~600 us later an `rb_erase` with `npc=0/rootn=0` leaves a heap child in
   the anchor's waiters root, and the enqueue faults on a NULL gparent. Android attaches a
   `BPF_CGROUP_SETSOCKOPT` program at boot (root `bpfloader`/tethering module); the 5.10 hook
   `kzalloc`s and copies the optval **before** the protocol handler
   (`kernel/bpf/cgroup.c:1343-1362`), so the parked copy is the hook's heap copy and the stack
   copy never runs. The park's premise therefore fails for the **native 64-bit** multicast
   carrier on a device with an effective hook; the page-free W1 (`selinux` + `w1_scratch =
   bm_pmd`, `page_free=1`) changes nothing. **The compat ABI is not hook-owned on this kernel
   (7e):** `__sys_setsockopt` runs the hook only for non-compat syscalls
   (`!in_compat_syscall()`, `net/socket.c:2128`), so the AArch32 helper's
   `compat_group_source_req` copy remains the first user copy. The park's viability is a
   per-device runtime property (a split-source `setsockopt` under a holder returns `-EFAULT`
   when the hook copy faulted first, `EADDRNOTAVAIL` when the stack copy ran); carriers not
   subject to a hooked copy: `select_stack` (blocks), `sigreturn` (dropped), and — on 5.10 —
   the compat multicast carrier (7e). A faithful QEMU bench must attach a cgroup setsockopt
   BPF program. The full hook/syscall table (which syscalls a cgroup
   program owns or can rewrite, and which are BPF-safe for a carrier) is
   `external/port/compat-multicast-2026-11-12/g3n-v4/bpf-syscall-surface.txt`. Records:
   `external/port/compat-multicast-2026-11-12/g3n-v4/park-run-{1,3,4}/`.
   **7e (2026-11-13): the hook is native-only — the compat carrier's copy is hook-free.** The
   5.10.236 GKI tree (`external/diting-mcast/diting-dev`, the tree the ksun Image was built
   from; the 5.10.81 vendor tree has the same code) guards the hook with
   `if (!in_compat_syscall())` (`net/socket.c:2128`). On arm64 a 32-bit task's `setsockopt`
   is `sys_setsockopt` (`arch/arm64/include/asm/unistd32.h:601-602`) and
   `in_compat_syscall()` is `is_compat_task()` (`include/linux/compat.h:866`, TIF_32BIT), so
   an AArch32 caller skips `__cgroup_bpf_run_filter_setsockopt` entirely: `kernel_optval`
   stays NULL and `copy_group_source_from_sockptr()` takes its `in_compat_syscall()` branch
   (`net/ipv4/ip_sockglue.c:707-716`), whose `copy_from_user` of `struct
   compat_group_source_req` is the first and only user copy. **The park's premise therefore
   holds for the compat carrier on a device with an effective hook — the diting included.**
   Scope, so "hook-free" is not overread: the 6.x kernels are not read from source here (the
   duchamp G2 pass is consistent with the same guard, an absent program or a program
   opt-out, not proof of any one), the diting's compat geometry (copy depth/home) is not
   derived — the armv7 helper route is currently a 6.1 derivation — and no diting compat
   device gate has run. Established: the hook does not own the compat copy on 5.10.236. Not
   established: that the compat park engages on the diting. This supersedes the "hook-owned
   on both ABIs" sentence in `g3n-v4/bpf-syscall-surface.txt`.
8. **Operator decision**: the bundle/route-priority call (the 6.1.134 `sigreturn` vs compat
   multicast; 6.1.138 stays select), and the Realme/fuxi follow-ups if units appear. The park
   itself is **closed** (see *Outcome*): the native 64-bit half is not needed (0 strip-clobber
   in 36 calls; the stock diting cannot fit it) and the compat half shows no measurable
   benefit over the drain-handshake fix (G3 10/10 both arms). Keep the drain fix; the fuxi
   select derivation is the cheaper fix for the one bundled native-multicast profile.

## Approval

**Requested:** approve the sigreturn gate **first** (slice 1: one QEMU-only run on the harness
already in evidence; test-first, drop-on-fail — a pass by itself authorizes nothing else); the
copy-time park design and slices 2–4; and the native multicast park (slice 7: host/QEMU plus
the G3n device read on the diting's ksun 236 Image, RAM-booted, no partition written). The
device work is adb-only on the duchamp (G2/G3) and the diting (G3n) and needs the usual
per-run approval; no flashing is expected; any RAM boot or flash needs a separate in-turn
approval. A sigreturn gate pass does **not** authorize the route-choreography slice or a
sigreturn device test — those need their own approval. Commits remain the operator's call.

**Granted 2026-11-12 (operator):** the plan as requested — the sigreturn gate (slice 1), the
design and slices 2–4, and the native slice 7; the device gates (G2/G3/G3n) still need their
per-run/in-turn approvals. Slice 1 has since run and failed (see the sigreturn section's Result
bullet); the sigreturn item is dropped.

The evidence behind this plan is in
`external/port/compat-multicast-2026-11-12/` (`README.md`, `rate-10/`, `rooted-oops/`,
`parked-carrier/`, `g3-series/`, `deadframe-carrier/fault-park/`). The predecessor plan's
reliability study (`compat-multicast-carrier-plan.md`, "no parked carrier") is superseded on
the parked-carrier question by this document: the park is the carrier's own copy fault, not an
existing syscall.
