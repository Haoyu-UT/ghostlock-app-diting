# AArch32 compat `MCAST_BLOCK_SOURCE` carrier (plan)

Level: **L** — a new route carrier on the attack-critical path (a new syscall park and a
new profile/wire surface). Plan first, then code (`AGENTS.md`); this document is the
operator-approval artifact.

Status: **proposed, nothing implemented.** The geometry below is derived from the store
Images by disassembly (the same conventions the extractor uses); no QEMU run and no device
run has been done for this variant. The existing routes and the shipped bundle are
unchanged.

## The problem

The Realme Neo7 image (`6.1.134-android14-11-o-gd252f36df142`, issue #6) has exactly one
feasible route: **sigreturn**. That is the weakest carrier measured on this port — on the
5.10 2×2 the route read **11/11 select vs 5/12 sigreturn** (p ≈ 0.0046, exploratory), and
the 236 sigreturn series is 8/15, every failure the `+0x188` class. The 64-bit multicast
route is infeasible on that image: its `group_source_req` copy lives at `sp+0x18`
(depth 0x348) while the futex waiter is at 0x198 — the copy window ends **0xa8 below the
waiter start** (0xe8 below the lock slot) with this image's own futex chain. The current
verdict's "0x48 short" uses a fixed chain that double-counts `do_futex`; the compat
derivation below fixes that number, and the 64-bit route stays infeasible either way.

The same option has a **compat (AArch32) branch** with a different stack local: when
`is_compat_task()` is true (`TIF_32BIT`, thread_info bit 22), `do_ip_setsockopt` copies
the **32-bit `group_source_req` (0x104 bytes) to `sp+0x120`** instead of the 64-bit
0x108 to `sp+0x18`. That copy lands on the waiter.

## What the images say

Formula, the extractor's convention for this route:

```
setsockopt_depth = Σ(frames on the setsockopt chain) − copy_local
waiter_depth     = Σ(frames on the futex chain)     − waiter_local
waiter_off       = setsockopt_depth − waiter_depth
window_end       = waiter_off + lock_offset + 8          (the app's rule)
strip_end        = waiter_off + 0x58                     (the 11-word stamp)
feasible iff window_end ≤ buffer_size and the waiter is compact
```

| image | chain Σ | copy local | copy depth | futex home | waiter_off | window_end | strip_end | buffer | verdict |
|---|---|---|---|---|---|---|---|---|---|
| 6.1.134 (Realme) | 0x360 | sp+0x120 | 0x240 | time64 **0x198** | **0xa8** | 0xe8 | 0x100 | 0x104 | **feasible** |
| 6.1.134 (Realme) | 0x360 | sp+0x120 | 0x240 | time32 **0x1e8** | **0x58** | 0x98 | 0xb0 | 0x104 | feasible |
| 6.1.138 (duchamp) | 0x350 | sp+0x120 | 0x230 | 0x1e8 (both ABIs) | **0x48** | 0x88 | 0xa0 | 0x104 | **feasible** |
| 64-bit control, 6.1.134 | 0x360 | sp+0x18 | 0x348 | 0x198 | 0x1b0 | 0x1f0 | — | 0x108 | infeasible |

Measured frames:

- 6.1.134 — setsockopt: `__arm64_sys_setsockopt` 0x10, `__sys_setsockopt` 0x60,
  `sock_common_setsockopt` 0x10, `udp_setsockopt` 0x10, `ip_setsockopt` 0x40,
  `do_ip_setsockopt` 0x290. Futex: `__arm64_sys_futex` 0x80 calls
  `futex_wait_requeue_pi` directly (0x1b0); `__arm64_sys_futex_time32` 0x70 goes through
  `do_futex` 0x60. Waiter local 0x98.
- 6.1.138 — setsockopt: 0x10 / 0x60 / 0x10 / 0x10 / 0x40 / 0x280. Both futex wrappers
  (0x70) call `do_futex` (0x60); `futex_wait_requeue_pi` 0x1b0. Waiter local 0x98.
- The compat copy site: `do_ip_setsockopt` has a `tbnz w8, #0x16` (TIF_32BIT) whose target
  memsets 0x104 bytes and then `copy_from_sockptr(sp+0x120, optval, 0x104)`; the same case
  has the non-compat `copy_from_sockptr(sp+0x18, optval, 0x108)`. Both images carry the
  same pair. The kernel's post-copy code reads the group/source sockaddr headers and
  rejects a bad family *after* the copy; the input buffer is not written.

## Device capability

The route needs a compact (`5.x`/`6.1`) waiter and `CONFIG_COMPAT`:

- **duchamp — POCO X6 Pro 5G, 6.1.138 (in hand).** The compact waiter; the feasible
  geometry above; the device already runs the app and the device-proven select route. This
  is the natural 6.1 test unit.
- **diting — 5.10.236 (in hand).** Compact waiter and the known-good G2 rig for the armv7
  helper; the 5.10 `ip_setsockopt` compat shape is not derived (5.10 inlines the option
  handlers and has no `do_ip_setsockopt`), so the first release scopes to 6.1 and the
  diting is used for the helper smoke only.
- **6.6.66 OnePlus 13s / 6.12 devices.** `rt_waiter_node` — non-compact; the existing
  route×waiter-shape guard refuses multicast/sigreturn. Out of scope by construction.
- **Realme 6.1.134.** The target image; feasible with a larger margin on time32 but the
  cleanest placement on time64. It is the reporter's unit; the QEMU gate covers the image,
  and the device result would come from a borrowed unit or the reporter.

## The mechanism

The compat `group_source_req` (32-bit alignment, ABI-fixed, derived from the image's own
0x104 copy):

```
0x00  gsr_interface (u32)
0x04  gsr_group     (sockaddr_storage, 128 B)
0x84  gsr_source    (sockaddr_storage, 128 B)
0x104 end
```

The native builds the struct and places the 11-word `waiter_words()` stamp at
`compat_waiter_off`. With the chosen placements:

- 6.1.134, time64: stamp 0xa8–0x100, entirely inside `gsr_source`'s padding; the source
  family at 0x84 is outside the stamp, so it can be set (to AF_UNSPEC, matching the
  64-bit route's group-family choice); the group family at 0x4 is outside it too.
- 6.1.138: stamp 0x48–0xa0; the source header (0x84–0x8c) falls inside the stamp's later
  words. The kernel reads (does not write) that header and will reject the call; the route
  accepts a failed `setsockopt` because only the copy is load-bearing (the 64-bit route's
  own success condition is `setsockopt == 0 || consumer_success > 0`). The task and lock
  words at 0x78/0x80 are inside `gsr_group`'s padding, which the kernel never interprets.
- The stamp words are the existing single source: `memory::waiter_words()` (tree stamp,
  `slide_init_task()`, the anchor lock word, `waiter_prio_word(FAKE_WAITER_PRIO,
  compact_waiter_has_wake_state())`). The 6.1 `wake_state` word is already handled.

Choreography (the same dance as the compat select carrier, one syscall different):

1. The armv7 helper's waiter thread parks in `FUTEX_WAIT_REQUEUE_PI` (time32, syscall 240,
   or time64, 422 — both enter `__arm64_sys_futex`/`_time32` and then `do_futex`;
   the 32-bit task sets TIF_32BIT).
2. The owner thread takes the PI lock; the main thread/the engine drives
   `CMP_REQUEUE_PI`; the waiter wakes.
3. The waiter thread creates `socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, 0)` and calls
   `setsockopt(fd, IPPROTO_IP, MCAST_BLOCK_SOURCE, stamp, 0x104)` — the compat branch
   copies the stamp over the stale waiter.
4. The waiter signals the consumer right after the call; the consumer rotates
   `sched_setattr(waiter_tid)` to drive `rt_mutex_adjust_prio_chain`; the native's
   `waiter_words` lock word points at the anchor slot (the same anchor allocator as the
   select carrier).
5. Bounded drain, `ghost_disarm`, counters, engine result — the existing select-carrier
   machinery.

The route is not a new primitive: it is the same futex/CVE bug, with the stale waiter
stamped by the compat multicast copy. It does not touch W1/W2/W3, the pipeline, or the
payload page (the anchor path is page-free, as the multicast route's anchored form already
is).

## Design

### 1. Extractor (`tools/extract_rs`)

- New `derive::derive_compat_multicast_layout()`:
  - Find the compat copy: in `do_ip_setsockopt` (5.x: `ip_setsockopt`; the compact-waiter
    scope means the split `do_mcast_group_source` is not required) locate the
    `copy_from_sockptr` whose size immediate is the compat struct size (0x104 on both
    sampled images), reachable from a `tbnz w8, #0x16` branch, and the non-compat sibling
    (0x108 at sp+0x18). A missing/multiple site is `Unknown`, never a guess.
  - Sum the setsockopt chain per image with the direct-call validation (the same
    `has_call_or_tail_branch` logic the inlined-`__sys_getsockopt` fix introduced).
  - Derive both futex homes per image (`__arm64_sys_futex_time32` and
    `__arm64_sys_futex`, each with `do_futex` only when the wrapper actually calls it) and
    the waiter local via the pi_tree-index proof (already register-agnostic).
  - Apply the window rule and the compact-waiter requirement; prefer the ABI whose stamp
    does not overlap the source sockaddr header (6.1.134: time64; 6.1.138: both are
    0x48, take the larger remaining margin).
  - Emit `compat_carrier = 1`, `compat_waiter_off`, `compat_buffer_size`,
    `compat_futex_abi` on the multicast verdict; the route becomes feasible with a reason
    naming the compat branch and the numbers.
- Drive-by correctness fix: the multicast verdict's waiter depth currently uses the fixed
  `FUTEX_CHAIN`; on images where `do_futex` is inlined (6.1.134) it double-counts 0x60.
  Use the per-image home (the same fix class as tcp). On 6.1.134 the 64-bit verdict's
  numbers change from the fixed chain's waiter_short 0x48 to waiter_short 0xa8 /
  lock_short 0xe8; still infeasible.
- `report::conf_compat_multicast_route_geometry()` renders the compat block;
  `main.rs` uses it when the chosen verdict carries `compat_carrier`.
- Tests: unit coverage of the copy-site detector and the window; store GT cases for
  6.1.134 (time64 0xa8; time32 0x58; window 0xe8/0x98) and 6.1.138 (0x48; window 0x88),
  with the 64-bit controls; a 5.10 image must not produce a compat multicast verdict
  unless its own 5.10 shape is derived (it is not in this slice).

### 2. Profile and wire

`route.multicast_waiter` gains four optional keys, mirroring the select carrier's style:

```
compat_carrier   = 1          # the route runs in the armv7 helper
compat_waiter_off = <i32>     # the compat copy's waiter offset (positive)
compat_buffer_size = <u32>    # the compat struct size (0x104; emitted, not assumed)
compat_futex_abi = 0 | 1      # time32 / time64
```

The existing `task_offset`/`lock_offset` and the anchor trio are reused. Touches:
`src/core/profile/model.h` (`MulticastWaiterLayout`), `binary.cpp` (`kRouteMulticast`),
`profile-core` `MulticastConfig`/`MulticastGeometry` + `NativeProfile`, the schema digest
and native-document golden (re-freeze; the select compat addition is the precedent), and
`ProfileResolver` validation (compat requires the compact waiter, the three compat fields
and the two offsets; absent compat keeps the 64-bit route). The app's route picker needs
no new route name: the multicast verdict is simply feasible with the compat facts; the
profile's block tells the native which shape to run.

### 3. Native

- `route::compat::carrier_requested()` also checks `multicast_waiter_layout()
  .compat_carrier`; `route_middleware.cpp` is unchanged.
- `run_compat_carrier()` branches: select keeps the bitmap path; multicast builds the
  0x104 stamp (the existing `waiter_words()` + the anchor slot + the struct header), fills
  a v3 command, and reuses the same spawn/attempt/result/dirty-stop flow. The smoke runs
  first (the same G2 shape).
- Protocol v3 (`carrier_protocol.h`): `CarrierMode::Multicast`, a 0x104 `stamp` field and
  `stamp_bytes`, the option/level (IPPROTO_IP / MCAST_BLOCK_SOURCE = 43) or a fixed
  multicast mode, and two new smoke slots (`socket`, `setsockopt`; the array grows to 11).
  The version bump makes a stale helper refuse; both ship in the same APK.
- Helper (`carrier_engine.cpp`, armv7): in the multicast mode the waiter's park is
  `setsockopt` instead of `_newselect` — create the UDP socket, call
  `syscall(__NR_setsockopt, ...)` (arm EABI 294; the arm64 compat table aliases it to
  `__arm64_sys_setsockopt`, which is what makes `is_compat_task()` true), record the
  result/errno, close, trigger the consumer, drain/disarm. The owner/consumer threads and
  the result mapping are unchanged; the smoke calls both futex ABIs plus socket/setsockopt.
- The helper binary (`libghostlock32.so`) is already built and packaged; no new ABI or
  packaging risk.

### 4. Route selection and bundle

- The extractor offers the compat multicast as a feasible verdict; on 6.1.134 it joins
  sigreturn in the feasible report (the app's picker/dialog already handles multiple
  feasible routes).
- **No bundled profile changes in the implementation slices.** The 6.1.134 golden stays
  on sigreturn and the 6.1.138 stays on select until the device gate. After G3, the
  bundle/ship script may render the compat route for images where the extractor chose it;
  the Realme golden switches only after a device result (the reporter's unit or a borrowed
  one).

## Test plan

**G0 — host, no device.** Extractor unit + the store GT tests (both images, both ABIs,
the 64-bit controls, the fail-closed cases); the native and helper builds at zero
warnings; `lint-tidy`; the full native host suite; profile-core/app tests; the schema
digest/golden re-freeze; `cmp_disasm.py` before/after (instruction counts; the known
missing-`multicast_*` control FAIL is unchanged); an APK inspection that the armv7 helper
is still `ELF 32-bit ARM static` and paired with the v3 native.

**G1 — QEMU engine gate.** The static armv7 helper runs the full multicast dance in the
guest on the 6.1.134 and 6.1.138 Images (and the 5.10.236 control, which should refuse or
be out of scope): the harness packs the stamp from the image's own symbols, verifies the
copy/placement with a readback, and verifies a real write (`selinuxfs` enforce 1 → 0) the
way the select carrier's G1 does. Both futex ABIs on 6.1.134 (0xa8/0x58) and 6.1.138
(0x48). This is the decisive kernel-side gate before a device.

**G2 — device delivery/syscall smoke.** On the duchamp (Android 14) and the diting 236
(control): a multicast-compat profile makes the driver run the extended smoke first —
`futex`, `futex_time64`, `socket`, `setsockopt`, `sched_setattr`, the existing slots —
under `untrusted_app` and the app's single seccomp filter. This settles the armv7 helper
on Android 14 and the ARM seccomp branch for the two new syscalls; the geometry check then
refuses or proceeds as designed.

**G3 — device full route (duchamp 6.1.138).** An external (SAF) compat-multicast profile
from the G1-verified geometry: the full dance, the consumer walk, a verified write, the
restore. A small fresh-boot series (e.g. 5 runs) against the 6.1.138 select-route control
(the select rate is already known there). If the route fails, the run must fail closed —
the dirty stop and the enforce restore are the select carrier's existing semantics.

**G4 — Realme 6.1.134.** The image's geometry is QEMU-covered in G1; the device run is the
reporter's or a borrowed unit. The golden/profile switch is gated on that result.

**G5 — evidence.** `external/port/compat-multicast-<date>/` with the QEMU logs, the run
stores and excerpts, the device logs; the plan's result section and `PORT-PLAN.md`.

## Risks

- **The compat copy is a compiler artifact, not an ABI.** The 0x104-at-sp+0x120 shape is
  measured on two images; a different 6.1 build may move it or inline the branch. The
  derivation must fail closed (`Unknown`/infeasible), and the app must never fall back to
  a family constant.
- **Kernel validation after the copy.** On the 6.1.138 placement the source sockaddr header
  lies inside the stamp; the kernel reads and rejects it (the call returns an error) but
  does not write the input. The route accepts a failed `setsockopt`; if a build ever wrote
  or fault-checked that buffer, the placement would need re-derivation.
- **Non-blocking stamp lifetime.** Unlike select, the copy is followed by a short
  processing path and the syscall returns; the walk races the frame reuse, as the 64-bit
  multicast route does (its 5.10 anchored form read 4/4 when page prep passed). The 6.1
  rate is unknown until G3; this is a second route, not a proven faster one.
- **The armv7 helper on Android 14.** The select carrier's G2 was on Android 12/5.10; the
  new smoke slots are the first Android 14 evidence for `socket`/`setsockopt`.
- **Anchor safety/alignment.** The anchor trio is the same object and the same allocator;
  the 8-byte alignment rule and slot exhaustion already exist. The 6.1.134/6.1.138
  anchors are in the shipped profiles, so the values exist.
- **Wire/schema churn.** Four optional fields change the schema digest and the golden
  tests; the select compat addition is the precedent and the re-freeze is mechanical, but
  every document's wire version is shared — the G0 digest test is the guard.
- **The fixed futex chain in the current multicast verdict.** This plan fixes it to the
  per-image home; the 64-bit verdict's shortfall numbers change (still infeasible). The
  store supersets and the reports must be regenerated in the same change.
- **Scope.** 5.x compat multicast is not derived (the 5.10 `ip_setsockopt` shape); the
  first release targets 6.1 (the Realme) and uses the diting only as the helper-smoke
  control.

## Implementation slices

1. **Extractor + GT tests (host-only).** The derivation, the verdict facts, the report
   renderer, the per-image futex-chain fix, the store tests; no wire, no profile asset.
2. **Profile/wire/model.** The four optional keys end-to-end behind the unused-by-default
   flag; digest/golden re-freeze; resolver checks.
3. **Protocol v3 + helper multicast mode + native driver branch.** Not bundled; verified
   by the QEMU harness.
4. **G1 QEMU** on the two Images (both ABIs), then **G2** device smoke (duchamp + diting
   control).
5. **G3** duchamp full route series; only then the ship-script/bundle question and the
   Realme unit.

## Implementation status (slice 1, 2026-11-11)

Landed in the `compat-multicast` worktree (uncommitted): the extractor derivation
`derive_compat_multicast_layout` (with `compat_multicast_copies` / `copy_in_block` /
`copy_sites`), the verdict substitution (`analysis::apply_compat_multicast` +
`RouteVerdict::is_compat_multicast`), the route-block renderer
(`report::conf_compat_multicast_route_geometry`), its `main.rs` branch, the unit test for the
copy-site detector, and the two store GT tests. The 64-bit multicast verdict now uses the
per-image futex home (`futex_strip_home`) instead of the fixed chain; only images whose
64-bit wrapper inlines `do_futex` change (6.1.134: waiter_depth 0x1f8 → 0x198, lock_short
0x88 → 0xe8; still infeasible). The 5.x/5.15/6.1.138 wrappers call `do_futex`, so their
numbers are unchanged.

Derived values (tests pin them): 6.1.134 copy depth 0x240, futex_time64 0x198, waiter_off
0xa8, buffer 0x104, strip 0x100, source header clear; 6.1.138 copy depth 0x230, home
0x1e8, waiter_off 0x48, strip 0xa0, source header overlapped (the kernel reads it after
the copy, so the failed `setsockopt` is accepted). A forced `--route multicast_waiter`
render emits `compat_carrier = 1`, `compat_futex_abi = 1`, `compat_waiter_off = 168/72`,
`compat_buffer_size = 260`, `task_offset = 48`, `lock_offset = 56`, the compact-waiter
flag and the auto-plan anchor.

Store: the 18 six-one option supersets were regenerated with the harness invocation (all
six-one entries carry the feasible compat verdict and its plans); the 5.x/5.15/6.6/6.12
supersets are byte-identical (the compat derivation finds no copy there and its error is
not appended to the 64-bit verdict). The analysis now reports two feasible routes on
6.1.134 and refuses to choose (`chosen: null`); the store's route priority
(`select_stack`, `sigreturn`, `tcp_zerocopy`, `multicast_waiter`) keeps the bundled
choices unchanged.

Gates run: extractor 150 unit; `route_verdicts_ondevice` 4 (both GT tests); 
`options_ondevice` 1 (all 71 entries vs the regenerated goldens); `cut_ondevice` 4;
`codegen_ondevice` 1; `ship_golden_profiles.py --check` 60 bundled / 0 missing / 11 exempt.
No QEMU or device run yet; slices 2–3 are not started.

## Implementation status (slices 2–3, 2026-11-11)

Slice 2 (profile/wire) is implemented: `RouteGeometry` gained `mcast_compat_*`, the
`MulticastWaiterLayout` carries the four compat fields, `binary.cpp`'s `kRouteMulticast`
declares the four keys, and `MulticastConfig`/`MulticastGeometry` + `NativeProfile` carry
them through HOCON -> resolver -> GLK1 -> decode. The round-trip tests pin the eleven-key
schema and a compat profile's geometry. No digest/golden re-freeze was needed: the wire
digest covers the *active route's* section, the select-stack vector is unchanged, and the
native-document fixture contains no multicast-route document (5.15.194 is not in it).

Slice 3 (protocol/helper/driver) is implemented: protocol v3 adds `CarrierMode::Multicast`,
the 0x104-byte `stamp` + `stamp_bytes` + `option`, `route_result`/`route_errno`, and two
smoke slots (`socket`, `setsockopt`). The armv7 engine's waiter parks in
`socket(AF_INET, SOCK_DGRAM) + setsockopt(MCAST_BLOCK_SOURCE, stamp, 0x104)` and triggers
the consumer after the copy (the 64-bit route's shape), then drains/disarms. The native
driver's `carrier_requested()` covers both compat variants; `run_multicast_carrier()`
validates the geometry (off/buffer/task/lock/abi), acquires the same anchor slot, encodes
the `waiter_words` stamp at `compat_waiter_off`, and maps the helper result (dirty stop on
3, Ok on 0). The smoke's `setsockopt` slot accepts the semantic post-copy errors
(EINVAL/EADDRNOTAVAIL/ENOPROTOOPT/EOPNOTSUPP/ENODEV) and still fails on EACCES/EPERM/ENOSYS.

Gates run: arm64 native and armv7 helper at zero warnings; `lint-tidy` rc 0; all native
host tests; app 231; profile-core; extractor 150 + the store suites; a **QEMU smoke on both
6.1 Images** (6.1.134 and 6.1.138) where the armv7 helper ran all eleven syscalls and
reached the compat handler; and the **full-dance G1 on both 6.1 Images** (2026-11-12): the
guest init in `external/port/compat-multicast-2026-11-12/` builds the real stamp
(target/anchor/init_task from the guest kallsyms + the profile offsets), runs the helper and
verifies the write by `selinuxfs` enforce 1 → 0 (`status=0`, `calls=1`, `successes=1`,
drain 0–1 ms, both Images). Two findings from the gate are in the engine: no syscall (a log
write or `close(fd)`) between the copy and the consumer's walk, and the waiter/consumer CPU
pair must differ (a same-CPU EL0 preemption over the spinning waiter writes its user PC into
the strip). Remaining: the duchamp G2 (app seccomp/SELinux) and G3 (device series). No
device run yet.

## Approval

**Requested:** approve the **compat multicast carrier (AArch32 `MCAST_BLOCK_SOURCE`)**
design and slices 1–3; slices 4–5 need the usual per-run device approvals (G2/G3 are
adb-only on the duchamp and the diting — no flashing is expected; any RAM boot or flash
would need a separate in-turn approval). Commits remain the operator's call.

The measurements and the per-image numbers in this document are derived from the store
Images under `external/test-kernels/`; the two device Images are the Realme
`6.1.134-android14-11-o-gd252f36df142` and the duchamp
`6.1.138-android14-11-g44bda9e8f6e9-ab13792638`.
