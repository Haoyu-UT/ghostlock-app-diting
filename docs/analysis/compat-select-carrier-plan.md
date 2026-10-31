# 32-bit compat victim and the `_newselect` carrier (plan)

Level: **L** — a new victim architecture and a new select carrier on the attack-critical path.
Plan first, then code (`AGENTS.md`); this document is the operator-approval artifact.

Status: **option B′ approved and implemented; G1 (QEMU), G2 (device delivery), G3 (236
no-regression) and G4 (era 5.10.81) passed 2026-10-31.** The full dance writes on all six
store images under QEMU; the helper execs and runs its syscalls on the real 236 ROM under
`untrusted_app` + the app seccomp filter; and the carrier carries the whole chain on the
launch 5.10.81 ROM — **10/10 fresh boots**, 8/8 route calls clean per run, `exploit
complete` T+6.648–7.749 s. 5.10.101 remains QEMU-gated (no ROM package on disk). The
original option A/B assessment is superseded by the revision in *Design options*.

## The problem

The sigreturn-only kernels (5.10.43, 5.10.81, 5.10.101; six store images) have no 64-bit
blocking carrier. The stale `rt_mutex_waiter` strip sits at depth **0x1c0** below the
syscall-entry sp (0x58 bytes at depths 0x168–0x1c0). A 42-candidate sweep of unprivileged
64-bit syscalls found only `rt_sigreturn`'s 0x200-byte fpsimd copy (destination 0x300)
spanning it: the closest others are `clone3` 0x1a0, `recvmmsg` 0x198, `bpf` 0x190 and
`sendmmsg` 0x180 (each short at the deep end), while `pselect6`'s 0x210 buffer zeroes the
shallow half through its `res_*` slots and the `ptrace` regset copies are too deep
(0x338/0x460). `PR_SET_MM_MAP` is compiled out, mqueue/SysV IPC are off, and the remaining
big copies are capability-gated.

`rt_sigreturn` stamps correctly but returns the victim to EL0, where the `+0x188`
context-switch class can paint the strip: ~50 % on 5.10.236 and 4/5 on the 81-era rig
(one unrelated W3 failure). A carrier that parks the victim in-kernel would remove that
exposure on the kernels that need it.

## What the 2026-10-31 measurements say (QEMU, host-only)

A 32-bit (AArch32/compat) victim changes both sides of the geometry, because the futex
chain and the select implementation are different kernel code. All numbers below are
measured on the six store images (identical), with the armv7 victim under the existing
QEMU harness; the direct readbacks were taken with a kprobe over the parked victim's
stack.

### Required depth

| victim | futex entry | entry→`do_futex` | entry→`futex_wait_requeue_pi` | strip home |
|---|---|---|---|---|
| 64-bit | `__arm64_sys_futex` | 0x90 | 0xb0 | 0x1c0 |
| 32-bit | futex_time32 (240) | 0x80 | 0xa0 | **0x1b0** |
| 32-bit | futex_time64 (422, `__arm64_sys_futex`) | 0x90 | 0xb0 | **0x1c0** |

(waiter local at `futex_wait_requeue_pi.sp − 0x110`.)

### Compat select carriers

- `pselect6` (335) and `pselect6_time64` (413): the `compat_core_sys_select` buffer
  destination is **0x250**; the user region is [0x1d8,0x250] and the `res_*` zeroing
  [0x160,0x1d8] covers the strip. **Fails**, and is 0x40 deeper than the 64-bit buffer.
- `_newselect` (ARM syscall 142, `compat_sys_select`): the buffer destination is **0x1e0**;
  the three in/out/ex copies span **0x78 bytes at [0x168,0x1e0]**.
  - With **futex_time64** (strip 0x1c0), the 0x58-byte stamp occupies buffer offsets
    0x20–0x77, so the whole strip is user-copied — one byte of margin.
  - With **futex_time32** (strip 0x1b0), the user copy covers strip bytes 0–0x47 and the
    kernel's `res_*` zeroing supplies bytes 0x48–0x57 — exactly the stamp's zero
    `deadline`/`ww_ctx` (`waiter_words()` sets both to 0).

### Readback and parking

- The 11 stamp words are read back exactly from the parked victim's stack on every one of
  the six images: `0x1122334455667700..770a` at home 0x1c0 (time64) and
  `0x2233445566778800..8808, 0, 0` at home 0x1b0 (time32).
- The fd_set bytes **are** the stamp, so every set bit must map to an open, non-ready fd.
  320 empty-pipe read ends at fds 0..319 (write ends kept open at 640..959; max_fds 1024;
  nfds 320 is not clamped and stays on the 256-byte stack path: size 0x28, 6×0x28 ≤ 0x100)
  satisfy it: the victim parks in `do_select` and is killed by SIGKILL with the stamp in
  place. The stamp's low bits fall on fds 0..7, which are read ends too.
- Other compat candidates fail: ppoll 0xf0 @0x404; sendmsg compat msghdr 0x1c @0x1a0
  (partial); recvmsg msghdr @0x120; sendto sockaddr @0xe8; compat iovec imports are
  `__get_user` loops; the compat sigreturn path copies only 8 bytes.

### The 5.10.236 control and the scope

On 5.10.236 the compat strips are **0x200** (time32 chain 0xf0) and **0x210** (time64
chain 0x100), while the `_newselect` buffer stays at 0x1e0 — it cannot reach them. A
32-bit-only app (or a 32-bit victim on 5.10.136+) would lose the select route, so the
compat carrier must be scoped to the sigreturn-only kernels.

## Design options (revised 2026-10-31 after the code inspection)

**A. A 32-bit build of the whole exploit native.** Rejected. The native stores kernel VAs
in `std::uintptr_t` end-to-end (`WriteRequest::target`, `PayloadWriteLayout`,
`HeapContext::fake_*`, the `KernelAddress` domains, ~200 uses). On armv7 that type is 32
bits, so every `0xffffff80…` address truncates; A means retyping the attack core to a
64-bit kernel-address type and re-gating every stage — W1, W2, the `init_cred` repair,
W3 and the handoff — as a 32-bit process. The test surface multiplies for no extra
carrier capability.

**B. A victim-only 32-bit helper with the 64-bit native as collaborator.** Superseded.
Its cost was the `MAP_SHARED` futex and a cross-process requeue/walk choreography. If the
helper owns all three roles (waiter, owner, consumer) the futex stays private, and the
cross-process race disappears.

**B′. A carrier helper (chosen).** The 64-bit native keeps every kernel-address
computation. It builds the 0x78-byte compat fd_set bitmap from the same single-source
stamp the 64-bit select route uses (`waiter_words()`/`encode_waiter_words()`), and hands
it to a small armv7 process. That process runs the existing dance with the bitmap:
waiter `FUTEX_WAIT_REQUEUE_PI` → `_newselect` park, owner PI lock, consumer
`sched_setattr` walk. It reports counters; it never sees a kernel address, a profile, a
spray or a payload page. All stages (W1/W2/W3, the repair) go through one seam,
`route::middleware::run_middleware_route()`.

Feasibility, checked before choosing B′:

- **App seccomp**: on arm64 bionic's filter accepts both `AUDIT_ARCH_AARCH64` and
  `AUDIT_ARCH_ARM` (`ValidateArchitectureAndJumpIfNeeded`), dispatching ARM syscalls to
  the 32-bit app policy. That policy allowlists `_newselect` (lp32) and `sched_setattr`
  (all) — the two non-obvious syscalls the carrier needs. Source-checked; gate G2 proves
  it on the device.
- **Delivery**: a static armv7 ELF packaged as `lib/arm64-v8a/libghostlock32.so` sits in
  the same `nativeLibraryDir` as `libghostlock.so`, which the app already execs pre-W1.
  Static removes the 32-bit loader dependency. Whether PackageManager extracts a 32-bit
  ELF from the arm64 lib dir is gate G2's first question.
- **Packing**: `compat_get_bitmap()` pairs two user 32-bit words into
  `(l2 << 32) | l1`, so the compat buffer is just the little-endian 0x58-byte waiter
  strip written at byte offset `select_dst_depth − waiter_home` — 0x20 for the time64
  chain (11 words, exact fit), 0x30 for time32 (9 words, `deadline`/`ww_ctx` supplied by
  the kernel's `zero_fd_set(fds.res_in)`).

**C. Status quo.** The 81/101 floor stays sigreturn (4/5 on the 81-era rig); nothing
changes.

## Implementation outline (B′)

1. **Shared protocol** — `src/core/compat/carrier_protocol.h`: fixed-width command
   (mode, futex ABI, nfds 320, timing, CPUs, 0x78-byte bitmap) and result (status, step,
   errno, select ret/errno, calls, successes, drain, clean/disarmed, smoke values).
2. **Bitmap packer** — `src/core/route/compat_bitmap.{h,cpp}`: pure, host-testable.
   Resolves `offset = select_dst_depth − waiter_home`; time64 requires the full 0x58 at
   `offset + 0x58 <= 0x78`; time32 requires `deadline == ww_ctx == 0` and the zero tail to
   lie inside the kernel's `res_*` window `[dst−6n, dst−3n]` with n = 0x28. 236's strip
   (0x200) must underflow and refuse. The ABI follows the measured home (0x1b0 → time32,
   0x1c0 → time64); any other pair is refused.
3. **Native driver** — `src/core/route/compat_carrier.{h,cpp}`: for each attempt, acquire
   an anchor slot exactly as the 64-bit route does, build the words from
   `heap.current.fake_*` + `slide_init_task()` + `waiter_prio_word()`, pack, spawn
   `dirname(readlink("/proc/self/exe"))/libghostlock32.so`, send the command over a pipe
   (fds above 320), read the result, map it to `RouteStatus`. On a dirty result the helper
   exits 70 and the native stops the run, matching today's dirty stop.
4. **Helper** — `src/core/compat/carrier_main.cpp` (armv7, static, API 31): a smoke mode
   (futex / timerfd_create / `_newselect` / `sched_setattr`) for gate G2, and the run
   mode: three threads with the existing semantics, fd planning (every set bit → one
   never-ready fd; fd 319 grown by `dup2` without setting its bit so the stamp word is
   untouched), `_newselect`, bounded drain, `ghost_disarm`, counters. One helper
   invocation per attempt, so anchor slots are consumed exactly as today.
5. **Profile** — three optional keys under `route.select_stack`: `compat_carrier` (0/1),
   `waiter_home` (0x1b0/0x1c0), `select_dst_depth` (0x1e0). Kotlin `SelectConfig` →
   `nativeValue` → v2 wire → native `SelectStackLayout`, with the schema digest and the
   native-document golden re-frozen. No app launch/UI change: the app still runs the
   64-bit native, which spawns the helper itself.
6. **Build** — new `src/Makefile` target (armv7a-linux-androideabi31-clang, `-static
   -no-pie`), and `prepareGhostlockJniLibs` copies/strips it into
   `app/src/main/jniLibs/arm64-v8a/libghostlock32.so`.
7. **Gating** — the compat profile stays external (SAF) until the 81 gate; the bundled
   81/101 assets stay sigreturn. The packer refuses 236 (strip 0x200 > the 0x1e0 buffer).

## Implementation status (2026-10-31, slice 1)

Landed: the protocol, the bitmap packer and its host test, the helper's smoke
mode and static armv7 build, the native driver's geometry plan + spawn + smoke
path, the middleware branch, the three profile keys end-to-end (schema digest
`0xe620f6d4022894a3`, native-document golden re-frozen), and the APK
packaging (`lib/arm64-v8a/libghostlock32.so`, ELF32 ARM static). Gates run:
arm64 native and armv7 helper at zero warnings, `lint-tidy` rc 0, the full
native host suite, profile-core 41, app 154 with only the known fixture
failure, `cmp_disasm` identical instruction counts (the FAIL is the known
missing-`multicast_*` control), and a QEMU smoke on 5.10.43/81/101/236 where
the helper executed `futex`/`timerfd_create`/`_newselect`/`sched_setattr`/
`pipe2`/`fcntl`/`dup2`/`prctl` and returned the protocol result. Evidence:
`external/port/compat-select-carrier-2026-10-31/` in the root repo (README,
QEMU logs and harness, the two external profiles).

Since then (same day): the helper's run mode and the native's real stamp path
landed. **G1** — the full dance plus a verified write (`selinuxfs` enforce
1 → 0) on all six store images: 5.10.81 ×2, 5.10.101 ×3, and 5.10.43 after
the anchor-alignment fix; every run `status=0`, `calls=128`,
`successes=128`, `drain=0`. Two bugs the gate caught: the futex wait timeout
must be **absolute** (`now + route_wait_ms`), and the anchor must be
**8-byte aligned** (43's `dump_skip.zeroes` is 4-aligned and the walk faults
on an `ldar`; align up). **G2** — on the 236 rig (674 APK over 672, the
Downloads external profile temporarily the 236 probe, restored after): under
`u:r:untrusted_app:s0:…` and `Seccomp=2 Seccomp_filters=1`, the native
exec'd the armv7 helper from `nativeLibraryDir` and every required syscall
returned 0; the packer then refused the 236 geometry (`HomeBelowDepth`) as
designed. Evidence: `external/port/compat-select-carrier-2026-10-31/`
(README, `g1-qemu/`, `g2-device/`).

## No-flash test paths (audited 2026-10-31)

The earlier wording implied the era/101 ROM had to be flashed before any
device test. The audit splits it:

- **Hard limit — the 236 kernel cannot run the carrier, and that is geometry,
  not the phone.** On 5.10.236 the compat strips are 0x200 (time32) / 0x210
  (time64); the compat `_newselect` buffer's deepest user byte is 0x1e0. The
  kernel keeps the six bitmaps on its stack only while `FDS_BYTES(n) <= 42`,
  i.e. n ≤ 320 (6 × 40 = 240 of the 256-byte `stack_fds`), so a wider bitmap
  moves to kmalloc and never touches the stack; and compat `pselect6`'s 0x250
  buffer zeroes the strip through its `res_*` slots. `HomeBelowDepth` is the
  correct outcome on 236, under QEMU and on the device alike.
- **G2 is testable on the current 236 rig with no flash.** The driver now runs
  the helper smoke *before* the geometry check, so a compat-flagged variant of
  the rig's own 236 profile (external, never bundled) execs
  `libghostlock32.so` under the app's real SELinux domain and seccomp filter,
  logs the eight syscall results, and then stops at the geometry refusal. That
  settles PackageManager extraction, exec, SELinux and the ARM seccomp branch —
  the decisive product questions — without writing anything.
- **A no-flash full-route device test is possible: a RAM-only kernel swap.**
  `fastboot boot` a 5.10.101 diting `Image` inside the current ROM's own boot
  image (kernel replaced, ramdisk byte-identical). Nothing is written; any
  reboot returns to 5.10.236. Precedent: the 5.10.209 and 5.10.226 diting
  kernels boot the current Android 15 userspace this way and the app ran
  (`external/port/k209/`, `k226/`). 5.10.81 is known not to bring adbd up on
  this userspace (2026-10-11, ~36 s, RAM only); 5.10.101 is untested and is the
  only sigreturn-only diting kernel with a plausible boot. If it boots, the
  101 compat profile runs the measured geometry with the current userspace —
  the full route on the device with no flash. `fastboot boot` still needs the
  operator's in-turn approval, and the 101 profile stays a QEMU-derived
  candidate until the gate passes.
- QEMU G1 covers the full dance and write on all six Images, including 101,
  with no phone at all.

## Test plan

**G0 — host, no device.** arm64 and armv7 builds at zero warnings; `lint-tidy`; full
native host suite; new `compat_bitmap_test` (time64 exact at 0x20, time32 at 0x30 with the
zero-tail assertion, 236 refuses, a deeper home refuses, the little-endian word pairing);
protocol static asserts; profile digest/golden tests; `cmp_disasm.py` before/after (read
counts, not the verdict); Gradle tests and an APK inspection (`file` says ELF32 ARM; both
files in the arm64 split).

**G1 — QEMU engine gate — PASSED 2026-10-31.** The real static helper runs the full
dance in the guest on all six store images; the harness packs the stamp from the
image's own symbols and verifies the *write* by `selinuxfs` enforce 1 → 0. 6/6 pass
(43 after an 8-byte anchor alignment); 5.10.236 refuses by construction. Both futex
ABIs were run on the 101 image in one boot (time32 at 0x1b0, reset `enforce=1`, time64
at 0x1c0 at a fresh slot): both 128/128 and `enforce=0`. The `CMP_REQUEUE_PI
ret=-1 errno=35` is the shipped route's own signature (the archived device logs show
the same line); the stale waiter comes from the wait's timeout path.

**G2 — device delivery/seccomp probe — PASSED 2026-10-31.** On the 236 rig (APK install
only; no flash), the native ran the helper smoke before the geometry check: all eight
syscalls returned 0 under `untrusted_app` + the app's single seccomp filter, then
`HomeBelowDepth` stopped W1 as designed.

**G3 — 236 no-regression — PASSED 2026-10-31.** The unchanged 64-bit select route on
the shared 674 build: five completed fresh-boot runs (`state=completed`, KernelSU
ready); two extra boots were the documented FAILED-TO-START class and were re-run.

**G4 — era 5.10.81 device gate — PASSED 2026-10-31 (10/10).** The RAM boot was tried
first and failed: the kernel-swap image was built and verified (md5 `2389687d…`) and
`fastboot boot`-ed with the operator's in-turn approval; the bootloader accepted it, but
the 5.10.101 kernel did not bring the Android 15 userspace up to adb and the device reset
to the installed 236 (`bootreason=bootloader`) — the Android 12/13-era GKI kernels do not
run this userspace (5.10.209/226 do, being 5.10.2xx).

The device path was therefore a ROM flash. With the operator's approval the era
`V13.0.3.0.SLFMIXM` fastboot package was flashed (full wipe, both `_ab` slots, 0 FAILED
lines), the documented patched `boot_a` restored root-from-boot, and the 674 test APK
(the 81 compat profile bundled) installed. **Ten fresh-boot runs (the operator extended the series from five to ten), 10/10 completed**: every
run `page_free=1 reason=policy+scratch+anchor`, geometry 0x1b0/0x1e0 (offset 0x30, time32,
nine words + zero tail), 8/8 `compat route attempt=1/4 … clean=1/1` calls (anchor slots
0–7), each engine `status=0 calls=1 success=1 drain=0`, seccomp bypassed, `exploit
complete` T+6.648–7.749 s, `KernelSU ready`, enforce restored to 1; no kernel fault in the
polled kmsg. Stores `20261031-134149`, `-134355`, `-134540`, `-134730`, `-134921`, `-135523`, `-135717`, `-135902`, `-140045`, `-140237`. The
harness needed three fixes: the app's select-route validation for a compat profile (no
`waiter_shift`; require `waiter_home`/`select_dst_depth`), the era ROM's zero-bounds
执行 label (tap the bottom-most wide clickable parent), and a 2 s settle between wake and
unlock swipe (plus a fail-closed keyguard gate). The remaining device work is the return
to 236 and, if a 101 ROM package appears, the 101 series; evidence:
`external/port/compat-select-carrier-2026-10-31/g4-device/`.

**G5 — 5.10.101 series outcome.** Same series as G4 if the ROM flash was used; promotes
or rejects the candidate. 5.10.43 has no device — QEMU evidence only.

**G6 — evidence.** `external/port/compat-carrier-<date>/` with the QEMU logs, run stores
and excerpts; plan-doc result; PORT-PLAN.

## Risks

- **Packaging**: PackageManager may refuse or skip a 32-bit ELF in the arm64 lib dir.
  G2's first question; fallback is a separate 32-bit helper APK launched over IPC.
- **Seccomp**: source says the ARM branch is present; a device build could differ. G2.
- **The dance**: the 2026-10-31 harness proved the select copy, not the requeue/walk with
  a 32-bit waiter. G1.
- **The zero tail (time32)**: relies on `deadline`/`ww_ctx` being zero and on
  `zero_fd_set(res_in)`. The packer asserts the words and the window; time64 is the
  full-stamp alternative if the tail proves fragile.
- **Process lifetime**: the helper is another untracked process (phantom trimmer,
  `oom_score_adj`), and a dirty race exits it while a walk may be pending — the same
  semantics today's `exit_group(70)` accepts.
- **Anchor slots**: one slot per attempt executed; the 4-attempt ladder still allocates
  per attempt, so a run's consumption is unchanged.
- **Device logistics**: the era re-flash and the 101 ROM need per-turn approval.
- **Anchor alignment (new, G1)**: the walk's `ldar` faults on a 4-byte-aligned
  anchor (5.10.43's `dump_skip.zeroes`). The allocator should refuse or align
  any `(image + slot*stride)` not 8-byte aligned, and the extractor's anchor
  emission must pick an aligned offset.

## Approval

**Approved by the operator on 2026-10-31: option B′ (carrier helper).** Implementation
starts with the profile keys, the packer and its host test, the helper smoke mode and the
packaging; the engine follows after G2. Commits remain the operator's call.
