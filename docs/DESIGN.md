# Design and measurements

> 中文: [DESIGN_ZH.md](DESIGN_ZH.md)

This is the technical companion to the [README](../README.md). It explains the
mechanism, the route list, the page-free design, how the extractor derives a
profile, and how far each kernel is verified. It does not cite internal evidence
paths.

## 1. The bug and the chain

GhostLock exploits **CVE-2026-43499**, a use-after-free in the futex
priority-inheritance code that Linux 5.7–7.1 shipped. The write rides on the
collateral of an rb-erase: a childless tree node whose `pc` is `target − 8`
writes NULL at `*(target)` without polluting the lock's tree root, so the PI
walk reads the node's own zeroed children on its way down and exits.
`waiter_tree_stamp()` in `src/core/memory/payload_builder.h` is the single
definition, shared by the route's stack stamp and the compact encoder.

The chain is three writes and one handoff:

| stage | result |
|---|---|
| W1 | SELinux switches to permissive (`enforcing = 0`, `initialized` set) |
| W2 | a live child's credentials are swapped for `init_cred` (`child uid = 0`) |
| W3 | the child's `TIF_SECCOMP` and `seccomp.mode` are cleared |
| handoff | a root script runs as `uid=0` and late-loads KernelSU |

A run either completes the handoff or stops at a named stage; the app's run
record says which.

## 2. Routes

| route | kernels served | delivery | page-free | anchor | notes |
|---|---|---|---|---|---|
| `select_stack` | 5.10.136+, 6.1, 6.6, 6.12 | pselect / `_newselect` | yes | yes | the default route; compact waiter on 5.10/6.1 |
| `sigreturn` | 5.10.43 / 81 / 101 | `rt_sigreturn` fpsimd restore | yes | yes | covers kernels older than 5.10.136 |
| `tcp_zerocopy` | 6.1 | setsockopt / UDP | no | no | page-based by nature; select is its fallback |
| `multicast_waiter` | a few kernels | IP multicast | yes | yes | no bundled profile uses it |
| `select_stack` (32-bit compat) | 5.10.43 / 81 / 101 | pselect via a 32-bit helper | yes | yes | the 32-bit delivery of select_stack |

**Route verdicts.** The extractor reads each image's own instructions, decides
which routes are feasible, and reports the numbers behind the verdict. When more
than one route is feasible the app asks the user; it never silently picks one.

**The other two 5.10 delivery paths.**

- `sigreturn` delivers the stamp through the `rt_sigreturn` fpsimd restore. It
  is for kernels whose `do_futex` frame is too shallow for the pselect route to
  reach (the 5.10.43 / 81 / 101 generation).
- **`select_stack` (32-bit compat)** covers the other half of that generation:
  the stale waiter strip sits *below* the 64-bit pselect buffer, so a statically
  linked AArch32 helper runs the race and parks in the compat `_newselect`, with
  the 64-bit native packing the bitmap. Every kernel address, the anchor
  allocator and the profile stay 64-bit. The helper refuses any geometry it
  cannot cover — 5.10.236's 0x200 / 0x210 strips are the example; it fails
  safely there, so the 236 keeps the 64-bit route.

**multicast_waiter** is not a default route: on a few 5.10 images (the 5.10.246
candidate, for one) it is the only route that works, but its geometry does not
fit other images, so no bundled profile depends on it.

## 3. Page-free routes

The old chain depended on a sprayed payload page: leak a slab page, free it,
reclaim it with controlled content, then hope the frag allocator hands the same
page back. The page-free design takes that dependency away from the anchored
routes:

- **Lock anchor.** A named, all-zero `.bss` region in the kernel
  (`dump_skip.zeroes`, `bm_pmd`, `serial8250_ports`, …) supplies slots for the
  fake lock. Slots rotate across attempts (128 slots in one 4 KiB page at
  stride 32); a failed attempt poisons a slot, a successful attempt does not.
- **W1 scratch.** A second all-zero region supplies the value W1 writes
  (`alias(scratch) + 0x100`). Byte 0 of that value must be 0 (`enforcing`) and
  bit 0 of the `initialized` byte must be 1. The derivation also needs the
  physical delta (`kernel_phys_load − kernel_phys_offset`) to be 64 KiB-aligned;
  if it is not, or the predicate fails, the scratch cannot be used. The
  `initialized` byte sits at offset 2 on 5.10/5.15/6.1 and offset 1 on
  6.6/6.12 (`+0x100` pins it). A region that cannot satisfy the rule is not
  offered as a self-contained plan.
- **Region safety policy.** `dump_skip.zeroes`, `bm_pmd` and `serial8250_ports`
  are always allowed. `s3c24xx_serial_ports` is conditional: without Samsung
  serial hardware it is dead code, but on a Samsung device the driver may be
  bound and the array may be live, so it is offered only when no safe plan
  exists, and it carries an amber label (red on a Samsung phone).
- **Plans.** The extractor lists every valid (anchor, scratch) combination. With
  a single safe plan the app takes it without asking; with several it lists them
  for the user; only when there is no safe page-free plan does it show the
  "page" row.
- **Fallback.** A profile with neither anchor nor scratch takes the page path as
  before. `tcp_zerocopy` is a page route by nature: its fake lock is a crafted
  object that a zero anchor cannot drive.

The run log names the mode: `page_free=1 reason=policy+scratch+anchor`, or
`page_free=0 reason=<first missing condition>`.

## 4. The extractor

The extractor decides which kernels can be covered. One parse produces
an **option superset** — every feasible route with its geometry, every named
anchor candidate with its page-free plan, and the common profile blocks. A
runnable profile is a *cut* of that document; no second derivation happens.

Inputs: `boot.img`, a raw arm64 `Image`, `payload.bin`, an OTA zip or an OTA
URL. The physical load address and offset come from the platform image:
`xbl_config.img` (or `uefi.img`) on Qualcomm, `vendor_boot.img` (and
`dtbo.img`) on MediaTek. Without a platform image both stay null and the native's
compiled default applies; `/proc/iomem` is never a source.

Per image, the derivation recovers kallsyms from the image itself, uses BTF when
the kernel carries it, and disassembles for the kernel family and route geometry.
Route verdicts, the anchor scan and the slab stride (measured on the device or
under QEMU) are part of the same derivation. Every value carries a source and
confidence record (`--explain` prints it).

### Verified kernels

"Device" means the full chain completed on that exact build; "QEMU" means the
ten `offset.*` values, the anchor and the stride were checked against the same
image running under QEMU.

| Kernel (`uname -r`) | Route(s) | Verified |
|---|---|---|
| `5.10.43-android12-9-gb8e472053352-ab8059253` | sigreturn | QEMU |
| `5.10.81-android12-9-00001-geba40aecb3b7-ab8534902` | sigreturn | QEMU |
| `5.10.81-android12-9-00001-g6cd504626bae-ab8485363` | sigreturn, select_stack (32-bit compat) | device |
| `5.10.101-android12-9-00001-gf4c0e37dbcde-ab8596533` | sigreturn | QEMU |
| `5.10.101-android12-9-00027-g1292f517889e-ab8602202` | sigreturn | QEMU |
| `5.10.101-android12-9-00005-ga829d48e78bd-ab9206161` | sigreturn | QEMU |
| `5.10.136-android12-9-00020-gc9f59ef34367-ab9585114` | select_stack | QEMU |
| `5.10.136-android12-9-00021-g821df8f5bd36-ab9585204` | select_stack | QEMU |
| `5.10.177-android12-9-00001-g219d8dfbba07-ab10551810` | select_stack | QEMU |
| `5.10.198-android12-9-00085-g226a9632f13d-ab11136126` | select_stack | QEMU (candidate profile) |
| `5.10.209-android12-9-00019-g4ea09a298bb4-ab12292661` | select_stack | device |
| `5.10.226-android12-9-00064-gea4a6f067d3f-ab12969919` | select_stack | device |
| `5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284` | select_stack, sigreturn | device + QEMU control |
| `5.10.236-android12-9-00003-gfb24cf99ad97-full-osize` | multicast_waiter | QEMU |
| `5.10.236-android12-9-00003-gfb24cf99ad97-full-none-os` | none feasible | QEMU |
| `5.10.236-android12-9-00003-gfb24cf99ad97-ksun-osize` | multicast_waiter | device (RAM boot) |
| `5.10.246-gki-g3e27bf130358` | multicast_waiter | QEMU exact; device attempts stopped at W1 — candidate |
| `5.15.194-android13-8-00019-gf4321180a397-ab15212794` | multicast_waiter | QEMU |
| `6.1.25-android14-11-g8744d1c0cf31-ab10888519` | select_stack, tcp_zerocopy | QEMU |
| `6.1.25-android14-11-g9f6af9a6c2cc-ab11205628` | select_stack, tcp_zerocopy | QEMU |
| `6.1.57-android14-11-g798323a4de21-ab11424362` | select_stack, tcp_zerocopy | QEMU |
| `6.1.75-android14-11-gd57efa708101-ab12102151` | select_stack, tcp_zerocopy | QEMU |
| `6.1.78-android14-11-gb6577b760481-ab12075023` | select_stack, tcp_zerocopy | QEMU |
| `6.1.99-android14-11-gd6f926cfde54-ab12786694` | select_stack, tcp_zerocopy | QEMU |
| `6.1.115-android14-11-gfaa9b1b32a11-ab13269000` | select_stack, tcp_zerocopy | QEMU |
| `6.1.118-android14-11-ga3b9c44908dd-ab13320413` | select_stack, tcp_zerocopy | QEMU |
| `6.1.118-android14-11-gca0ef6d17716-ab13624819` | select_stack, tcp_zerocopy | QEMU |
| `6.1.138-android14-11-g0c3d559bcd85-ab14529422` | select_stack, tcp_zerocopy | QEMU |
| `6.1.138-android14-11-g44bda9e8f6e9-ab13792638` | select_stack, tcp_zerocopy | device (duchamp) + QEMU |
| `6.1.138-android14-11-g51f8c580613d-ab13911623` | select_stack, tcp_zerocopy | QEMU |
| `6.6.30-android15-8-g6b55ce738535-4k` | select_stack | QEMU |
| `6.6.56-android15-8-g443415d527b9-ab13130172-4k` | select_stack | QEMU |
| `6.6.66-android15-8-g29d86c5fc9dd-abogki428889875-4k` | select_stack | device (CPH2723, single pass) |
| `6.6.77-android15-8-g4a507830d890-ab13636293-4k` | select_stack | QEMU |
| `6.6.89-android15-8-g096cdb6ecefc-ab14358676-4k` | select_stack | QEMU |
| `6.6.102-android15-8-g32d1c845cb64-abogki446052083-lotus-4k` | select_stack | QEMU |
| `6.12.23-android16-5-g16e473de48a3-abogki462654244-4k` | select_stack | QEMU (9/10; `security_hook_heads` absent) |
| `6.12.23-android16-5-g316453da9a9e-abogki441133159-4k` | select_stack | QEMU (9/10; same reason) |
| `6.12.23-android16-5-g5a0e85dd9db0-ab14499855-4k` | select_stack | device (parse + stride; no chain run yet) |
| `6.12.30-android16-5-g6e872b4863d6-ab13847919-4k` | select_stack | QEMU (9/10; same reason) |
| `6.12.38-android16-5-g3c4da6410bcb-ab13872285-4k` | select_stack | QEMU (9/10; same reason) |
| `6.12.69-android16-6-g014ca48a80ee-ab15889839-4k` | select_stack | patched; the extractor refuses, the anchor was checked by hand |

Notes:

- On 6.12 the `security_hook_heads` symbol is gone (per-hook lists replaced it),
  so nine of the ten offsets can be checked, and all nine match.
- The corpus also holds host-checked-only kernels (5.10.157, 5.10.189, 5.10.214
  and another 5.10.209 build). Their profiles generate and are self-consistent,
  but there is no runtime or device witness, so they are not listed above.
- The extractor's contract is checked in both languages: the native wire digest
  and the Kotlin document digest hold the same value, and changing either side
  fails its own test.

## 5. The profile model

- **Bundled profiles** are assets inside the APK, looked up by exact `uname -r`;
  for the kernel they cover they are the authoritative source.
- **External profiles** are chosen through the system file picker; once chosen
  they outrank the bundled profile, and a document that cannot be read is a
  clear error, never a silent fallback.
- **The measured store** keeps `mm_struct_sz` measured by the root phase; it is a
  read-only fact source and never a precedence layer. Merging it produces a new
  document, which must be exported and selected to take effect.
- The editor lives in memory; export is the only save. The native wire schema and
  the Kotlin document stay in step through one shared digest.

## 6. Measurement method

- One run per fresh boot: reboot, wait for `sys.boot_completed=1`, let the system
  settle, run, then confirm the boot id changed.
- The series are driven by `sigret-run-once.sh`: before each run it puts the app
  back into the `top-app` cpuset, and on devices that expose `core_ctl` it also
  keeps the profile's CPUs in the active mask. The numbers in the README tables
  were measured under exactly that setup.
- The verdict is the app's run record: `state=completed` (plus
  `native exited code=0` for a handoff run). Secondary: the route line
  (`calls=… success=… clean=1/1`) and any oops in the polled kernel log.
- Start refusals are not counted; retry on a fresh boot. When a new failure
  appears, stop and triage.
- Rates are reported with Wilson 95% confidence intervals, and the failure
  classes are listed alongside — never averaged away.
- Extractor verification is a separate line: QEMU boots each image, dumps
  `/proc/kallsyms` and `/proc/slabinfo`, compares the generated profile with the
  running kernel, and uses the device-verified 5.10.236 values as the control.

## 7. Building and testing

Toolchain: ONDK r30.1 (not Google's stock NDK), JDK 25, and the Android Rust
target.

```sh
make -C src ghostlock          # native payload, zero warnings
make -C src compat-helper      # static AArch32 helper (libghostlock32.so)
make -C src lint-tidy
make -C src native-host-tests
cargo test --release           # extractor
./gradlew --offline :app:assembleDebug
./gradlew --offline :app:testDebugUnitTest :profile-core:test
```

The APK packages `libghostlock.so`, the AArch32 `libghostlock32.so` and the
extractor `libextract.so`. Before a release the attack path is also checked with
`tools/cmp_disasm.py`; its known control failure (two `multicast_*` symbols
absent from both binaries) is expected, so read the per-target instruction
counts, not just the exit code.
