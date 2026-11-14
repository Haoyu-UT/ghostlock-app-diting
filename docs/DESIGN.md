# Design and measurements

> 中文: [DESIGN_ZH.md](DESIGN_ZH.md)

This is the technical companion to the [README](../README.md). It explains the
mechanism, the two pipelines (GhostLock and DirtyFrag), the route and carrier
list, the page-free design, how the extractor derives a profile, and how far
each kernel is verified. It does not cite internal evidence paths.

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

## 2. The second way: DirtyFrag

GhostLock is not the only pipeline. **DirtyFrag (CVE-2026-43284)** shares its first step — W1,
SELinux to permissive — and then writes **file page cache**, not kernel memory. An app can install
a transport-mode IPsec transform and splice a file page into the UDP send path through
`IpSecManager`/`IpSecService`; on an image without the ESP fix the kernel attaches the file page
to the skb and the payload becomes the file's page cache. The chain then injects a small stub into
`init`'s libc++/libbase sentry constructor, so init runs it with its own uid 0 and opens a root
daemon (module-free); KernelSU is optional. This is the second way for Samsung phones: KDP rejects
credential writes, but there is nothing to reject when the credential is init's own.

A profile carries an **ordered pipeline list** (`pipeline = [ "dirtyfrag", "ghostlock" ]`, highest
precedence first). The app resolves it before W1: the static verdict from the image, the ROM
preflight (libc++ hook and cave, policy/service), the stage-2 primitive probe (`libdfprobe`,
recorded in the measured DB) and the live state. The first viable entry runs; there is no fallback
after W1, and a KDP image carries `["dirtyfrag"]` only. Every DirtyFrag failure exit restores
SELinux enforcing. The send path decides feasibility: 5.10 `splice() → udp_sendpage() →
ip_append_page()`, 6.5+ `skb_splice_from_iter`; a 6.1 image without the latter copies the page,
so DirtyFrag is infeasible there.

## 3. Routes

A route is a delivery mechanism for the stamped waiter; a **carrier** is how that mechanism is
implemented for the image's ABI. The extractor decides both from the image.

| route | carrier | kernels served | delivery | page-free | notes |
|---|---|---|---|---|---|
| `select_stack` | 64-bit native | 5.10.136+, 6.1, 6.6, 6.12 | pselect / `_newselect` | yes | the default route; compact waiter on 5.10/6.1 |
| `select_stack` | 32-bit compat | 5.10.43 / 81 / 101; 6.1.138 | pselect via the AArch32 helper | yes | the 32-bit delivery of select_stack |
| `sigreturn` | 64-bit native | 5.10.43 / 81 / 101 | `rt_sigreturn` fpsimd restore | yes | covers kernels older than 5.10.136 |
| `tcp_zerocopy` | 64-bit native | 6.1 | setsockopt / UDP | no | page-based by nature; select is its declared fallback |
| `multicast_waiter` | 64-bit native | 5.15.194 (fuxi), a few 5.10 images | IP multicast | yes | the route those images run |
| `multicast_waiter` | 32-bit compat | 6.1.134, 6.1.138 | AArch32 `MCAST_BLOCK_SOURCE` | yes | 6.1 images whose 64-bit copy is too deep |

**Route verdicts.** The extractor reads each image's own instructions, decides which routes are
feasible and with which carrier, and reports the numbers behind the verdict. A route can be
offered twice — the native and the compat carrier — and one option is exactly two fields: the
route and its carrier (`64-bit native` / `32-bit compat`). The grade beside a row is the route's
mechanism hint, not a per-kernel or per-carrier prediction. When more than one route is feasible
the app asks; when only one is, it takes the image's primary carrier without asking.

**The carrier variants.**

- `sigreturn` delivers the stamp through the `rt_sigreturn` fpsimd restore. It is for kernels
  whose `do_futex` frame is too shallow for the pselect route to reach (the 5.10.43 / 81 / 101
  generation).
- **`select_stack` (32-bit compat)** covers the other half of that generation and, since r11, the
  6.1 images whose compat chain fits: the stale waiter strip sits *below* the 64-bit pselect
  buffer, so a statically linked AArch32 helper runs the race and parks in the compat
  `_newselect`, with the 64-bit native packing the bitmap. Every kernel address, the anchor
  allocator and the profile stay 64-bit. The helper refuses any geometry it cannot cover —
  5.10.236's 0x200 / 0x210 strips are the example; it fails safely there, so the 236 keeps the
  64-bit route. 6.1.138 is the first 6.1 device gate (4/4).
- **`multicast_waiter` (32-bit compat)** is the 6.1 delivery for images whose 64-bit
  `group_source_req` copy is too deep (on 6.1.138 the copy window ends 0x88 short of the lock
  slot): the AArch32 helper's `MCAST_BLOCK_SOURCE` branch copies the 32-bit structure into a
  local that lands on the waiter. It is device-gated on 6.1.138; the route's copy-to-lock window
  is intrinsically exposed (the dead-frame audit found no parked carrier), so its measured rate
  is the one quoted.

**multicast_waiter** is not a default route: the 5.15.194 (fuxi) and 6.1.134 (Realme) bundled
profiles are the images where the derivation leaves it as the route that runs; it is the only
route that works there, but its geometry does not fit the other images.

## 4. Page-free routes

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
- **Policy capabilities.** The W1 value is a kernel address, so its bytes 5–6 are
  `0xff`; those bytes are `policycap[3]` (`always_check_network`) and `[4]`
  (`cgroup_seclabel`). The store silently forces them on, and the network data
  path can be blocked until the policy is reloaded. The root script therefore
  reloads the policy immediately after root, before any KernelSU handoff; when
  the live policy is unreadable (a warm run with KernelSU already loaded returns
  `EINVAL`), the app shows **建议重启** and posts a notification — a reboot
  restores the bytes. The value-independent W1 write that would avoid the flip is
  planned, not shipped.
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

## 5. The extractor

The extractor decides which kernels can be covered. One parse produces
an **option superset** — every feasible route with its geometry and carrier
variants (`alternatives[]`), the pipeline verdicts (`pipelines[]`, the derived
order), every named anchor candidate with its page-free plan, and the common
profile blocks. A runnable profile is a *cut* of that document; no second
derivation happens.

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

The pipeline verdict decides whether DirtyFrag is feasible: the ESP fix level,
the splice send path (`udp_sendpage`/`ip_append_page` on 5.10,
`skb_splice_from_iter` on 6.5+) and the image's KDP fact. The app's pre-W1
resolver adds the ROM preflight (hook and cave) and the live probe.

### Verified kernels

"Device" means the full chain completed on that exact build; "QEMU" means the
ten `offset.*` values, the anchor and the stride were checked against the same
image running under QEMU. The authoritative per-kernel list, with each bundled
profile's route and verification level, is
[`kernel_profiles/BUNDLED_PROFILES.md`](kernel_profiles/BUNDLED_PROFILES.md);
the table below is the derivation corpus the design was validated on.

| Kernel (`uname -r`) | Route(s) | Verified |
|---|---|---|
| `5.10.43-android12-9-gb8e472053352-ab8059253` | sigreturn | QEMU |
| `5.10.66-android12-9-00001-g41ff3fa8fff9-ab8171928` | sigreturn | QEMU |
| `5.10.81-android12-9-00001-geba40aecb3b7-ab8534902` | sigreturn | QEMU |
| `5.10.81-android12-9-00001-g6cd504626bae-ab8485363` | sigreturn, select_stack (32-bit compat) | device |
| `5.10.101-android12-9-00001-gf4c0e37dbcde-ab8596533` | sigreturn | QEMU |
| `5.10.101-android12-9-00027-g1292f517889e-ab8602202` | sigreturn | QEMU |
| `5.10.101-android12-9-00005-ga829d48e78bd-ab9206161` | sigreturn | QEMU |
| `5.10.136-android12-9-00020-gc9f59ef34367-ab9585114` | select_stack | QEMU |
| `5.10.136-android12-9-00021-g821df8f5bd36-ab9585204` | select_stack | QEMU |
| `5.10.168-android12-9-00002-gf3c080171fd5-ab10346004` | select_stack | QEMU |
| `5.10.177-android12-9-00001-g219d8dfbba07-ab10551810` | select_stack | QEMU |
| `5.10.198-android12-9-00085-g226a9632f13d-ab11136126` | select_stack | QEMU (candidate profile) |
| `5.10.209-android12-9-00019-g4ea09a298bb4-ab12292661` | select_stack | device |
| `5.10.226-android12-9-00064-gea4a6f067d3f-ab12969919` | select_stack | device |
| `5.10.226-android12-9-00047-g4968e29b7f92-ab12786767` | select_stack | QEMU |
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
| `6.1.134-android14-11-o-gd252f36df142` | multicast_waiter (32-bit compat), sigreturn | reporter's device (image and profile match); the compat route is the derived fix, unit gate pending |
| `6.1.138-android14-11-g0c3d559bcd85-ab14529422` | select_stack, tcp_zerocopy | QEMU |
| `6.1.138-android14-11-g44bda9e8f6e9-ab13792638` | select_stack (native + 32-bit compat), tcp_zerocopy, multicast_waiter (32-bit compat), sigreturn | device (duchamp: native select 10/10, compat select 4/4, compat multicast 8/10) + QEMU |
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
| `6.12.23-android16-5-abA165MUBS6CYL1-4k` | select_stack + DirtyFrag pipeline | device (DirtyFrag second way, operator-confirmed) |
| `6.12.30-android16-5-g6e872b4863d6-ab13847919-4k` | select_stack | QEMU (9/10; same reason) |
| `6.12.38-android16-5-g3c4da6410bcb-ab13872285-4k` | select_stack | QEMU (9/10; same reason) |
| `6.12.69-android16-6-g014ca48a80ee-ab15889839-4k` | select_stack | patched; the extractor refuses, the anchor was checked by hand |

Notes:

- On 6.12 the `security_hook_heads` symbol is gone (per-hook lists replaced it),
  so nine of the ten offsets can be checked, and all nine match.
- The corpus also holds host-checked-only kernels (5.10.157, 5.10.189, 5.10.214
  and another 5.10.209 build). Their profiles generate and are self-consistent,
  but there is no runtime or device witness, so they are not listed above.
- The store holds 71 corpora; sixty of them ship as golden-derived bundled
  profiles. The seven hand-finished 6.1 profiles carry family evidence only
  (their Images are not in the store), and the four templates are reference
  documents that never match a device.
- The extractor's contract is checked in both languages: the native wire digest
  and the Kotlin document digest hold the same value, and changing either side
  fails its own test.

## 6. The profile model

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

## 7. Measurement method

- One run per fresh boot: reboot, wait for `sys.boot_completed=1`, let the system
  settle, run, then confirm the boot id changed.
- The canonical series pair is `series-run.sh` (one fresh boot per run) around
  `sigret-run-once.sh`: before the tap it puts the app back into the `top-app`
  cpuset, and on devices that expose `core_ctl` it also keeps the profile's CPUs
  in the active mask. The numbers in the README tables were measured under
  exactly that setup.
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

## 8. Building and testing

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
extractor `libextract.so`. The store corpus tests run only when
`GHOSTLOCK_IMAGE_DIR` points at `external/test-kernels`; without it they skip
silently. Before a release the attack path is also checked with
`tools/cmp_disasm.py`; its known control failure (two `multicast_*` symbols
absent from both binaries) is expected, so read the per-target instruction
counts, not just the exit code. The release itself is gated on
`tools/ship_golden_profiles.py --check` (60 bundled, 0 missing, 0 mismatched, 11
exempt at r11) plus a fresh-boot smoke on the final build.
