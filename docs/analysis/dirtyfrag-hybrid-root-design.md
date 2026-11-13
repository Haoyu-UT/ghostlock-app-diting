# DirtyFrag hybrid root — stage-3 design

**Level: L** (a new root route, attack-critical path, app/native contract, profile work).
**Status: for operator approval.** Decisions taken 2026-11-08: one root shell per trigger;
v1 includes the KernelSU late-load handoff; the A16 W1 profile is in scope.

Inputs: `dirtyfrag-samsung-second-route-plan.md` (the approved route),
`dirtyfrag-stage1-static-checks.md` (both targets pass the static gates), and the stage-2
page-cache proof on the diting (untrusted app, SELinux Enforcing, no root; own file and a
restored block of `/system/lib64/libc++.so`).

## 1. Goal

Root a Samsung KDP device (Galaxy A16, `6.12.23-android16-5-abA165MUBS6CYL1-4k`) without a
flashed kernel and without any credential write:

```
W1 only  (futex route: selinux_state.enforcing = 0, SELinux permissive)
  -> page-cache write into libc++'s sentry ctor (DirtyFrag / CVE-2026-43284)
  -> the stub runs in init (uid 0, tid 1) and hands the app a root shell
  -> the app runs its root script over the shell; v1 then attempts the KernelSU late-load
```

**Non-goals.** No `.ko` is required *for root*. Nothing persists past reboot. No kernel
credential or PI state is written on the KDP device.

## 2. Why the route needs no kernel code — and where a module does appear

- Root is a task carrying uid-0 credentials. The kernel already has the code to run it; the
  exploit only changes *state*: W1 writes the SELinux enforcing word, and on a non-KDP device
  W2 would point a task's `cred` at `init_cred`. No injected code, no module.
- KDP closes the credential *state* route: every LSM dispatch calls
  `security_integrity_current`, which rejects a cred that is not a legitimate one. The first way
  therefore hijacks the kernel's own usermode-helper work item; the second way, this design,
  never touches a cred at all — it makes **init** run a shell with init's own credentials.
- A kernel module appears only for **KernelSU**: KSU's su policy is a kernel driver, so a
  managed `su` requires loading its per-KMI module (`ksud late-load`). Root is what makes that
  load possible; the module is a second step, not a dependency of the root itself.
- **This is the app's existing handoff.** On the diting, GhostLock's root script already stages
  a late-load-capable `ksud` (ManagerScanner) and runs `ksud late-load` — the module is
  KernelSU's, loaded by the root the exploit produced. The second way reuses exactly this in
  phase F. "Module-free" describes the **root step** only: the kernel still has to accept the
  module, which is why the A16's module gates are a separate, non-fatal item (4.7).

## 3. Phases

| phase | runs where | what |
|---|---|---|
| A. setup + W1-only | native | the existing exploit setup, W1 and W1p; then **stop** (no cred_pin, W2, W3 or handoff) |
| B. patch | native (app UID) | read libc++, pick the hook/cave, write the stub blocks into the page cache through ESP-in-UDP |
| C. trigger | native (app UID) | double-fork an orphan; init reaps it, logs through libbase/libc++, and calls the patched ctor on tid 1 |
| D. handoff | init stub | bind `@<random>`, fork; child accepts one connection, `dup2`s it and execs `/system/bin/sh`; parent returns to init |
| E. confirm + restore | native | connect, send `id`, require `uid=0`, then write the original blocks back |
| F. root script + KSU | app over the shell | run the existing root script; attempt `ksud late-load`; report the handoff state |

## 4. Components

### 4.1 W1-only mode (native)

- New profile-level selector (e.g. `route.second_way = 1`, emitted for KDP profiles) or a
  `--w1-only` mode on the native. `run()` already returns after `has_umh()`; this adds the
  analogous early return after `w1<M>()` (plus the W1p repairs it performs).
- The app's two KDP refusals (`AndroidGhostlockRepository.kt` around the archive gate and
  `runExploit()`) change from "refuse" to "select the second way" when the profile carries the
  second-way flag; a KDP profile without it still refuses.
- Nothing else in the native changes: W2/W3, `cred_pin`, the victim handoff and the root-script
  frontend are skipped entirely.

### 4.2 The A16 profile (in scope)

**Derived 2026-11-08** from the official firmware (`boot.img` + `vendor_boot.img` + `dtbo.img`,
hashes in the private record) with the KDP-aware extractor build — the `document` line predates
`kdp`/`umh`, so the working-tree build is the one to use.

- `kernel_phys_load = 0x40000000` (vendor_boot header, MediaTek) and
  `kernel_phys_offset = 0x40000000` (vendor_boot DTB `/memory`).
- `route = select_stack` (feasible; `tcp_zerocopy` infeasible, multicast/sigreturn underived on
  non-5.10), `waiter_shift = 0`; `rt_mutex_size = 32`, waiter `pi_tree 0x28 / task 0x50 /
  lock 0x58 / wake_state 0x60`, compact = false.
- `task_struct` fields and `selinux_enforcing = 0x277E560`, `init_cred = 0x2512B08`,
  `init_task = 0x24FCF40` from BTF/kallsyms.
- **The image's cred layout is not the 6.x template's**: BTF says `usage` is 8 bytes and `uid`
  is at +8 (the template assumes 4/+4); `security` 128, caps 48, copy 136. The profile carries
  the BTF values — a derivation win, since any stage using the template's assumptions would be
  wrong on this device.
- `kdp = 1` (CONFIG_KDP). The raw derivation also carries the first way's `umh` block; the
  second-way profile **strips it** (`kdp = 1` alone), otherwise the native would take the helper
  stage. The second-way selector is implemented (`--w1-only` in the native).
- **No QEMU gate is possible for this image** (KDP is live before userspace and panics in
  `prepare_ro_creds` under QEMU), and there is no A16 unit in hand — the report's device belongs
  to its reporter. The profile remains image-derived until an A16 core gate.
- **Experimental bundle (2026-11-09, operator request).** The profile is bundled for the
  experimental Samsung build (not marked device-gated). It carries the A16 report's own
  device-run plan: `lock_anchor_image = 41364144` (`__dump_skip.zeroes +0x2772ab0`, 4096 B,
  stride 32, `page_free=true`), `w1_scratch.image = 41364480` (`+0x2772c00`, reserves anchor
  slots 18..19) and `kernelsnitch.mm_struct_sz = 1280`. The reporter's run used exactly this
  plan and W1 verified on attempt 1; the earlier derivation omitted the anchor, which would
  have silently fallen back to the page-based route. `security_hook_heads` stays 0;
  `mm_struct_sz` is the 6.12-family 1280, not a device `/proc/slabinfo` measurement.

### 4.3 The page-cache patch

- **Target selection.** Primary `libc++` sentry ctor
  (`_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_`); fallback `libbase`
  `_ZN7android4base10LogMessageD1Ev`. Choose by the cave the stub needs: on the A16 the tail
  caves are 640 B (libc++) and 1200 B (libbase); on the diting 2520 / 2256 B. The zero-run
  fallback does not exist on either ROM.
- **Stub budget — measured, not estimated.** A prototype assembly (uid/tid gate, abstract-socket
  bind, fork, accept, dup2/dup3, exec `/system/bin/sh`) assembles to **420 bytes**: 76 B data
  (sockaddr + paths), 336 B code, 8 B patch slots (original instruction + return branch), with
  **zero absolute relocations** — fully position-independent. It fits every measured cave: A16
  libc++ 640 B (220 B spare), A16 libbase 1200 B, diting libc++ 2520 B, diting libbase 2256 B. The
  A16 libc++ cave is therefore usable, not just the libbase fallback.
- **Blob layout** (DFRoot-compatible): `[data][code]`, a fixed `code_start` offset, the hooked
  site's original instruction saved in a fixed slot, and the return branch as the last word
  (`b hook+4`).
- **Hook.** At the ctor entry, skip a leading `BTI c`/`PACIASP`, and replace the next 4 bytes
  with a branch to `cave + code_start`. The hook and cave are written as 16-byte
  read-modify-write blocks; the rest of each block is preserved.
- **Writes.** One ESP-in-UDP packet per 16-byte block: `SPI|Seq|IV` + the block as ciphertext,
  `IV = AES_ECB_DEC(key, current_block) XOR desired_block`, AES-256-CBC transport transform via
  `IpSecManager`, sender bound to the transform's remote port, one `splice` per packet, sequence
  numbers increasing. Proven end-to-end on the diting.
- **Send-path capability (per image, mandatory).** The kernel must attach the spliced file page
  to the UDP skb; otherwise ESP decrypts a copy and nothing is written. Two paths qualify: the
  5.10-style `udp_sendpage → ip_append_page` (diting `5.10.236`) or `skb_splice_from_iter`
  (6.5+ and backports; the A16 `6.12.23` has it and `__ip_append_data` calls it). Kernels in
  between are a gap: the duchamp `6.1.138` build has `udp_sendpage` setting `MSG_SPLICE_PAGES`
  but **no `skb_splice_from_iter`**, so the datagram append copies — measured: the patch read-back
  showed the original bytes and no shell. The extractor must emit this fact and the app must
  refuse the second way without it (a failed run otherwise leaves SELinux permissive).
- **Order.** Cave blocks first, then the hook block (so the branch target is valid when the hook
  lands); restore in the reverse order.
- **Hazard (measured).** On both libc++ builds the exec segment ends where the RW segment's file
  data begins, so the cave is page-shared with the RW start. The window must stay short and the
  restore is mandatory; the stub is not resident (see 4.5), so the page can be restored.

### 4.4 The init stub

- Raw syscalls only (no libc, no locks): `getuid`, `gettid`, `socket`, `bind`, `listen`,
  `accept`, `dup3`, `clone`/`fork`, `execve`, `close`, `exit`.
- Flow: `getpid() != 1 || uid != 0` → execute the saved instruction and branch back. (Init's
  reap logging is not guaranteed to run on thread 1, so the gate is the **process**, not the
  tid; measured below.) Otherwise bind abstract socket `@<random 8 bytes>`; `EADDRINUSE` means
  this boot already handed off → return. `fork()`; the **parent** executes the saved instruction
  and branches back into the ctor; the **child** `listen`s, `accept`s one connection, `dup2`s it
  onto 0/1/2 and `execve`s `/system/bin/sh` with a minimal `PATH` environment.
- **One-shot per boot** by the abstract socket name; a new run uses a new random name.
- **No exec of app data.** The only exec is `/system/bin/sh`, a read-only system binary — so
  DEFEX's user-exec policy is not in the path at all, and the plan's bind-mount stage is not
  needed for the primary shape.
- **No resident shellcode.** After the child execs, no process executes the patched pages, which
  is what makes the restore safe.

### 4.5 Handoff and the root shell

- The app creates the transform (Kotlin `IpSecManager`, exactly the stage-2 probe's shape) and
  passes `encapPort`, `senderPort`, `SPI`, key, patch list and socket name to the native stage.
- After the patch, the native double-forks an orphan; init reaps it and logs (the stage-1 check:
  both inits link libbase/libc++ and import the sentry ctor, and their `sigchld_handler` reap
  path carries its log strings).
- The native connects to `@<name>` with retries (~5 s budget), sends `id`, and requires a
  `uid=0` answer. It then restores the original blocks and keeps the session.
- **Session lifetime:** until reboot, or until the app closes it. A dropped session costs one
  re-trigger (new socket name, ~seconds).
- If no connection arrives within the budget, restore anyway and fail the phase.

**Measured on the diting (2026-11-08).** The injected stub fires from init's orphan-reap
logging: within ~1 s of the trigger the abstract socket appears in `/proc/net/unix` (owner:
init), so the page-cache hook, the branch, the cave and the `getpid()==1 && uid==0` gate all
work. Under SELinux **Enforcing** the app's connect is denied (`Permission denied`), and a TCP
variant fails earlier (`avc: denied { create } ... scontext=u:r:init:s0 tclass=tcp_socket`), so
there is no non-SELinux channel and W1 is genuinely required. **With W1 applied (permissive):
both links succeed** — the shell answers `uid=0(root) … context=u:r:toolbox:s0` over AF_UNIX and
over TCP, and the page cache is restored afterwards (blocks verified byte-identical). The
stage-4 mechanism gate passes.

### 4.6 App integration

- Kotlin: a new second-way stage in the run flow (selected by the profile flag); the `IpSecManager`
  setup, orchestration, run-store records (`phase`, `w1`, `patch`, `shell`, `ksu`) and UI states.
- Native: a new stage in `libghostlock.so` (or a sibling binary the app runs the same way) that
  owns phases B, C and E. It runs with the app's UID; the transform is created by Kotlin, so the
  native only needs the ports/spi/key and the patch list.
- `ManagerScanner`'s ksud staging and the existing root script are reused for phase F; the shell
  replaces the exploit's root child as the script's execution context.

### 4.7 KernelSU late-load in v1

- Over the shell, run the app's root script (or the script's KSU section): find the staged
  `ksud`, then `ksud late-load`. KSU is what turns the temporary shell into managed root.
- **Stock KernelSU does not work on Samsung KDP devices — this is reported, not assumed.**
  Community reports and the patchset that fixes it (`KernelSU-v3.2.5-samsung-kdp-rkp-defex`)
  say the stock `kernelsu.ko` crashes with a synchronous external abort / EL2 panic because it
  writes KDP-protected cred refcounts directly (`ksu_mark_running_process_locked`), where Samsung
  requires `kdp_usecount_inc_not_zero()`/`kdp_usecount_dec_and_test()`; RKP rejects the
  syscall-table write, DEFEX keeps a separate credential tuple, and the late-load's own SELinux
  context prevents it from writing a fresh `ksud` under `/data/adb`. Working builds are
  Samsung-patched KSU forks (`diabl0w`'s KernelSU, which DFRoot also names for Samsung, and the
  `KernelSU_JingMatrix` KDP-API variant our A16 report cites), with `ksud` **and** the `.ko`
  built together for the exact firmware `uname -r`, and DEFEX handled by bind-mounting `ksud`
  over a whitelisted binary (e.g. `logcat`).
- **What the diting already taught about modules.** Its kernel has `CONFIG_MODVERSIONS` and a
  frozen 7,252-symbol KMI: a module built against anything but the exact build fails at load with
  `unknown symbol` or `disagrees about version of symbol <name>`, and the build work needed
  vermagic plus every CRC byte-identical before the release check would pass. A hand-built module
  is not a shortcut on a GKI device — do not assume "we have root, so insmod works".
- **KSU late-load is narrower than it looks.** It works where KSU ships a module built for the
  *standard* GKI KMI of that family — duchamp's plain 6.1 GKI is the positive case. That is
  evidence for KSU's per-KMI module, not for arbitrary modules, and it says nothing about a
  vendor kernel that diverges from the standard KMI.
- **Module gates on the A16** (from the image config): `CONFIG_MODULE_SIG=y`, `SIG_ALL=y`,
  `SIG_HASH=sha1`, but `MODULE_SIG_FORCE` **not set** and `MODULE_SIG_PROTECT` **not set**, so the
  module loader accepts an unsigned module (tainting the kernel); `CONFIG_MODULE_SCMVERSION=y`,
  `SECURITY_DEFEX=y` (USER, IMR_V2), `RKP=y`, `KDP=y` and `KNOX_NCM=y` are present, and the
  module must match the `6.12.23` KMI/vermagic. On a Samsung kernel that may diverge from the
  standard KMI, even KSU's per-KMI module is not guaranteed.
- **Reuse, don't compile.** The project never builds or signs a `.ko`. The step reuses a
  Samsung-patched KSU manager's own bundled `ksud`/module: the app's `ManagerScanner` already
  finds and stages a manager's `libksud.so`, and `ksud late-load` loads the module that build
  carries. What reuse requires is that the build match **this firmware's** vermagic/KMI — a
  module from another model or firmware fails the load, which is the gate the diting's own module
  attempts already demonstrated.
- **The A16 is a MediaTek Samsung build** (`SM-A165M`, MT6789 — the report's corrected identity,
  matching the extractor's MediaTek compressed image) and it is **not** in the reported tested
  model list. So no matching public Samsung-patched build is known; if none appears, reuse cannot
  satisfy the step, and compiling one against Samsung's 6.12.23 source with the KDP patchset is a
  separate, large effort — explicitly out of v1.
- **Therefore the KSU step is best-effort, and the design says so.** It must name a
  Samsung-patched KSU build (not upstream) whose `ksud` and `.ko` match this firmware; attempt
  the late-load over the shell, record the exact failure (KDP/RKP/DEFEX, KMI/CRC, SCM version),
  keep the shell, and report "root shell, no manager". The root shell is the guaranteed
  deliverable. The reported tested Samsung models are S24/S25/S26, A36/A56/A536E, Fold6 and
  Tab S10 FE — **the A16 (SM-A165M) is not among them**, so its KSU status is unproven even with
  the patched build.
- **Failure is non-fatal.** If the module is refused (SCM version, DEFEX/knox, KMI mismatch), the
  shell remains root; the app reports "root shell, no manager" and the run store records the
  reason. The KSU handoff is a second product layer, not a gate of the route.
- **Measured on the diting with a stock `boot_a` (2026-11-09).** With the preloaded KSU removed,
  the init shell's root script ran `ksud late-load` and the module loaded
  (`kernelsu … Live`, `su` works as `u:r:ksu:s0`), SELinux restored to enforcing, the page cache
  restored byte-identical. So the handoff works from an init-owned shell on a device with no
  preloaded manager; the Samsung-specific acceptance gates remain the open part (4.7's module
  gates), and the A16's MTK build is not in the community-tested list.

### 4.8 Restore, failure modes, recovery

- Restore is idempotent and runs on success, timeout and trigger failure. It writes the original
  blocks back (16-byte RMW, same primitive).
- A stub defect runs in init: the failure mode is a reboot. Everything the route changed is in
  page cache and RAM, so a reboot restores the device; the restore path is what keeps first-run
  success from becoming system-wide corruption for later mappings of libc++.
- The page-cache window is a few seconds. During it, a newly started process mapping libc++ could
  read the patched RW bytes; this is the same trade DFRoot makes and is why restore is not
  optional.

## 5. Security notes

- The abstract socket is root-equivalent for its lifetime. Its name is a per-run 64-bit random
  value never written to disk; the window is short; the shell dies at reboot.
- No files are created in world-writable locations; no persistent state; no module is required
  for the root step.
- If the KSU module loads, the kernel is tainted (unsigned module); that is a user-visible state
  and must be reported, not hidden.

## 6. Gates, in order — the Samsung KSU load is last

1. **Diting stage 4 (mechanism and product gate). Passed 2026-11-08/09.** The first pass proved
   the patch/stub/shell/restore with W1 emulated (`setenforce 0` via the rig's `su`). The second
   pass ran the product build end to end with **the real W1**: W1 via the shipped select route
   (`clean=1/1`) → plan → 28 blocks patched → init shell → the root script as `uid=0` → KSU
   already loaded → enforcing restored; `state=completed`, blocks restored byte-identical.
2. **Send-path capability (per image, mandatory).** The image must attach spliced pages to the
   UDP skb (`skb_splice_from_iter` or the 5.10 `ip_append_page` sendpage path). The diting and
   the A16 qualify; the **duchamp `6.1.138` does not** (measured: the patch read-back stayed
   original, ESP ran into a copy). The extractor fact and the app refusal are a follow-up; until
   they exist, the toggle must not be enabled on an unqualified device.
3. **A16 core (product gate).** The W1 profile on the device, the patch, the stub, the shell and
   the restore — **without** the KSU attempt. This is the gate that decides the route on the
   target.
4. **A16 KSU load (last).** Only after gate 3 passes: reuse a Samsung-patched KSU build matching
   this firmware if one exists, run `ksud late-load` over the shell, and record the exact
   failure if it is refused. Non-fatal by design: the shell from gate 3 remains the product.
5. **Regression surface.** The first way, the shipped profiles and the normal runs must be
   unaffected when the second-way flag is absent.

## 7. Risks

- **A16 profile is image-derived only** (no QEMU); W1 may need device-side adjustment.
- **Stub size**: settled by the 420-byte prototype (4.4); no longer a risk.
- **Send-path gap (measured 2026-11-09).** A kernel whose UDP append path copies spliced pages
  cannot host the route — the duchamp `6.1.138` (no `skb_splice_from_iter`) is the case. Without
  a per-image check the app would leave SELinux permissive and give no root. This gate is a
  prerequisite for shipping the toggle.
- **Trigger reliability**: the orphan-reap logging path fires on the diting and duchamp; the A16
  remains untested.
- **KSU module acceptance** on the A16: the stock module is reported to crash on Samsung (KDP
  cred refcounts, RKP syscall write, DEFEX tuple), so a Samsung-patched build is required. The
  QEMU gates (2026-11-09, §9) show the `samsung-v2.2` `android16-6.12` LKM loads and initializes
  on the A16's own 6.12.23 image with KDP forced off, including its KDP/RKP/DEFEX detection and
  DEFEX patch; live KDP remains the first device gate. Designed as non-fatal and sequenced last;
  the shell is the guarantee.
- **IpSec reachability under One UI** (the stage-2 proof is Xiaomi.eu; One UI SELinux may
  differ) — stage 5.

## 8. Relationship to the first way

- The first way (KDP-safe UMH stage) stays in the tree; it is paused, not removed.
- The app's KDP refusal becomes a mode selector: a KDP profile with the second-way flag runs
  this design; without it, the refusal remains.
- Neither way writes a credential on the KDP device.

## 9. Implementation status (2026-11-09)

- **Experimental build.** The A16 profile is bundled (`kdp` accepted by `ProfileResolver`; the
  bundle is 66 profiles) with the device run's page-free plan (anchor/scratch/mm_struct_sz,
  §4.2), and the generated root script retries `ksud late-load` through the `/system/bin/lmkd`
  bind mount when the direct root exec does not load the module. The script also carries a
  stale-mount sweep, an EXIT-trap unmount, `CAPS:`/`MOUNT-PROBE=` diagnostics, a `$LOG`
  fallback, a polled `dmesg` snapshot (`kmsg-live.txt`, 0.5 s, atomic + sync) and a
  `KSU-PHASE`/`KSU-SUMMARY` section with the `defex|kdp|rkp|kernelsu` dmesg tail. The debug dump
  runs before the enforcing restore (and before the late-load on the mount path), because the
  toolbox domain cannot write the app's data dir once SELinux is enforcing; the run folder
  therefore carries `kernel-info.txt`, `kernel-dmesg.log`, `iomem.txt`, `ksu.log` and
  `kmsg-live.txt` alongside the run log. The app's log export zips every top-level run-folder
  file except `meta`, so all of these travel; `pstore` is flattened to top-level
  `pstore-<name>` for the same reason (a previous boot's pstore lands in the next run's
  export), while the `pstore/` subdirectory stays for manual inspection. The page-cache restore
  now runs immediately after the init shell connects (`uid=0`), before the root script, and the
  stage carries `noshell`/`noscript`/`laterestore` diagnostic modes via a debug file. APK md5
  `6447e538…` (superseded by `6cda534d…` after the Samsung-manager scanner fix below); records
  `external/port/experimental-samsung-build-2026-11-09/` and
  `external/port/dirtyfrag-ab-2026-11-09/`.
- **The Samsung manager now passes the scanner (2026-11-09).** diabl0w's `samsung-v2.2`
  manager prints `ksud samsung-v2.2 (uapi: 5)` from `--version`; the scanner required
  `^ksud\s+\d`, marked it "not ksud", and the picker/pre-flight refused with "no suitable ksud".
  The `--version` identity check is **removed**: `scan()` now runs `late-load --help` for every
  ksud-like candidate and uses that interface as the gate (static-token fallback only when the
  probe cannot run). The picker on the diting now lists `KernelSU (me.weishu.kernelsu)`. Its
  late-load interface accepts `--kmi android16-6.12 --allow-shell` (the exact call the root
  script makes, default `--package-name me.weishu.kernelsu`). APK `6cda534d…`; record
  `external/port/ksu-samsung-manager-2026-11-09/`. App-side only: the fork's own `late-load` on
  the A16 remains the device gate.
- **The init shell can mount.** The diting's second-way shell reported
  `CapEff 000001ffffffffff` and `MOUNT-PROBE=ok`; the full smoke run completed
  (`RESULT=OK`, 28 blocks restored, Enforcing, no leftover mount). The instrumented smoke
  (runs `20261109-023700`, `024420` and, final, `025626`) wrote a 300-line `kmsg-live.txt`, the
  full dump set (`kernel-info.txt`, `kernel-dmesg.log`, `iomem.txt`, `ksu.log`) and
  `KSU-SUMMARY enforce=0 kernelsu=1 lmkd_mount=0` into the run folder, with no `.new` temp; the
  late-load `KSU-PHASE` markers await a boot where KernelSU is not already loaded. The retry
  branch itself was also not taken on that rig (KernelSU already loaded).
- **Samsung KSU QEMU gates.** `diabl0w/KernelSU` `samsung-v2.2` (`android16-6.12` LKM) loads
  first try on a plain 6.12.23 GKI and on the A16's own 6.12.23 image with `kdp_enable=false`
  and `is_boot_state_unlocked=1`: 235 symbols relocated from `/proc/kallsyms`, SCMVERSION
  accepts the untagged module, KernelSU 32687 initializes, and the module detects KDP/RKP/DEFEX
  and installs its `task_defex_enforce → defex_allow` branch. Record
  `external/port/ksu-samsung-qemu-2026-11-09/`. **Live KDP was not exercised** (it was forced
  off to boot QEMU); it is the first device gate, followed by live DEFEX safeplace and the
  DirtyFrag/stub chain (gate 3).
