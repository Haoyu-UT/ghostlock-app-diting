# The DirtyFrag second route for the Samsung KDP exploit

**Status:** operator decision 2026-11-08 — this is the **second way** to root a Samsung KDP
device. Design only; no implementation yet. The first way (the KDP-safe UMH stage) stays in the
tree and is paused, not removed.

**Stage 1 passed 2026-11-08.** The static checks on the diting `5.10.236` and the A16 `6.12.23`
images and their ROM libraries all pass: both kernels lack the ESP shared-frag guard, both configs
are built in, the splice send path exists on both, and both libc++/libbase hook targets exist with
a usable tail-page cave (the A16 libc++ margin is thin). Details:
[dirtyfrag-stage1-static-checks.md](dirtyfrag-stage1-static-checks.md).

**Stage 2 passed 2026-11-08.** A minimal probe app (`IpSecManager` transport mode + UDP
encapsulation, a JNI `splice` sender — no product change) wrote a 16-byte block of its own file,
and of `/system/lib64/libc++.so` at a non-mapped offset (restored afterwards), through the ESP
in-place decrypt, and read each back. It ran as an ordinary untrusted app with SELinux
**Enforcing** and no root. The page-cache primitive is proven on the rig; the next step is the
hybrid design (stage 3), which is L-level and needs operator approval.

## 1. Why a second way exists

KDP blocks the credential route: every LSM dispatch checks the task's `cred` against the
RKP-protected objects, so W2 (`child cred = init_cred`) panics, and the first way's only KDP-legal
ending is the kernel's own usermode helper (`_exec_work`). That path needs one arbitrary
text-pointer store, which the futex write cannot provide safely: the write's value is published
as PI-tree state, and a page-resident value freezes the walk (2026-11-08 device evidence).

The second way avoids that class entirely. It does not write kernel state to escalate; it writes
**file page cache**, gets the kernel's own init (uid 0, tid 1) to run a small stub, and starts a
root daemon from init's legitimate credentials. KDP has nothing to reject: the credential is the
real init credential, not a forged one.

## 2. The primitive

CVE-2026-43284 ("DirtyFrag"): the kernel's ESP/AES-CBC input path decrypts in place into pages
that were spliced from a file. By choosing the IV
(`IV = AES_ECB_DEC(key, current_block) XOR desired_block`) an app can overwrite any 16-byte block
of any file it can open — read-only system libraries included, without write permission and
without copy-on-write.

Properties that matter here:

- No KASLR slide, no heap leak, no per-image kernel offsets.
- The write is to a *file page*, not kernel memory; it cannot replace a kernel write.
- `CONFIG_INET_ESP=y` is built in on the diting; the ESP leg is reachable from an untrusted app
  through `IpSecManager` transport mode (the `CAP_NET_ADMIN`/`enforceTunnelFeatureAndPermissions`
  check is tunnel-mode only). The RxRPC leg is out (`CONFIG_AF_RXRPC` unset).

## 3. The chain, and the module-free hybrid

Reference implementation: DFRoot (GPL-2.0, source only; build locally). Its chain:

1. patch `crash_dump64` with `splicehelper` (the `crash_dump` domain may open vendor files the
   app cannot),
2. use the CBC primitive to write a per-KMI `dfroot.ko` into a vendor file,
3. patch `libc++.so`'s `std::ostream::sentry` with a code cave; init runs it while reaping an
   orphan (uid 0, tid 1); the stub switches to `u:r:vendor_modprobe:s0` and `insmod`s the module,
4. the module sets `selinux_state=false`, bypasses DEFEX where needed, and calls
   `call_usermodehelper` to start the SU daemon.

**The preferred shape here is the module-free hybrid:**

```
W1 (futex write: SELinux permissive)        [already proven on the diting]
  -> page-cache injection into libc++        [the new primitive]
  -> init (legitimate uid 0 credentials) runs the stub
  -> the stub starts a small root daemon (socket), no .ko
```

- **SELinux:** W1 is a plain data write to `selinux_state`; KDP does not guard it. The module's
  `selinux_state=false` is therefore unnecessary.
- **Execution:** init already has the root credential KDP trusts; running our code in init does
  not forge anything. The stub forks the daemon and returns init to its work.
- **The `.ko` is optional by design:** it exists in DFRoot only to do the jobs DFRoot has no
  kernel write for. With W1 those jobs are already done. The remaining kernel-side job is
  Samsung's DEFEX / vendor hooks; the preferred first attempt is the userspace bind-mount over a
  whitelisted system binary in a private mount namespace (the Samsung precedent), with a small
  module only if that fails.
- **KernelSU is optional:** a self-contained `su`-over-socket daemon gives temporary root without
  a manager. `ksud late-load` would itself load a `.ko`, so it is a later convenience, not a
  requirement.

The standalone DFRoot shape (its module, no W1) remains the fallback if DEFEX/vendor hooks cannot
be defeated in userspace on the target.

## 4. Gates, in order

1. **Vulnerability present.** The ESP fix must postdate the target image and no vendor backport:
   check the diting's `5.10.236` Image and the Samsung A16's `6.12.23` Image against the fix, not
   only the version. An accidental mitigation on 6.x is a known outcome.
2. **App reachability.** `IpSecManager` transport mode + UDP-encapsulation socket from the app,
   under the target ROM's SELinux (Xiaomi.eu Android 15 for the diting; One UI Android 16 for
   the A16).
3. **The bridge.** `crash_dump64`/`splicehelper` reachable from the app, and the target's
   `libc++.so`/`libbase.so` exports the hook symbol with a usable code cave.
4. **SELinux.** W1 makes the system permissive before the init stub runs.
5. **DEFEX / vendor hooks (Samsung).** Userspace bind-mount first; a per-KMI module only if
   needed, with its KMI/vermagic/signing checked against the target.
6. **The daemon.** A small root socket daemon started by the stub; the app connects; no manager
   required.

## 5. Stages

0. **Docs and source study** — file the DFRoot source study; correct the old DirtyFrag rejection
   in `CLAUDE.md` and the write-primitive survey (the ESP transport path does not need
   `CAP_NET_ADMIN`; the RxRPC leg is still out).
1. **Static checks** — on the diting and A16 images: the ESP fix level, `CONFIG_INET_ESP`, the
   `libc++.so`/`libbase.so` hook symbol and code cave, and (only if the module fallback is needed)
   the KMI/vermagic. **Done 2026-11-08** — both targets pass; see
   [dirtyfrag-stage1-static-checks.md](dirtyfrag-stage1-static-checks.md). The module's KMI is
   not checked (module-free shape).
2. **Non-escalating page-cache proof on the diting** — write and read back a harmless block in a
   world-readable file, no root, no daemon. This is the decisive cheap test. **Done 2026-11-08** —
   PASS on an app file and on a restored block of `/system/lib64/libc++.so`, as an untrusted app
   with SELinux enforcing, no root.
3. **The hybrid design** — W1 + the init stub + the root daemon; L-level, operator approval, own
   doc. Only after 2 passes. **Written 2026-11-08** — `dirtyfrag-hybrid-root-design.md` (one root
   shell per trigger, KSU late-load in v1, A16 profile in scope); awaiting operator approval.
4. **Diting device proof** — the full module-free hybrid on the diting (non-KDP, no DEFEX): the
   mechanism gate.
5. **Samsung device gate** — the A16 needs a unit: ESP path, init hook, DEFEX bind-mount, daemon.

## 6. Risks

- **The vulnerability may be patched** on the target (backport or accidental mitigation); the
  static check decides before any code.
- **Page-cache writes modify system files.** DFRoot manages a read-only partition and a soft
  reboot; the plan must state what is modified, whether it persists across reboot, and how to
  restore it without flashing. Any persistent system change is an operator decision.
- **The init hook is timing- and layout-dependent** (the orphan-reap path, the library symbol,
  the cave size); a ROM/library update can break it.
- **DEFEX/vendor hooks are Samsung-only unknowns**; the userspace bind-mount is the first
  attempt, a module the fallback.
- **Trust.** DFRoot ships prebuilt module blobs and a prebuilt `splicehelper`; use the source
  (GPL-2.0), build locally, and never run prebuilt exploit binaries. No flashing is involved.

## 7. Relation to the first way

- The first way's shipped value stays: KDP detection plus fail-closed refusal (a Samsung user is
  never sent into the reboot loop), and the KDP-safe UMH mechanism (QEMU-proven). The carrier
  work is paused; the 2026-11-08 device discovery (the fake device's `list.prev` must be zero at
  insertion, and the target's own prev word is the next open issue) is recorded for any future
  resumption.
- The second way, if stage 2 passes, replaces the *root step*; it does not replace the detection
  and refusal or the profile work.
- Neither way writes a credential; both end in the kernel's own legitimate root (init or a
  kernel helper).
