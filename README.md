# GhostLock — `diting` port (Redmi K50 Ultra, 5.10.236)

> 中文: [README_ZH.md](README_ZH.md)

## Supported devices

| Kernel | Devices | Codename | Status |
|---|---|---|---|
| `5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284` | Redmi K50 Ultra · Xiaomi 12T Pro | `diting` | **tested end to end** — Global `OS2.0.206.0`–`OS3.0.6.0` |
| `5.10.226-android12-9-00064-gea4a6f067d3f-ab12969919` | Redmi K50 Ultra · Xiaomi 12T Pro | `diting` | **tested end to end** — Global `OS2.0.3.0`–`OS2.0.205.0` |
| `5.10.209-android12-9-00019-g4ea09a298bb4-ab12292661` | Redmi K50 Ultra · Xiaomi 12T Pro | `diting` | **tested end to end** — Global `OS1.0.11.0` · `OS1.0.12.0` · `OS2.0.1.0` · `OS2.0.2.0` |

The Redmi K50 Ultra is codename `diting` (SM8475 / Snapdragon 8+ Gen 1). **Xiaomi 12T Pro is the
same physical device** — one codename, three retail names (also sold as the Redmi K50 Extreme
Edition). It is not a second port.

Reported as possibly sharing the build, but **untested**:

| Retail name | Codename | SoC | vs. the tested device |
|---|---|---|---|
| Xiaomi 12S Ultra | `thor` | SM8475 | same SoC |
| Xiaomi 12 | `cupid` | SM8450 | different SoC |
| Redmi Note 13 Pro 5G | `garnet` | SM7435 | different SoC |
| POCO X6 5G | `garnet` | SM7435 | different SoC |
| POCO F5 | `marble` | SM7475 | different SoC |
| Redmi Pad Pro | `dizi` / `ruan` | SM7435 | different SoC |

None of these has been run. Only the Xiaomi 12S Ultra is on the same SoC as the tested device; for
the rest, **a dedicated profile may be required** — a device on a different SoC is not expected to
ship the same certified kernel build.

This fork also **removes 24 upstream kernels** from the supported list, because its
compact-waiter change breaks them. The full table, including which devices those 24 covered, is in
[`docs/kernel_profiles/SUPPORTED_DEVICES.md`](docs/kernel_profiles/SUPPORTED_DEVICES.md).

## About this fork

A fork of **[YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app)**. Upstream supports
5.15 / 6.1 / 6.6 / 6.12 — **5.10 is not among them**: there is no built-in profile for it, and no
5.10 family entry in the offset extractor. This fork adds one, plus the fixes that turning it on
required.

**For the app itself — usage, the offset extractor, the profile schema, the porting guide — read
[upstream's README](https://github.com/YuKongA/ghostlock-app#readme).** This page only covers what
the port changed and what it has been shown to do.

## Status

Verified end-to-end on a **stock, unpatched kernel** — no root beforehand, no instrumentation:

| stage | result |
|---|---|
| W1 — SELinux → permissive | works |
| W2 — child credential write (`child uid = 0` → `child is root!`) | works |
| W3 — seccomp filter bypass | works |
| Handoff — root script as `uid=0`, KernelSU loaded, SELinux back to enforcing | works, `native exited code=0` |

Repeat runs in one boot are stable as well: **8 consecutive runs completed, with no freeze and no
reboot**, after fixing the two causes that ended earlier series — anchor slots reused across
processes
([`anchor-slot-persistence-plan.md`](docs/analysis/anchor-slot-persistence-plan.md)) and
`init_cred` freed under the rooted children
([`init-cred-lifetime-plan.md`](docs/analysis/init-cred-lifetime-plan.md)).

Root is **temporary**. KernelSU is late-loaded from the exploit, so it is gone on reboot; the
bootloader is unlocked throughout. Relocking (which wipes data) is a separate, later step and has
not been done.

### KernelSU handoff

The chain completes and hands off either way; whether the **KernelSU module** ends up loaded depends
on a **late-load-capable `ksud`** being reachable. The app copies one out of an installed manager it
recognises — `me.weishu.kernelsu` (KernelSU), `me.weishu.kernelsu.pr` (KernelSU-Next),
`com.resukisu.resukisu` (ReSukiSU) or `com.kowx712.supermanager` — into its own files directory, and
the root script prefers that copy. The verified setup is **ReSukiSU** (`com.resukisu.resukisu`):

```
[ksu] [*] ksud=/data/user/0/com.ghostlock.app/files/ksud
[ksu] [+] KernelSU module loaded
[+] KernelSU ready
```

A manager outside that list — the earlier `com.sukisu.ultra`, for example — is not matched, and the
script falls through to `/data/adb/ksu/bin/ksud`, some builds of which have no `late-load`
subcommand, leaving the module unloaded. A late-load-capable `ksud` executable at
**`/data/local/tmp/ksud`** is also picked up; per KernelSU's LKM design, that binary carries its own
`kernelsu.ko`, so no separate module file is needed.

### Open regression — read this before using the fork on anything but a 5.10 device

**This fork breaks 24 of upstream's built-in profiles.** It is a defect in the fork, not in
GhostLock — upstream supports those devices normally, and nothing here affects it.

The change that makes the compact waiter work on 5.10 sits on a code path shared with every kernel
family, so the **19 built-in 6.1 profiles and 5 built-in 5.15 profiles** now build a waiter whose
priority is written to the wrong field. The families disagree on the waiter layout — 5.10 has
`int prio` at `0x40`, while 5.15 and 6.1 have `unsigned int wake_state` at `0x40` and `int prio` at
`0x44` — and the fork writes the 5.10 pair unconditionally.

6.6 and 6.12 are unaffected, as they don't use the compact waiter. The devices those 24 kernels
covered are listed in
[`docs/kernel_profiles/SUPPORTED_DEVICES.md`](docs/kernel_profiles/SUPPORTED_DEVICES.md), and the
analysis with the planned fix is in
[`docs/analysis/waiter-layout-family-gating-plan.md`](docs/analysis/waiter-layout-family-gating-plan.md).
**Do not build this fork for a 5.15 or 6.1 device until that is fixed.**

## What the port changed

The route is **`select_stack`** (the pselect path), with `waiter_shift = -2` and the 5.10
**compact** waiter — the 10-word
`{tree_entry, pi_tree_entry, task, lock, int prio, u64 deadline, ww_ctx}` shape, derived statically
from `boot.img` and confirmed live on the device with kprobes (the waiter and the `stack_fds`
buffer land on the same stack address, delta 0).

The chain on top of the profile:

| commit | change |
|---|---|
| `6c8b18a` | Disarm the ghost on 5.x kernels; line-buffer the run log |
| `c1b8569` | Keep the victim's protocol fds out of the select route's fd range |
| `765b137` | Snapshot and restore every fd the select route's `dup2` pass clobbers |
| `9acf2f1` | Perform zero writes through the erase's collateral (the 5.10 leaf layout) |
| `a703604` | Carry `lock_anchor_image` from the profile document through to the wire |
| `6e70e8c` | Port plans and analysis documents |
| `0f76309` | Make the anchor region's slots safe, batched and profile-sized |
| `75f64c1` | Report why the W2 verifier gave up |
| `30f0c14` | Keep `init_cred` alive for the boot (the cred pin) |
| `55f3413` | Derive the lock anchor's region from the kernel image (`--anchor-scan`) |
| `f08c49c` | Retry the cred pin and never fail a run for it |
| `81d0cdb` | **r3**: bundle the profile, police the applied layers, digest the wire, and let a fresh install reach its first run |

The last two fd fixes were the difference between "the write lands" and "the chain completes" —
before them the route's `dup2` pass silently destroyed long-lived descriptors, so the W2 victim saw
EOF one dance before its write landed.

`81d0cdb` is the r3 change set in one commit: the built-in profile and the layer rules that stop an
import or an old build's overrides from changing a run silently, the schema digest native refuses to
run without, the fix that lets a fresh install run at all, and the SELinux policy working copy that
no longer accumulates in app storage. The release notes are in the port repository; the device gate
that verified it is described in `PORT-PLAN.md` there.

## Reproducing

The diting profiles ship as **built-in assets**, so a device on one of those exact kernels needs no
import and no setup. Two layers used to outrank a built-in profile and no longer do: an imported document
is **not applied** while a bundled profile covers your kernel, and parameter overrides apply **only
when the installed build wrote them**. Both stay stored — the app raises a one-time *"Disabled by
this update"* notice saying what is off and why, keeps a banner on the profile screen, and re-saving
an override from Parameters re-enables it immediately. See `PORT-PLAN.md` Phase 8 in the project
notes for the full rule.

To port a *different* build, extract your own profile and then bundle or import it:

1. Extract on a host (`--iomem /dev/null` — the tool otherwise reads the *build host's*
   `/proc/iomem` and silently produces a plausible wrong `kernel_phys_load`):

   ```sh
   ghostlock-extract boot.img --iomem /dev/null --phys 0xa8000000 --format conf --out profile.conf
   ```

2. Either add it under `app/src/main/assets/kernel_profiles/` and register it in `index.conf` (then
   it is the authoritative layer for that kernel), or import it as a user document on a kernel that
   has no bundled profile.
3. Run. The phantom-process trimmer does **not** need to be disabled — that advice is obsolete:
   runs were measured to complete with it at its default, and it cannot be turned off before the
   first successful run anyway, since it needs root.

A profile is specific to one exact kernel build, so extract one for your own device as above rather
than reusing a file from here — the values differ per build, and a mismatch fails at W1.

## Layout

- [`docs/analysis/`](docs/analysis/) — design notes and analysis behind this port, including the
  regression described above.
- [`docs/kernel_profiles/`](docs/kernel_profiles/) — upstream's porting guide and profile schema,
  unchanged.

## Reporting a problem

Open an issue — <https://github.com/Haoyu-UT/ghostlock-app-diting/issues/new/choose>. The form asks for a
screenshot of **Settings → About phone → 全部参数与信息**, scrolled down: it carries your kernel version and
your ROM channel, which is where triage starts. Every run is kept on the device: tap **Export log & report** on the
main screen, pick the run, and save the zip wherever you like — that zip is what to attach.

Check `uname -r` first — **a different kernel is not a bug**, it is a device this port was never derived
for. See [Supported devices](#supported-devices).

## Credits & License

Fork of [YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app), Apache License 2.0 (see
[LICENSE](LICENSE)). Upstream in turn credits:

- [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia)
- [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus)
- [x-spy/CVE-2026-43499-popsicle](https://github.com/x-spy/CVE-2026-43499-popsicle)
