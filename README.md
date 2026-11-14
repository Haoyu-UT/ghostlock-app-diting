# GhostLock — broad kernel support, measured success

> 中文: [README_ZH.md](README_ZH.md)

Temporary root for Android kernels that have not yet patched CVE-2026-43499.

This repository is a fork of [YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app).
**This branch rebuilds the parts of the pipeline that decide whether a generated profile is
accurate and whether a run completes.**

## Supported routes and carriers

This fork supports the following route and carrier combinations.

| Route | Carrier | Page model | Notes |
|---|---|---|---|
| `select_stack` | 64-bit native | page-free | from upstream, made page-free |
| `tcp_zerocopy` | 64-bit native | page-based | from upstream |
| `multicast_waiter` | 64-bit native | page-free | from upstream, made page-free |
| `sigreturn` | 64-bit native | page-free | added by this fork |
| `select_stack` | 32-bit compat | page-free | added by this fork |
| `multicast_waiter` | 32-bit compat | page-free | added by this fork |

## Design principles

1. Support comes from a profile generator that reads the kernel image, not from a hand-maintained
   list of builds.
2. Built-in profiles do not define the support boundary. A kernel that is not listed can generate
   its own profile, and an upstream profile the maintainer has not personally tested is not removed
   for that reason.
3. A correct profile runs at the full success rate its route is capable of.

## Profile generation accuracy

Tested against 40+ kernels: every one produces an accurate profile, identical to the results seen on
the real device or in the emulator. The full list is in [`docs/DESIGN.md`](docs/DESIGN.md).

## Root success rate

Measured on real phones, one run per fresh boot. The tables were measured with the r11
release-candidate build and are split into two groups by how much a run depends on a page. When the
same phone, kernel and route appear on two rows, the two rows are the two carriers of that route.

**Fully page-free**

| Phone | Kernel | Route | Completed | Typical time | Measured |
|---|---|---|---|---|---|
| Redmi K50 Ultra (`diting`) | 5.10.236 | `select_stack` | 10/10 | 8.0–8.7 s | 2026-11-14 |
| Redmi K50 Ultra (`diting`) | 5.10.236 | `sigreturn` | 4/10<br>(6 runs rebooted mid-run) | 6.8 s | 2026-11-14 |
| Redmi K50 Ultra (`diting`) | 5.10.236<br>(custom build) | `multicast_waiter` | 9/10 | 38.7–39.9 s | 2026-11-14 |
| Redmi K50 Ultra (`diting`) | 5.10.81 | `select_stack`<br>(32-bit compat) | 10/10 | 7.9 s | 2026-11-14 |
| POCO X6 Pro 5G (`duchamp`) | 6.1.138 | `select_stack` | 10/10 | 16.2–18.2 s | 2026-11-14 |
| POCO X6 Pro 5G (`duchamp`) | 6.1.138 | `select_stack`<br>(32-bit compat) | 10/10 | 16.9 s | 2026-11-14 |
| POCO X6 Pro 5G (`duchamp`) | 6.1.138 | `multicast_waiter`<br>(32-bit compat) | 8/10 | 16.3 s | 2026-11-14 |
| OnePlus 13T | 6.6.66 | `select_stack` | 10/10 | 16.5–17.1 s | 2026-11-14 |
| Xiaomi K90 Pro Max (`myron`) | 6.12.23 | `select_stack` | 10/10 | 34.9–35.2 s | 2026-11-14 |

**Fully page-based**

| Phone | Kernel | Route | Completed | Typical time | Measured |
|---|---|---|---|---|---|
| POCO X6 Pro 5G (`duchamp`) | 6.1.138 | `tcp_zerocopy` | 8/10 | 30–36 s | 2026-11-14 |

*All numbers are from the r11 release-candidate build (2026-11-14 series, versionCode 745).*

## Prerequisites

> [!WARNING]
> **Do not try this on vivo/iQOO phones, or on any phone with built-in anti-root protection. The
> maintainer does not own such a phone, the attack flow has not been tuned for it, and there is a
> risk of bricking the device.**  
> **You use this app entirely at your own risk.**

- Android 12 or newer.
- The kernel and its security patch level are not yet patched for CVE-2026-43499.
- A KernelSU-family root manager is installed first: KernelSU, KernelSU-Next, BakaSU (formerly
  ReSukiSU), KowSU, or SukiSU Ultra. Each manager gained temporary-root support in a different
  version; use the newest one you can.

## Supported devices

Support is organized by **kernel family**, not by phone model or by a list of individual builds:

**5.10 · 5.15 · 6.1 · 6.6 · 6.12**

If your kernel belongs to one of those families and is not patched for CVE-2026-43499, the app can
generate a profile from your own image and try to run it. The built-in profiles are only the ones
that have passed independent verification; for a kernel that is not built in, you can generate a
profile yourself. The exact bundled list is in
[`docs/kernel_profiles/BUNDLED_PROFILES.md`](docs/kernel_profiles/BUNDLED_PROFILES.md).

Kernels outside these families have no derivation template and are currently out of scope.

## Quick start

1. Install the APK and open the app.
2. The home screen checks your kernel.
3. If it reads **Supported / Profile ready**, keep the app in the foreground and tap **Run**.
4. Wait for `KernelSU ready`. `su` works until the next reboot. If the app shows **Reboot
   recommended**, reboot the phone: the run changed SELinux policy capabilities that the post-root
   repair could not restore, and the network may not work until the reboot.

## Generating a profile

> [!WARNING]
> Some fields in a profile are measured on the phone itself. Do not generate a profile for any
> kernel other than the one the phone is running.

1. Note the exact OS build.
2. For a Qualcomm phone, get `boot.img`, `xbl_config.img` and `uefi.img` from the same OS build;
   for a MediaTek phone, get `boot.img`, `vendor_boot.img` and `dtbo.img`. Extract them from the
   full OTA's `payload.bin`, or from the fastboot package, and copy them to the phone's storage.
3. Open the app and tap **Generate profile** on the home screen:

   <img src="docs/images/profile-generation/en/01-home.png" width="520" alt="The generate-profile entry on the home screen">

4. Choose **Parse local image**, then pick `boot.img` (or `payload.bin`):

   | Source | Image type |
   |---|---|
   | <img src="docs/images/profile-generation/en/02-source.png" width="360" alt="Source selection"> | <img src="docs/images/profile-generation/en/03-image-type.png" width="360" alt="Image-type selection"> |

5. Attach the platform image the app asks for (skipping is not recommended — the physical address
   may be wrong):
   - Qualcomm: `xbl_config.img`; if the physical load is still missing, `uefi.img`.
   - MediaTek: `vendor_boot.img`; if the offset is still missing, `dtbo.img`.

   <img src="docs/images/profile-generation/en/04-physical.png" width="420" alt="The xbl_config prompt on a Qualcomm phone">

6. If the app asks **Multiple routes are available — choose one**, pick from the row descriptions.
   A route that also has a 32-bit layout appears twice, tagged `64-bit` and `32-bit compat`. The
   grade on the right is about the route and that choice, not about your kernel; it reads **not
   measured** when there is no evidence:

   <img src="docs/images/profile-generation/en/05-route.png" width="420" alt="Route selection">

7. If the app asks for a page-free plan, choose from the row descriptions. Each row states where
   the lock and the value come from; the dangerous Samsung serial-port area is labelled separately:

   <img src="docs/images/profile-generation/en/06-plan.png" width="420" alt="Page-free anchor space selection">

8. If **Slab stride** appears, pick a value marked **Confirmed** or **Consistent**, or skip it and
   merge the measurement from the home screen later.

9. **Export** the profile, then select it. A generated profile that is not exported is lost when
   you leave the screen.

## If a run fails

- **Reboot and retry.** A fresh boot is the strongest single lever; one attempt per boot.
- **If the app says Reboot recommended, reboot.** The run changed the SELinux policy capabilities
  and the post-root repair did not restore them; the network may be blocked until the reboot.
- **Check the plan, route and 64/32-bit choice** if the app offered one; each option can produce a
  different success rate.
- **Export the log** and attach it to the issue, together with the profile-generation log and the
  attack-run log.

## Why the success rate is higher

An exploit has many steps, and a mistake in any one of them lowers the success rate of the whole
chain. This branch optimizes the following steps:

1. **The main routes no longer depend on a sprayed page.** The old route leaked a page, freed it,
   reclaimed it with controlled contents, and hoped the allocator returned the same page; a page
   reclaimed elsewhere could take the phone down. The lock used for the write now sits in a fixed,
   all-zero region of the kernel. (`tcp_zerocopy` is the exception: its lock is a crafted object
   and stays page-based by construction.)
2. **Profiles are generated from measurable facts.** The app fills a profile from facts where it
   has them and falls back to heuristics only where it has none. A profile that was a few bytes off
   used to fail in the middle of the chain; that class of failure is gone.
3. **Older 5.10 kernels get a route that fits.** Two extra routes cover kernels the default route
   cannot reach: one for older 5.10 layouts, and a 32-bit helper for 5.10.43 / 5.10.81 / 5.10.101,
   whose stack layouts are outside the 64-bit route's reach. The same helper is now also offered
   where both layouts fit (for example a second `select_stack` choice on 6.1.138); the shipped
   profile follows the measured route order.
4. **A failed attempt cleans up after itself.** Kernel state left behind by one attempt used to
   spoil the next. The app disarms after every attempt and retries the early stages, so one miss
   does not end the run.
5. **A stage that cannot finish stops.** A walk that would never end used to leave the app waiting
   indefinitely. A stage that cannot complete now stops and reports where it stopped.
6. **The log says what happened.** The app logs with as little delay as it can and can export the
   log.

## Acknowledgements

This repository is a fork of [YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app),
Apache License 2.0. Upstream in turn credits:

- [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia)
- [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus)
- [x-spy/CVE-2026-43499-popsicle](https://github.com/x-spy/CVE-2026-43499-popsicle)

The app also uses [miuix](https://github.com/compose-miuix-ui/miuix),
[Shizuku](https://github.com/RikkaApps/Shizuku),
[Typesafe Config](https://github.com/lightbend/config) and Apache Commons Compress. The diting 5.10
offsets were initially based on the OPPO Reno10 Pro+ (CPH2521).

## License

Apache License 2.0 — see [LICENSE](LICENSE). Root is temporary and probabilistic. The built-in
profiles are based on real-device or emulator verification; the actual run result is what counts.
You use this software entirely at your own risk.
