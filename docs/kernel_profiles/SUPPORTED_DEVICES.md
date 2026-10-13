# Supported Devices

> 中文版本：[SUPPORTED_DEVICES_ZH.md](SUPPORTED_DEVICES_ZH.md)

> **This is the `diting` fork, and its list of supported kernels is shorter than
> [upstream](https://github.com/YuKongA/ghostlock-app/blob/main/docs/kernel_profiles/SUPPORTED_DEVICES.md)'s.**
> This fork breaks the built-in 5.15 and 6.1 profiles, so those rows are removed here and listed
> separately at the bottom. **Upstream is unaffected** — the defect is in the fork, not in
> GhostLock, and upstream supports those devices normally. Analysis and the planned fix:
> [`../analysis/waiter-layout-family-gating-plan.md`](../analysis/waiter-layout-family-gating-plan.md).

> MediaTek device not working (no matching profile, or `W1: target 0x0`)?
> Root the device first, then follow [MEDIATEK.md](MEDIATEK.md) to obtain the
> two physical addresses (`kernel_phys_load` / `kernel_phys_offset`).

Rows marked **Shizuku recommended** ship a profile with `recommend_shizuku = 1`.
The app automatically turns on the home-screen **Run via Shizuku** switch for
them at every start; you can switch it off for the current session, and while it
is off the app stops asking for Shizuku until the next start.

Shizuku runs the exploit as the shell user, which has no seccomp filter, so the
W3 seccomp bypass stage is skipped. To use it:

1. Start Shizuku (for example over ADB) and keep it running.
2. Tap the status card at the top of the app and grant access when prompted.

Rows without the marker don't turn the switch on automatically, but **you can
enable it manually on any device**. Running via Shizuku skips the W3 seccomp
bypass there as well, so it saves time even where it isn't required.

## Redmi K50 Ultra (this fork's port)

| Kernel                                                 | Devices                                                          |
|--------------------------------------------------------|------------------------------------------------------------------|
| `5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284`  | Redmi K50 Ultra (`diting`) — Global `OS2.0.206.0`–`OS3.0.6.0`; tested end to end |
| `5.10.226-android12-9-00064-gea4a6f067d3f-ab12969919`  | same device — Global `OS2.0.3.0`–`OS2.0.205.0`; tested end to end (2026-10-10) |
| `5.10.209-android12-9-00019-g4ea09a298bb4-ab12292661`  | same device — Global `OS1.0.11.0`, `OS1.0.12.0`, `OS2.0.1.0`, `OS2.0.2.0`; tested end to end (2026-10-10) |

Upstream has no 5.10 family — no built-in profile for it, and no 5.10 entry in the offset
extractor. In this fork the profiles ship as **built-in assets**
(`app/src/main/assets/kernel_profiles/<exact uname -r>.conf`, registered in `index.conf`), so a
device on one of those exact kernels needs no import — and a bundled profile is authoritative for
its release. The two newer builds were each verified by one full gate run plus a 3-run series
(`5.10.226` completed 1/3, `5.10.209` 2/3), so "tested end to end" means at least one full pass.

## Possibly supported — untested

None of these has been run. A profile matches on the **exact `uname -r`**, so a device is only
really supported if its build string matches the one above character for character — and the
profile also hard-codes two board-level values (`kernel_phys_load`, `kernel_phys_offset`) that
the kernel string does not describe.

| Retail name | Codename | SoC | vs. the tested device |
|---|---|---|---|
| Xiaomi 12S Ultra | `thor` | SM8475 | same SoC |
| Xiaomi 12 | `cupid` | SM8450 | different SoC |
| Redmi Note 13 Pro 5G | `garnet` | SM7435 | different SoC |
| POCO X6 5G | `garnet` | SM7435 | different SoC |
| POCO F5 | `marble` | SM7475 | different SoC |
| Redmi Pad Pro (Wi-Fi) | `dizi` | SM7435 | different SoC |
| Redmi Pad Pro 5G | `ruan` | SM7435 | different SoC |

Only the Xiaomi 12S Ultra is on the same SoC as the tested device. For the rest, **a dedicated
profile may be required**: a device on a different SoC is not expected to ship the same certified
kernel build — and with it, the struct offsets this profile carries.

## Inherited from upstream (unmodified)

| Kernel                                                 | Devices                                                          |
|--------------------------------------------------------|------------------------------------------------------------------|
| `6.1.25-android14-11-maybe-dirty`                      | MEIZU 21                                                         |
| `6.6.30-android15-8-g54dcbfbef792-ab12368803-4k`       | Red Magic Tablet 3 Pro                                           |
| `6.6.77-android15-8-g4a507830d890-ab13636293-4k`       | Xiaomi Civi 5 Pro, REDMI K90 / 4 Turbo, POCO F7                  |
| `6.6.77-android15-8-g63ce7556864c-ab13994517-4k`       | Xiaomi 15                                                        |
| `6.6.77-android15-8-gca30f3b4bef6-abogki440974771-4k`  | Xiaomi 15 Pro, REDMI K80 Pro / K80 Ultra                         |
| `6.6.89-android15-8-g096cdb6ecefc-ab14358676-4k`       | OPPO Pad 4 Pro                                                   |
| `6.6.89-android15-8-g0889fe95bb10-ab14402178-4k`       | POCO X8 Pro Max                                                  |
| `6.6.89-android15-8-g8e4be6b47e40-ab14134548-4k`       | POCO X8 Pro                                                      |
| `6.6.89-android15-8-g42db9ecb036b-ab14487600-4k`       | Honor Magic V5 (10.0.0.164)                                      |
| `6.6.89-android15-8-gb99b4586a3ee-ab13754593-4k`       | Honor Magic V5 (9.0.1.160)                                       |
| `6.6.89-android15-8-g5a0ffb447c1d-ab13771415-4k`       | Redmi 15C 4G / POCO C85 4G                                       |
| `6.6.89-android15-8-gf4dc45704e54-abogki446052083-4k`  | OnePlus 13                                                       |
| `6.6.92-android15-8-g3637f4904cf5-ab13944661-4k`       | Red Magic Tablet 3 Pro, Red Magic 10 Pro, Red Magic 11 Air       |
| `6.6.102-android15-8-gab8eb70a71b8-ab14350911-4k`      | Nothing Phone 3                                                  |
| `6.6.102-android15-8-gb01b41c2647c-ab15574720-4k`      | Xiaomi 17T                                                       |
| `6.6.102-android15-8-gfe76d1bc97fd-ab14689815-4k`      | Xiaomi 17T                                                       |
| `6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k`      | OPPO Find N5                                                     |
| `6.6.118-android15-8-g93e223c276e7-abogki500782043-4k` | OPPO Find X8 Ultra, OnePlus 13 / ACE 5 Pro                       |
| `6.6.118-android15-8-g608a629fedf7-ab15154340-4k`      | REDMI K90 Ultra                                                  |
| `6.6.118-android15-8-gbf8cd367de7a-ab15314822-4k`      | Motorola Razr 60 Ultra                                           |
| `6.6.118-android15-8-gc44b714366cc-abogki519650608-4k` | REDMI K80 Pro / Turbo 5 Max, POCO X8 Pro Max, Xiaomi Pad 7 Ultra |
| `6.6.118-android15-8-ge56cf6b09cca-ab15511674-4k`      | REDMI K90 Ultra, POCO F7, Redmi Note 13 5G                       |
| `6.6.118-android15-8-ge58033dc8ea6-abogki498046332-4k` | OPPO Pad 5, OnePlus Pad 2, OPPO Find X8s                         |
| `6.6.118-android15-8-gebdfad32d749-ab15099304-4k`      | OPPO Find X8 / Find X8 Pro                                       |
| `6.6.118-android15-8-g21be90ecfb5e-ab15480137-4k`      | Honor Magic V5 (10.0.0.105)                                      |
| `6.6.127-android15-8-gb947b5758b2a-ab15580855-4k`      | Motorola Edge 40                                                 |
| `6.12.23-android16-5-g16e473de48a3-abogki462654244-4k` | REDMI K90 Pro Max                                                |
| `6.12.23-android16-5-g75e9b1c7ae7c-abogki463945075-4k` | Xiaomi 17 / 17 Pro / 17 Pro Max / 17 Ultra                       |
| `6.12.23-android16-5-g82efd98459a2-ab14457512-4k`      | OPPO Find X9 / Find X9 Pro                                       |
| `6.12.23-android16-5-ga8f88ad96df3-ab13929693-4k`      | OnePlus 15                                                       |
| `6.12.23-android16-5-gb2a876903b49-ab14541642-4k`      | OnePlus 15                                                       |
| `6.12.23-android16-5-gf1bdb13583da-ab13761046-4k`      | Red Magic 11 Pro, Tablet 5 Pro                                   |
| `6.12.30-android16-5-g6e872b4863d6-ab13847919-4k`      | REDMI Note 15 4G, POCO M6 Pro 4G                                 |
| `6.12.30-android16-5-g1750f757fabe-ab13938768-4k`      | Lenovo Legion Tab Gen 5 (China)                                  |
| `6.12.38-android16-5-g1d46253471dd-ab15048002-4k`      | Motorola Razr Fold                                               |
| `6.12.38-android16-5-g3c4da6410bcb-ab13872285-4k`      | Xiaomi 13T                                                       |
| `6.12.38-android16-5-g665eafb62659-ab14778838-4k`      | NX809J / NX888J                                                  |
| `6.12.38-android16-5-g74ad46052215-ab14494108-4k`      | Lenovo Legion Y700 Wuji                                          |
| `6.12.38-android16-5-g844001fb8721-ab14552068-4k`      | OnePlus 15T                                                      |

## Delisted in this fork (24 kernels)

Removed from the table above because this fork's compact-waiter change leaves them building a
waiter with `prio = 0` (highest) on their kernels. **They work upstream**; they are listed here
so the removal is visible rather than silent:

| Family | Kernels | Devices affected |
|---|---|---|
| 5.15 | 5 | MEIZU 20 Pro · MEIZU 21 Note · Red Magic 8 Pro · Sony Xperia 1 V |
| 6.1 | 19 | POCO X6 Pro · Xiaomi 14 · REDMI K80 · Redmi Note 15 Pro+ · Lenovo Xiaoxin Pad Pro 12.7 · Lenovo Yoga Tab Plus · Infinix Note 50s 5G / GT 30 / GT 30 Pro · RedMagic 9(S) Pro · vivo T4 / IQOO 12 · Motorola Razr 50 Ultra · Motorola Edge 60 Fusion · Zenfone 11 Ultra · Google Pixel 9a / 9 Pro / 9 Pro Fold / Pixel 7 |

Note that this is a **documentation-level** delisting: the built-in profiles are still present in
`app/src/main/assets/kernel_profiles/` and still listed in `index.conf`, so the app will still
accept them. Re-listing is the expected outcome once
[`../analysis/waiter-layout-family-gating-plan.md`](../analysis/waiter-layout-family-gating-plan.md)
is implemented.
