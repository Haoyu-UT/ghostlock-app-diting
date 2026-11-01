# Bundled profiles

> 中文版本：[BUNDLED_PROFILES_ZH.md](BUNDLED_PROFILES_ZH.md)

The APK ships **43 kernel profiles** plus four family templates. A profile is matched by the exact
`uname -r` and nothing else; a kernel that is not on this list can still generate its own profile
(see the README's *Generating a profile*). The authoritative list is
`app/src/main/assets/kernel_profiles/index.conf`; this page is its readable form.

Current mix: 34 page-free, 2 half-page, 7 page-based.

- **Route** — what the bundled profile runs.
- **Page-free** — *page-free*: the lock and the W1 value both come from anchor areas; *half*: the
  lock comes from an anchor, the W1 value from a sprayed page; *page*: `tcp_zerocopy`, page-based by
  construction.
- **Verified** — *device*: the full chain completed on that exact build; *QEMU*: the ten
  `offset.*`, the anchor and the stride were checked against the same image running under QEMU.

| Kernel (`uname -r`) | Route | Page-free | Verified | Devices |
|---|---|---|---|---|
| `5.10.81-android12-9-00001-g6cd504626bae-ab8485363` | select_stack | page-free | device | Redmi K50 Ultra (`diting`) — Global `V13.0.3.0` / `V13.0.4.0` (the launch ROM, Android 12) |
| `5.10.101-android12-9-00005-ga829d48e78bd-ab9206161` | select_stack | page-free | QEMU (candidate) | Redmi K50 Ultra (`diting`) — Global `V14.0.1.0` |
| `5.10.136-android12-9-00021-g821df8f5bd36-ab9585204` | select_stack | page-free | QEMU (candidate) | Redmi K50 Ultra (`diting`) — Global `V14.0.3.0` |
| `5.10.177-android12-9-00001-g219d8dfbba07-ab10551810` | select_stack | page-free | QEMU (candidate) | Redmi K50 Ultra (`diting`) — Global `V14.0.5.0` |
| `5.10.198-android12-9-00085-g226a9632f13d-ab11136126` | select_stack | page-free | QEMU (candidate) | Redmi K50 Ultra (`diting`) — Global `OS1.0.5.0` |
| `5.10.209-android12-9-00019-g4ea09a298bb4-ab12292661` | select_stack | page-free | device | Redmi K50 Ultra (`diting`) — Global `OS1.0.11.0`, `OS1.0.12.0`, `OS2.0.1.0`, `OS2.0.2.0` |
| `5.10.226-android12-9-00064-gea4a6f067d3f-ab12969919` | select_stack | page-free | device | Redmi K50 Ultra (`diting`) — Global `OS2.0.3.0`–`OS2.0.205.0` |
| `5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284` | select_stack | page-free | device + QEMU control | Redmi K50 Ultra (`diting`) — Global `OS2.0.206.0`–`OS3.0.6.0` |
| `6.1.115-android14-11-ga2521ca27699-ab13294383` | select_stack | page-free | QEMU | POCO X6 Pro |
| `6.1.118-android14-11-ga3b9c44908dd-ab13320413` | select_stack | page-free | QEMU | Redmi Note 15 Pro+ |
| `6.1.118-android14-11-gca0ef6d17716-ab13624819` | select_stack | page-free | QEMU | Xiaomi 14 |
| `6.1.138-android14-11-g0c3d559bcd85-ab14529422` | select_stack | page-free | QEMU | Xiaomi 14 |
| `6.1.138-android14-11-g151cf2b6bfbe-ab13719792` | tcp_zerocopy | page | unverified | Lenovo Xiaoxin Pad Pro 12.7 (TB375FC) |
| `6.1.138-android14-11-g2ecae636cf9b-ab14676408` | tcp_zerocopy | page | unverified | Lenovo Yoga Tab Plus (TB520FU) |
| `6.1.138-android14-11-g44bda9e8f6e9-ab13792638` | select_stack | page-free | device (duchamp) + QEMU | POCO X6 Pro |
| `6.1.138-android14-11-g6ab8c9a86a33-ab14396278` | select_stack | page-free | QEMU | POCO X6 Pro |
| `6.1.138-android14-11-g965475777129-mi` | select_stack | page-free | QEMU | REDMI K80 |
| `6.1.145-android14-11-g09f1c0074ad7-ab14226177` | tcp_zerocopy | page | unverified | Infinix Note 50s 5G, Infinix GT 30 (X6876) |
| `6.1.145-android14-11-g11c274d0441f-ab14259673` | select_stack | page-free | QEMU | RedMagic 9(S) Pro (REDMAGICOS11.0.5MR1_GB) |
| `6.1.145-android14-11-g74d1702dab4d-ab14669069` | tcp_zerocopy | page | unverified | vivo T4, IQOO 12 |
| `6.1.145-android14-11-g9b69cc399ae1-ab14819715` | tcp_zerocopy | page | unverified | Motorola Edge 60 Fusion |
| `6.1.145-android14-11-geaa643a2c0ee-ab14763719` | tcp_zerocopy | page | unverified | Motorola Razr 50 Ultra / Razr+ 2024 |
| `6.1.157-android14-11-ga8b0b542991e-ab15601211` | tcp_zerocopy | page | unverified | Infinix GT 30 Pro (X6873) |
| `6.1.157-android14-11-gbd23337e42e7-ab14791245` | select_stack | half | QEMU | Google Pixel 9a (Tensor G4), Google Pixel 7 (Tensor G2) |
| `6.1.162-android14-11-gce140c0e5bf5-ab15450923` | select_stack | page-free | QEMU | Zenfone 11 Ultra |
| `6.6.77-android15-8-g4a507830d890-ab13636293-4k` | select_stack | page-free | QEMU | Xiaomi Civi 5 Pro, REDMI K90 / 4 Turbo, POCO F7 |
| `6.6.77-android15-8-g63ce7556864c-ab13994517-4k` | select_stack | page-free | QEMU | Xiaomi 15 |
| `6.6.77-android15-8-gca30f3b4bef6-abogki440974771-4k` | select_stack | page-free | QEMU | Xiaomi 15 Pro, REDMI K80 Pro / K80 Ultra |
| `6.6.89-android15-8-g0889fe95bb10-ab14402178-4k` | select_stack | page-free | QEMU | POCO X8 Pro Max |
| `6.6.89-android15-8-g096cdb6ecefc-ab14358676-4k` | select_stack | page-free | QEMU | OPPO Pad 4 Pro |
| `6.6.89-android15-8-g5a0ffb447c1d-ab13771415-4k` | select_stack | page-free | QEMU | Redmi 15C 4G / POCO C85 4G |
| `6.6.89-android15-8-g8e4be6b47e40-ab14134548-4k` | select_stack | page-free | QEMU | POCO X8 Pro |
| `6.6.92-android15-8-g3637f4904cf5-ab13944661-4k` | select_stack | page-free | QEMU | Red Magic Tablet 3 Pro, Red Magic 10 Pro, Red Magic 11 Air |
| `6.6.102-android15-8-gab8eb70a71b8-ab14350911-4k` | select_stack | half | QEMU | Nothing Phone 3 |
| `6.6.102-android15-8-gb01b41c2647c-ab15574720-4k` | select_stack | page-free | QEMU | Xiaomi 17T |
| `6.6.102-android15-8-gfe76d1bc97fd-ab14689815-4k` | select_stack | page-free | QEMU | Xiaomi 17T |
| `6.6.118-android15-8-gc44b714366cc-abogki519650608-4k` | select_stack | page-free | QEMU | REDMI K80 Pro / Turbo 5 Max, POCO X8 Pro Max, Xiaomi Pad 7 Ultra |
| `6.6.118-android15-8-ge56cf6b09cca-ab15511674-4k` | select_stack | page-free | QEMU | REDMI K90 Ultra, POCO F7, Redmi Note 13 5G |
| `6.12.23-android16-5-g16e473de48a3-abogki462654244-4k` | select_stack | page-free | QEMU (9/10) | REDMI K90 Pro Max |
| `6.12.23-android16-5-g75e9b1c7ae7c-abogki463945075-4k` | select_stack | page-free | QEMU | Xiaomi 17 / 17 Pro / 17 Pro Max / 17 Ultra |
| `6.12.23-android16-5-gf1bdb13583da-ab13761046-4k` | select_stack | page-free | QEMU | Red Magic 11 Pro, Tablet 5 Pro |
| `6.12.30-android16-5-g6e872b4863d6-ab13847919-4k` | select_stack | page-free | QEMU (9/10) | REDMI Note 15 4G, POCO M6 Pro 4G |
| `6.12.38-android16-5-g3c4da6410bcb-ab13872285-4k` | select_stack | page-free | QEMU (9/10) | Xiaomi 13T |

Notes:

- `QEMU (9/10)`: on 6.12 the `security_hook_heads` symbol no longer exists, so nine of the ten
  `offset.*` values can be checked, and all nine match.
- The seven `tcp_zerocopy` rows marked *unverified* were kept from upstream unchanged; this branch
  has no runtime witness for them.
- The 5.10 rows are this fork's own. Upstream has no 5.10 family — no bundled profile and no 5.10
  entry in the extractor.
- The four templates (`5.15-template`, `6.1-template`, `6.6-template`, `6.12-template`) are
  reference documents for profile generation; they never match a device.
- A MediaTek device that cannot get past W1 (`W1: target 0x0`)? See [MEDIATEK.md](MEDIATEK.md) for
  the two physical addresses.
