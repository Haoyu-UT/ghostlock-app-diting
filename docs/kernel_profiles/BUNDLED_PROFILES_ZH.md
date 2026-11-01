# 内置配置

> English version: [BUNDLED_PROFILES.md](BUNDLED_PROFILES.md)

APK 内置 **43 份内核配置**，另有四份内核族模板。配置只按确切的 `uname -r` 匹配，别的一概不算；
不在这个列表里的内核仍然可以用自己的镜像生成配置（见 README 的「自行生成配置」）。权威列表是
`app/src/main/assets/kernel_profiles/index.conf`，本页是它的可读版本。

当前构成：34 份完全免页面、2 份半页面、7 份基于页面。

- **路线** —— 这份内置配置实际跑的路线。
- **页面依赖** —— *完全免页面*：锁和 W1 的写入值都来自锚点区域；*半页面*：锁来自锚点，W1 的
  写入值来自喷射页面；*完全页面*：`tcp_zerocopy`，按构造依赖页面。
- **验证程度** —— *设备*：完整链路在该确切构建上跑通；*QEMU*：十个 `offset.*`、锚点与跨度都
  已对 QEMU 中运行的同一镜像核对过。

| 内核（`uname -r`） | 路线 | 页面依赖 | 验证程度 | 机型 |
|---|---|---|---|---|
| `5.10.81-android12-9-00001-g6cd504626bae-ab8485363` | select_stack | 完全免页面 | 设备 | Redmi K50 Ultra（`diting`）—— Global `V13.0.3.0` / `V13.0.4.0`（出厂 ROM，Android 12） |
| `5.10.101-android12-9-00005-ga829d48e78bd-ab9206161` | select_stack | 完全免页面 | QEMU（候选） | Redmi K50 Ultra（`diting`）—— Global `V14.0.1.0` |
| `5.10.136-android12-9-00021-g821df8f5bd36-ab9585204` | select_stack | 完全免页面 | QEMU（候选） | Redmi K50 Ultra（`diting`）—— Global `V14.0.3.0` |
| `5.10.177-android12-9-00001-g219d8dfbba07-ab10551810` | select_stack | 完全免页面 | QEMU（候选） | Redmi K50 Ultra（`diting`）—— Global `V14.0.5.0` |
| `5.10.198-android12-9-00085-g226a9632f13d-ab11136126` | select_stack | 完全免页面 | QEMU（候选） | Redmi K50 Ultra（`diting`）—— Global `OS1.0.5.0` |
| `5.10.209-android12-9-00019-g4ea09a298bb4-ab12292661` | select_stack | 完全免页面 | 设备 | Redmi K50 Ultra（`diting`）—— Global `OS1.0.11.0`、`OS1.0.12.0`、`OS2.0.1.0`、`OS2.0.2.0` |
| `5.10.226-android12-9-00064-gea4a6f067d3f-ab12969919` | select_stack | 完全免页面 | 设备 | Redmi K50 Ultra（`diting`）—— Global `OS2.0.3.0`–`OS2.0.205.0` |
| `5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284` | select_stack | 完全免页面 | 设备 + QEMU 对照 | Redmi K50 Ultra（`diting`）—— Global `OS2.0.206.0`–`OS3.0.6.0` |
| `6.1.115-android14-11-ga2521ca27699-ab13294383` | select_stack | 完全免页面 | QEMU | POCO X6 Pro |
| `6.1.118-android14-11-ga3b9c44908dd-ab13320413` | select_stack | 完全免页面 | QEMU | Redmi Note 15 Pro+ |
| `6.1.118-android14-11-gca0ef6d17716-ab13624819` | select_stack | 完全免页面 | QEMU | Xiaomi 14 |
| `6.1.138-android14-11-g0c3d559bcd85-ab14529422` | select_stack | 完全免页面 | QEMU | Xiaomi 14 |
| `6.1.138-android14-11-g151cf2b6bfbe-ab13719792` | tcp_zerocopy | 完全页面 | 未验证 | Lenovo Xiaoxin Pad Pro 12.7 (TB375FC) |
| `6.1.138-android14-11-g2ecae636cf9b-ab14676408` | tcp_zerocopy | 完全页面 | 未验证 | Lenovo Yoga Tab Plus (TB520FU) |
| `6.1.138-android14-11-g44bda9e8f6e9-ab13792638` | select_stack | 完全免页面 | 设备（duchamp）+ QEMU | POCO X6 Pro |
| `6.1.138-android14-11-g6ab8c9a86a33-ab14396278` | select_stack | 完全免页面 | QEMU | POCO X6 Pro |
| `6.1.138-android14-11-g965475777129-mi` | select_stack | 完全免页面 | QEMU | REDMI K80 |
| `6.1.145-android14-11-g09f1c0074ad7-ab14226177` | tcp_zerocopy | 完全页面 | 未验证 | Infinix Note 50s 5G, Infinix GT 30 (X6876) |
| `6.1.145-android14-11-g11c274d0441f-ab14259673` | select_stack | 完全免页面 | QEMU | RedMagic 9(S) Pro (REDMAGICOS11.0.5MR1_GB) |
| `6.1.145-android14-11-g74d1702dab4d-ab14669069` | tcp_zerocopy | 完全页面 | 未验证 | vivo T4, IQOO 12 |
| `6.1.145-android14-11-g9b69cc399ae1-ab14819715` | tcp_zerocopy | 完全页面 | 未验证 | Motorola Edge 60 Fusion |
| `6.1.145-android14-11-geaa643a2c0ee-ab14763719` | tcp_zerocopy | 完全页面 | 未验证 | Motorola Razr 50 Ultra / Razr+ 2024 |
| `6.1.157-android14-11-ga8b0b542991e-ab15601211` | tcp_zerocopy | 完全页面 | 未验证 | Infinix GT 30 Pro (X6873) |
| `6.1.157-android14-11-gbd23337e42e7-ab14791245` | select_stack | 半页面 | QEMU | Google Pixel 9a (Tensor G4), Google Pixel 7 (Tensor G2) |
| `6.1.162-android14-11-gce140c0e5bf5-ab15450923` | select_stack | 完全免页面 | QEMU | Zenfone 11 Ultra |
| `6.6.77-android15-8-g4a507830d890-ab13636293-4k` | select_stack | 完全免页面 | QEMU | Xiaomi Civi 5 Pro, REDMI K90 / 4 Turbo, POCO F7 |
| `6.6.77-android15-8-g63ce7556864c-ab13994517-4k` | select_stack | 完全免页面 | QEMU | Xiaomi 15 |
| `6.6.77-android15-8-gca30f3b4bef6-abogki440974771-4k` | select_stack | 完全免页面 | QEMU | Xiaomi 15 Pro, REDMI K80 Pro / K80 Ultra |
| `6.6.89-android15-8-g0889fe95bb10-ab14402178-4k` | select_stack | 完全免页面 | QEMU | POCO X8 Pro Max |
| `6.6.89-android15-8-g096cdb6ecefc-ab14358676-4k` | select_stack | 完全免页面 | QEMU | OPPO Pad 4 Pro |
| `6.6.89-android15-8-g5a0ffb447c1d-ab13771415-4k` | select_stack | 完全免页面 | QEMU | Redmi 15C 4G / POCO C85 4G |
| `6.6.89-android15-8-g8e4be6b47e40-ab14134548-4k` | select_stack | 完全免页面 | QEMU | POCO X8 Pro |
| `6.6.92-android15-8-g3637f4904cf5-ab13944661-4k` | select_stack | 完全免页面 | QEMU | Red Magic Tablet 3 Pro, Red Magic 10 Pro, Red Magic 11 Air |
| `6.6.102-android15-8-gab8eb70a71b8-ab14350911-4k` | select_stack | 半页面 | QEMU | Nothing Phone 3 |
| `6.6.102-android15-8-gb01b41c2647c-ab15574720-4k` | select_stack | 完全免页面 | QEMU | Xiaomi 17T |
| `6.6.102-android15-8-gfe76d1bc97fd-ab14689815-4k` | select_stack | 完全免页面 | QEMU | Xiaomi 17T |
| `6.6.118-android15-8-gc44b714366cc-abogki519650608-4k` | select_stack | 完全免页面 | QEMU | REDMI K80 Pro / Turbo 5 Max, POCO X8 Pro Max, Xiaomi Pad 7 Ultra |
| `6.6.118-android15-8-ge56cf6b09cca-ab15511674-4k` | select_stack | 完全免页面 | QEMU | REDMI K90 Ultra, POCO F7, Redmi Note 13 5G |
| `6.12.23-android16-5-g16e473de48a3-abogki462654244-4k` | select_stack | 完全免页面 | QEMU（9/10） | REDMI K90 Pro Max |
| `6.12.23-android16-5-g75e9b1c7ae7c-abogki463945075-4k` | select_stack | 完全免页面 | QEMU | Xiaomi 17 / 17 Pro / 17 Pro Max / 17 Ultra |
| `6.12.23-android16-5-gf1bdb13583da-ab13761046-4k` | select_stack | 完全免页面 | QEMU | Red Magic 11 Pro, Tablet 5 Pro |
| `6.12.30-android16-5-g6e872b4863d6-ab13847919-4k` | select_stack | 完全免页面 | QEMU（9/10） | REDMI Note 15 4G, POCO M6 Pro 4G |
| `6.12.38-android16-5-g3c4da6410bcb-ab13872285-4k` | select_stack | 完全免页面 | QEMU（9/10） | Xiaomi 13T |

说明：

- `QEMU（9/10）`：6.12 上 `security_hook_heads` 已不存在，所以十个 `offset.*` 里能核对九个，
  九个全部一致。
- 标为*未验证*的七份 `tcp_zerocopy` 配置是从上游原样保留下来的；本分支对它们没有任何运行见证。
- 5.10 各行是本 fork 自己的内核。上游没有 5.10 内核族——既没有内置配置，提取器里也没有 5.10
  条目。
- 四份模板（`5.15-template`、`6.1-template`、`6.6-template`、`6.12-template`）是生成配置时的
  参考文档，永远不参与设备匹配。
- 联发科机型卡在 W1（`W1: target 0x0`）？两个物理地址见
  [MEDIATEK_ZH.md](MEDIATEK_ZH.md)。
