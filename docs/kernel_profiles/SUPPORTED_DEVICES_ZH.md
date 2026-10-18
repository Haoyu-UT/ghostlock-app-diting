# 支持的设备

> English version: [SUPPORTED_DEVICES.md](SUPPORTED_DEVICES.md)

> **本仓库是 `diting` fork。** 其列表为
> [上游](https://github.com/YuKongA/ghostlock-app/blob/main/docs/kernel_profiles/SUPPORTED_DEVICES_ZH.md)
> 列表加上本 fork 自有的 5.10 内核。r5 及更早版本曾因 fork 自身的缺陷下架 24 个上游 5.15/6.1
> 内核；**r6 已恢复**——修复与门禁见
> [`../analysis/waiter-layout-family-gating-plan.md`](../analysis/waiter-layout-family-gating-plan.md)，
> 恢复行的来源说明见文末。

> 联发科（MediaTek）机型跑不通（没有匹配的 profile，或 `W1: target 0x0`）？
> 请先 root 设备，再按 [MEDIATEK_ZH.md](MEDIATEK_ZH.md) 取得两个物理地址
> （`kernel_phys_load` / `kernel_phys_offset`）。

标记为**推荐 Shizuku**的固件，其 profile 中 `recommend_shizuku = 1`。每次启动时，应用会为主页的
**通过 Shizuku 执行**开关自动打开；你可以在本次会话中关掉它，关掉后应用在本次会话内不再要求 Shizuku。

Shizuku 以 shell 用户身份执行攻击，而 shell 没有 seccomp 过滤，因此会跳过 W3 seccomp bypass 阶段。
使用步骤：

1. 先启动 Shizuku（例如通过 ADB）并保持运行。
2. 点击应用顶部的状态卡，在弹出的请求中授予权限。

未标记的固件不会自动打开该开关，但**任何设备都可以手动开启**：通过 Shizuku 执行同样会跳过
W3 seccomp bypass，即使并非必需，也能节省时间。

## Redmi K50 Ultra（本 fork 的移植目标）

| Kernel                                                 | Devices                                                          |
|--------------------------------------------------------|------------------------------------------------------------------|
| `5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284`  | Redmi K50 Ultra（`diting`）—— Global `OS2.0.206.0`–`OS3.0.6.0`；已端到端验证 |
| `5.10.226-android12-9-00064-gea4a6f067d3f-ab12969919`  | 同上 —— Global `OS2.0.3.0`–`OS2.0.205.0`；已端到端验证（2026-10-10） |
| `5.10.209-android12-9-00019-g4ea09a298bb4-ab12292661`  | 同上 —— Global `OS1.0.11.0`、`OS1.0.12.0`、`OS2.0.1.0`、`OS2.0.2.0`；已端到端验证（2026-10-10） |
| `5.10.81-android12-9-00001-g6cd504626bae-ab8485363`    | 同上 —— Global `V13.0.3.0.SLFMIXM` / `V13.0.4.0.SLFMIXM`（出厂 ROM，Android 12）；已端到端验证 —— 经由 **sigreturn** 路线交付，500 µs 间隔下 5 次中完成 4 次（2026-10-14） |

上游没有 5.10 内核族：既没有内置配置，偏移提取器也没有 5.10 条目。在本 fork 中，配置以
**内置资源**形式随包分发（`app/src/main/assets/kernel_profiles/<精确 uname -r>.conf`，
登记在 `index.conf` 中），因此精确匹配上述内核的设备无需导入 —— 且内置配置对其 release 具有权威性。
后两款各经过一次完整 gate 与一次 3 连发序列（`5.10.226` 完成 1/3、`5.10.209` 完成 2/3），
「已端到端验证」指至少一次完整跑通。`5.10.81` 是出厂内核：其 `do_futex` 帧更浅，select-stack
的 waiter 够不到，因此改由 **sigreturn** 路线交付，速率来自一次五连发序列（完成 4/5，一次 hang
形态；`5.10.101` 尚未实跑）。

## 可能支持 —— 未经验证

以下机型**均未实际运行过**。profile 按**精确 `uname -r`** 匹配，因此只有当设备的构建字符串与上表
完全一致时才算真正支持；此外 profile 还硬编码了两个板级取值（`kernel_phys_load`、
`kernel_phys_offset`），这些并不由内核字符串描述。

| 机型 | 代号 | SoC | 与已验证机型相比 |
|---|---|---|---|
| Xiaomi 12S Ultra | `thor` | SM8475 | 同 SoC |
| Xiaomi 12 | `cupid` | SM8450 | SoC 不同 |
| Redmi Note 13 Pro 5G | `garnet` | SM7435 | SoC 不同 |
| POCO X6 5G | `garnet` | SM7435 | SoC 不同 |
| POCO F5 | `marble` | SM7475 | SoC 不同 |
| Redmi Pad Pro（Wi-Fi） | `dizi` | SM7435 | SoC 不同 |
| Redmi Pad Pro 5G | `ruan` | SM7435 | SoC 不同 |

只有 Xiaomi 12S Ultra 与已验证机型同 SoC。其余机型**可能需要单独的 profile**：SoC 不同，预计不会
搭载同一份经过认证的内核构建——以及 profile 所携带的结构体偏移。

## 继承自上游（未改动）

| Kernel                                                 | Devices                                                          |
|--------------------------------------------------------|------------------------------------------------------------------|
| `5.15.41-android13-8-g8dc4c75ab7d8-ab1673212412`       | MEIZU 20 Pro · 推荐Shizuku                                        |
| `5.15.119-android13-8-g6ff5097ee32a-ab1764665171`      | MEIZU 21 Note                                                    |
| `5.15.167-android13-8-00017-gb1f32b310a30-ab12826353`  | Red Magic 8 Pro                                                  |
| `5.15.189-android13-8-00016-g51bba4309aac-ab14546557`  | Sony Xperia 1 V                                                  |
| `5.15.189-android13-8-00004-g1c3825f8ac0a-ab14110541`  | Sony Xperia 1 V                                                  |
| `6.1.25-android14-11-maybe-dirty`                      | MEIZU 21                                                         |
| `6.1.115-android14-11-ga2521ca27699-ab13294383`        | POCO X6 Pro                                                      |
| `6.1.118-android14-11-ga3b9c44908dd-ab13320413`        | Redmi Note 15 Pro+                                               |
| `6.1.118-android14-11-gca0ef6d17716-ab13624819`        | Xiaomi 14                                                        |
| `6.1.138-android14-11-g0c3d559bcd85-ab14529422`        | Xiaomi 14                                                        |
| `6.1.138-android14-11-g151cf2b6bfbe-ab13719792`        | Lenovo Xiaoxin Pad Pro 12.7 (TB375FC)                            |
| `6.1.138-android14-11-g6ab8c9a86a33-ab14396278`        | POCO X6 Pro                                                      |
| `6.1.138-android14-11-g44bda9e8f6e9-ab13792638`        | POCO X6 Pro                                                      |
| `6.1.138-android14-11-g965475777129-mi`                | REDMI K80                                                        |
| `6.1.138-android14-11-g2ecae636cf9b-ab14676408`        | Lenovo Yoga Tab Plus (TB520FU)                                   |
| `6.1.145-android14-11-g09f1c0074ad7-ab14226177`        | Infinix Note 50s 5G, Infinix GT 30 (X6876)                       |
| `6.1.145-android14-11-g11c274d0441f-ab14259673`        | RedMagic 9(S) Pro (REDMAGICOS11.0.5MR1_GB)                       |
| `6.1.145-android14-11-g74d1702dab4d-ab14669069`        | vivo T4, IQOO 12                                                 |
| `6.1.145-android14-11-geaa643a2c0ee-ab14763719`        | Motorola Razr 50 Ultra / Motorola Razr+ 2024                     |
| `6.1.145-android14-11-g9b69cc399ae1-ab14819715`        | Motorola Edge 60 Fusion                                          |
| `6.1.157-android14-11-ga8b0b542991e-ab15601211`        | Infinix GT 30 Pro (X6873)                                        |
| `6.1.157-android14-11-gbd23337e42e7-ab14791245`        | Google Pixel 9a (Tensor G4), Google Pixel 7 (Tensor G2)          |
| `6.1.162-android14-11-gce140c0e5bf5-ab15450923`        | Zenfone 11 Ultra                                                 |
| `6.1.162-android14-11-g752d9c17787d-ab15574904`        | Google Pixel 9 Pro / 9 Pro Fold (Tensor G4)                      |
| `6.1.162-android14-11-g5e8b0cffebd1-ab15202165`        | Google Pixel 9a (Tensor G4)                                      |
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

## r6 已恢复（2026-10-14）：r5 下架的 24 个内核

r1–r5 曾下架 24 个上游内核（5 个 5.15、19 个 6.1），因为本 fork 的 compact waiter 改动
使这些内核上构造出的 waiter 其 `prio` 读作 0（最高优先级）。内核族门控
（[`../analysis/waiter-layout-family-gating-plan.md`](../analysis/waiter-layout-family-gating-plan.md)）
已实现，相关行已回到上表。

恢复行的来源，如实说明：修复按内核族重建 waiter 的 `prio` 字（5.10 输出逐字节不变，
经 `cmp_disasm` 核验），单元测试覆盖两种字型，5.10 一侧通过了设备门禁。6.1 一侧现已有一个
实测内核：在 `6.1.138-android14-11-g44bda9e8f6e9-ab13792638`（POCO X6 Pro 5G，`duchamp`）上，
r6 在 10 次全新启动中完成 5 次（关闭 Android phantom-process trimmer 后为 3/5）；开发线构建
638 为 3/5（2026-10-18）。其余 18 个 6.1 内核与全部 5.15 内核仍依据上游支持与上述离线门禁，
而非此处的实机运行。
