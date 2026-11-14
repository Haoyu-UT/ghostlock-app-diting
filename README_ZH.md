# 为广泛内核支持及成功率优化的GhostLock

> English: [README.md](README.md)

为尚未修补 CVE-2026-43499 漏洞的安卓内核提供临时 root。**三星手机需要同时未修补 CVE-2026-43284。**

本仓库是 [YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app) 的分支。
**本分支新增3条路线，并优化了决定配置文件导出准确性和漏洞利用成功率的关键部分**。

## 支持的路线与实现方式

本分支支持以下路线与实现方式的组合。

| 路线 | 实现方式 | 页面依赖 | 来源 |
|---|---|---|---|
| `select_stack` | 64 位原生 | 免页面 | 来自上游，改为免页面 |
| `tcp_zerocopy` | 64 位原生 | 基于页面 | 来自上游 |
| `multicast_waiter` | 64 位原生 | 免页面 | 来自上游，改为免页面 |
| `sigreturn` | 64 位原生 | 免页面 | 本分支新增 |
| `select_stack` | 32 位兼容 | 免页面 | 本分支新增 |
| `multicast_waiter` | 32 位兼容 | 免页面 | 本分支新增 |

## 本分支的设计哲学
1. 内核支持来自精确的配置生成器，而不是逐一内置。
2. 内置配置不定义支持范围。未列出的内核可以自行生成；未由维护者亲自测试的上游配置也不会因此移除。
3. 每个正确的配置文件以没有妥协的成功率执行。

## 配置文件生成准确性
测试使用40+个内核，全部准确生成配置文件，与实机/模拟器结果完全相同。具体清单见[`docs/DESIGN_ZH.md`](docs/DESIGN_ZH.md)。

## root成功率

**完全免页面**

| 手机 | 内核 | 路线 | 完成 | 典型耗时 | 测量于 |
|---|---|---|---|---|---|
| Redmi K50 Ultra（`diting`） | 5.10.236 | `select_stack` | 10/10 | 8.0–8.7 秒 | 2026-11-14 |
| Redmi K50 Ultra（`diting`） | 5.10.236 | `sigreturn` | 4/10<br>（6 次运行中重启） | 6.8 秒 | 2026-11-14 |
| Redmi K50 Ultra（`diting`） | 5.10.236<br>(custom build) | `multicast_waiter` | 9/10 | 38.7–39.9 秒 | 2026-11-14 |
| Redmi K50 Ultra（`diting`） | 5.10.81 | `select_stack`<br>（32 位兼容） | 10/10 | 7.9 秒 | 2026-11-14 |
| POCO X6 Pro 5G（`duchamp`） | 6.1.138 | `select_stack` | 10/10 | 16.2–18.2 秒 | 2026-11-14 |
| POCO X6 Pro 5G（`duchamp`） | 6.1.138 | `select_stack`<br>（32 位兼容） | 10/10 | 16.9 秒 | 2026-11-14 |
| POCO X6 Pro 5G（`duchamp`） | 6.1.138 | `multicast_waiter`<br>（32 位兼容） | 8/10 | 16.3 秒 | 2026-11-14 |
| OnePlus 13T | 6.6.66 | `select_stack` | 10/10 | 16.5–17.1 秒 | 2026-11-14 |
| Xiaomi K90 Pro Max（`myron`） | 6.12.23 | `select_stack` | 10/10 | 34.9–35.2 秒 | 2026-11-14 |

**完全基于页面**

| 手机 | 内核 | 路线 | 完成 | 典型耗时 | 测量于 |
|---|---|---|---|---|---|
| POCO X6 Pro 5G（`duchamp`） | 6.1.138 | `tcp_zerocopy` | 8/10 | 30–36 秒 | 2026-11-14 |

*数字来自 r11 候选构建（2026-11-14 系列，versionCode 745）。*

## 使用前提
> [!WARNING]
> **vivo/iQOO 及未来任何内置反 root 的机型禁止直接尝试，维护者不持有这类机型，攻击流程未对其优化，有变砖的风险。**  
> **使用本 App 的一切风险由使用者自行承担。**

- 系统为Android 12 或更高。
- 内核及安全补丁尚未修补 CVE-2026-43499 漏洞。**三星手机需要同时满足未修补 CVE-2026-43284。**
- 提前安装下列 root 管理器之一：KernelSU、KernelSU-Next、BakaSU（曾是ReSukiSU）、KowSU 或 SukiSU Ultra。每个管理器支持临时 root 的首个版本各不相同，尽可能下载新版。**三星手机只能使用**[这个管理器](https://github.com/diabl0w/KernelSU)。

## 设备支持

支持按内核家族划分，不按机型或具体构建逐一列举：

**5.10 · 5.15 · 6.1 · 6.6 · 6.12**

只要内核属于以上家族且尚未修补 CVE-2026-43499，App 就可以从你自己的镜像文件尝试生成配置并运行。内置配置仅为通过独立验证的部分，未内置可以自行生成。完整的内置列表见 [`docs/kernel_profiles/BUNDLED_PROFILES_ZH.md`](docs/kernel_profiles/BUNDLED_PROFILES_ZH.md)。

以上家族之外的内核目前没有对应的推导模板，不在支持范围内。

## 快速开始

1. 安装 APK 并打开 App。
2. 首页会检查你的内核。
3. 若显示受支持 / 配置已就绪，保持 App 在前台，点执行。
4. 等到 `KernelSU ready`。`su` 在下次重启前可用。若 App 显示 **建议重启**，请重启手机：本次运行改动了 SELinux 策略能力，root 后的修复未能恢复，重启前网络可能不可用。

## 自行生成配置

> [!WARNING]
配置文件的部分字段来自于本机实测，不要为当前运行内核之外的任何其他内核生成配置文件。

1. 记下确切的系统版本。
2. 高通机型：取得同一OS版本的 `boot.img`、`xbl_config.img`、`uefi.img`，联发科机型：取得同一OS版本的 `boot.img`、`vendor_boot.img`、`dtbo.img`（从完整 OTA 的 `payload.bin` ，或 fastboot 包提取），放到手机存储中。
3. 打开 App，点首页的 **生成配置**：

   <img src="docs/images/profile-generation/01-home.png" width="520" alt="首页的生成配置入口">

4. 选择 **解析本地镜像**，再按手上的文件选择 **boot.img**（或 `payload.bin`）：

   | 选择来源 | 选择镜像类型 |
   |---|---|
   | <img src="docs/images/profile-generation/02-source.png" width="360"> | <img src="docs/images/profile-generation/03-image-type.png" width="360"> |

5. 按提示附加平台镜像（不建议跳过，物理地址可能不准）：
   - 高通：`xbl_config.img`；若物理地址仍缺，再附加 `uefi.img`。
   - 联发科：`vendor_boot.img`；若偏移仍缺，再附加 `dtbo.img`。

   <img src="docs/images/profile-generation/04-physical.png" width="420" alt="高通机型的 xbl_config 提示">

6. 如果 App 询问 **多条路线均可用，请选择一条**，按行内说明选择。每个选项只有两项：路线与实现方式。同一路线如果有 32 位布局，会分两行显示，分别标注 `64-bit native` 与 `32-bit compat`；右侧是**该路线机制**的建议等级（与内核型号和实现方式无关），没有依据时显示“未测量”：

   <img src="docs/images/profile-generation/05-route.png" width="420" alt="路线选择">

7. 如果 App 询问免页面方案，按行内说明选择。每一行都写明了锚点与取值的区域，危险的
   三星串口区域会单独标注：

   <img src="docs/images/profile-generation/06-plan.png" width="420" alt="免页面锚点空间选择">

8. 若出现 **Slab 跨度**，选择标有“已确认”或“结果一致”的值；也可以跳过，之后用主页的
   测量数据合并：

   <img src="docs/images/profile-generation/07-stride.png" width="420" alt="Slab 跨度选择">

9. **导出**配置，再选择使用。生成的配置未保存退出会消失。

## 如果运行失败

- **重启后重试。** 全新启动是最有效的手段；每次重启仅尝试一次。
- **若 App 提示建议重启，请重启。** 本次运行改动了 SELinux 策略能力，root 后的修复未能恢复；重启前网络可能被拦截。
- **看方案、路线与 64/32 位选择**（如果 App 询问过）每个选项都有可能产生不同的成功率。
- **导出日志** 并附在 issue 中。同时提交配置文件生成的日志和执行攻击的日志。

## 我们如何改善成功率

漏洞利用有很多环节，每个环节的失误都会降低全链路成功率。这个分支优化了以下环节：

1. **主要路线不再依赖于"喷射内存页"。** 旧路线泄漏一个页，释放并用受控内容回收，然后祈祷分配器交回同一页；页面被回收会直接造成死机。现在写入用的锁位于内核中一块固定的全零区域，运行直接使用固定的内核区域。（`tcp_zerocopy` 路线除外。）
2. **配置生成时更多使用可测量的事实。** App 更多基于事实填充配置文件，仅在无事实可用时基于经验填充。
   过去"关键字段差几个字节"的配置会在链路中途失败；这一类失败被消除了。
3. **更老的 5.10 内核也有适配的路线。** 两条额外路线覆盖默认路线够不到的内核：一条面向旧
   5.10 布局的路径，以及一个用于 5.10.43 / 5.10.81 / 5.10.101 的 32 位小助手——
   这些内核的栈布局超出了 64 位路线的覆盖范围。两种布局都成立时也会提供这个小助手（例如
   6.1.138 上的第二种 `select_stack` 选择）；内置配置沿用实测的路线顺序。
4. **攻击失败后清理留下的垃圾。** 上一次失败留下的内核状态会干扰下一次尝试。App 在每次尝试
   后解除残留状态并重试早期阶段，一次失败不会拖垮整次运行。
5. **不会无限尝试。** 过去一条永远不会结束的内核遍历会让 App 无限等待。现在无法完成的阶段
   会停止并报告停在哪一步。
6. **基于日志的迭代。** App 尽力以最小延迟记录日志并支持导出。

## 致谢

本仓库是 [YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app) 的分支，可选的DirtyFrag路线参考自 [diabl0w/DFRoot](https://github.com/diabl0w/DFRoot)，
采用 Apache License 2.0。上游另致谢：

- [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia)
- [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus)
- [x-spy/CVE-2026-43499-popsicle](https://github.com/x-spy/CVE-2026-43499-popsicle)
- [lsposed/lspromise](https://github.com/lsposed/lspromise)
- [combeng6th/DirtyInit](https://github.com/combeng6th/DirtyInit)

App 还使用了 [miuix](https://github.com/compose-miuix-ui/miuix)、
[Shizuku](https://github.com/RikkaApps/Shizuku)、
[Typesafe Config](https://github.com/lightbend/config) 与 Apache Commons Compress。
diting 5.10 的偏移最初参考了 OPPO Reno10 Pro+（CPH2521）。

## 许可

Apache License 2.0——见 [LICENSE](LICENSE)。root 是临时的、概率性的。内置配置文件基于实机或模拟器验证，以实际运行结果为准。使用本软件的风险由使用者自行承担。
