# GhostLock — `diting` 移植版（Redmi K50 Ultra，5.10.236）

> English: [README.md](README.md)

## 支持的设备

| Kernel | 机型 | 代号 | 状态 |
|---|---|---|---|
| `5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284` | Redmi K50 Ultra · Xiaomi 12T Pro | `diting` | **已端到端验证** —— Global `OS2.0.206.0`–`OS3.0.6.0` |
| `5.10.226-android12-9-00064-gea4a6f067d3f-ab12969919` | Redmi K50 Ultra · Xiaomi 12T Pro | `diting` | **已端到端验证** —— Global `OS2.0.3.0`–`OS2.0.205.0`（2026-10-10） |
| `5.10.209-android12-9-00019-g4ea09a298bb4-ab12292661` | Redmi K50 Ultra · Xiaomi 12T Pro | `diting` | **已端到端验证** —— Global `OS1.0.11.0` · `OS1.0.12.0` · `OS2.0.1.0` · `OS2.0.2.0`（2026-10-10） |

Redmi K50 Ultra 的代号是 `diting`（SM8475 / 骁龙 8+ Gen 1）。**Xiaomi 12T Pro 是同一台设备**——
同一个代号，三个零售名（也称 Redmi K50 至尊版）。它不是第二个移植。

据称可能共用同一构建、但**未经验证**的机型：

| 机型 | 代号 | SoC | 与已验证机型相比 |
|---|---|---|---|
| Xiaomi 12S Ultra | `thor` | SM8475 | 同 SoC |
| Xiaomi 12 | `cupid` | SM8450 | SoC 不同 |
| Redmi Note 13 Pro 5G | `garnet` | SM7435 | SoC 不同 |
| POCO X6 5G | `garnet` | SM7435 | SoC 不同 |
| POCO F5 | `marble` | SM7475 | SoC 不同 |
| Redmi Pad Pro | `dizi` / `ruan` | SM7435 | SoC 不同 |

均未实际运行过。其中只有 Xiaomi 12S Ultra 与已验证机型同 SoC；其余机型**可能需要单独的
profile**——SoC 不同，预计不会搭载同一份经过认证的内核构建。

本 fork 还从支持列表中**移除了 24 个上游内核**，因为本 fork 的 compact waiter 改动会破坏它们。
完整表格（含这 24 个内核覆盖哪些机型）见
[`docs/kernel_profiles/SUPPORTED_DEVICES_ZH.md`](docs/kernel_profiles/SUPPORTED_DEVICES_ZH.md)。

## 关于本 fork

本仓库是 **[YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app)** 的 fork。
上游支持 5.15 / 6.1 / 6.6 / 6.12——**5.10 不在其中**：既没有内置配置，偏移提取器也没有 5.10 的
族条目。本 fork 补上了这一款，以及让它跑通所必需的几处修复。

**关于 App 本身——使用方法、偏移提取器、配置 schema、移植指南——请阅读
[上游 README](https://github.com/YuKongA/ghostlock-app/blob/main/README_ZH.md)。**
本页只说明移植改了什么、以及已经验证到什么程度。

## 当前状态

已在**原厂、未打补丁的内核**上端到端验证通过——事先无 root，无任何插桩：

| 阶段 | 结果 |
|---|---|
| W1 — SELinux 改为 permissive | 通过 |
| W2 — 子进程凭据覆写（`child uid = 0` → `child is root!`） | 通过 |
| W3 — 绕过 seccomp 过滤器 | 通过 |
| 交接 — root 脚本以 `uid=0` 运行、KernelSU 加载、SELinux 恢复 enforcing | 通过，`native exited code=0` |

单次启动内连续多次运行同样稳定：**连续 8 次运行全部完成，无死机、无重启**。此前终结多轮系列的两个
原因均已修复——anchor 槽位跨进程复用
（[`anchor-slot-persistence-plan.md`](docs/analysis/anchor-slot-persistence-plan.md)），以及
`init_cred` 被已 root 的子进程释放
（[`init-cred-lifetime-plan.md`](docs/analysis/init-cred-lifetime-plan.md)）。

root 是**临时的**。KernelSU 由漏洞利用现场 late-load，因此重启即失效；全程 bootloader 保持
解锁。重新上锁（会清空数据）是后续独立步骤，目前尚未执行。

### KernelSU 交接

无论哪种情况，整条链都会跑完并交接；**KernelSU 模块**最终能否加载，取决于能否找到
**支持 late-load 的 `ksud`**。App 会从已安装且被它识别的管理器中复制一个——`me.weishu.kernelsu`
（KernelSU）、`me.weishu.kernelsu.pr`（KernelSU-Next）、`com.resukisu.resukisu`（ReSukiSU）、
`com.kowx712.supermanager`——到自己的 files 目录，root 脚本优先使用这份副本。已验证的组合是
**ReSukiSU**（`com.resukisu.resukisu`）：

```
[ksu] [*] ksud=/data/user/0/com.ghostlock.app/files/ksud
[ksu] [+] KernelSU module loaded
[+] KernelSU ready
```

不在该列表中的管理器——例如更早用过的 `com.sukisu.ultra`——不会被匹配，脚本会回退到
`/data/adb/ksu/bin/ksud`，其中部分构建没有 `late-load` 子命令，模块因此不会加载。把一个
**支持 late-load 的 `ksud`**（可执行文件）放到 **`/data/local/tmp/ksud`** 同样会被采用；
按 KernelSU 的 LKM 设计，该二进制内部自带 `kernelsu.ko`，无需另放模块文件。

### 未修复的回归——除 5.10 机型外，使用本 fork 前请先读这一段

**本 fork 破坏了上游 24 个内置配置。** 这是本 fork 自身的缺陷，而非 GhostLock 的问题——上游对这些
机型的支持一切正常，本仓库不会影响上游。

让 compact waiter 在 5.10 上工作的那处改动，位于与所有内核族共用的代码路径上，因此**19 个内置
6.1 配置与 5 个内置 5.15 配置**现在会把 waiter 的优先级写进错误的字段。各内核对 waiter 布局的定义
并不一致——5.10 的 `int prio` 位于 `0x40`，而 5.15 与 6.1 的 `unsigned int wake_state` 位于 `0x40`、
`int prio` 位于 `0x44`——而本 fork 无条件地按 5.10 的写法写入。

6.6 与 6.12 不受影响（它们不使用 compact waiter）。这 24 个内核所覆盖的机型见
[`docs/kernel_profiles/SUPPORTED_DEVICES_ZH.md`](docs/kernel_profiles/SUPPORTED_DEVICES_ZH.md)，
完整分析与修复方案见
[`docs/analysis/waiter-layout-family-gating-plan.md`](docs/analysis/waiter-layout-family-gating-plan.md)。
**在该问题修复之前，请勿用本 fork 为 5.15 或 6.1 设备构建。**

## 移植改动了什么

路线为 **`select_stack`**（pselect 路径），`waiter_shift = -2`，使用 5.10 的 **compact**
waiter —— 10 字布局
`{tree_entry, pi_tree_entry, task, lock, int prio, u64 deadline, ww_ctx}`。该几何由 `boot.img`
静态推导，并用 kprobe 在设备上实测确认（waiter 与 `stack_fds` 缓冲区落在同一栈地址，delta 为 0）。

配置之外，链路改动如下：

| commit | 改动 |
|---|---|
| `6c8b18a` | 在 5.x 内核上关闭 ghost；运行日志改为行缓冲 |
| `c1b8569` | 让受害进程的协议 fd 避开 select 路线的 fd 区间 |
| `765b137` | 快照并恢复 select 路线 `dup2` 过程覆盖的每一个 fd |
| `9acf2f1` | 零值写入改由 erase 的 collateral 完成（5.10 leaf 布局） |
| `a703604` | 让 `lock_anchor_image` 从配置文档一路传到 wire |
| `6e70e8c` | 移植计划与分析文档 |
| `0f76309` | 让 anchor 区域的槽位安全、按批预留并按配置尺寸划分 |
| `75f64c1` | 说明 W2 校验器为何放弃 |
| `30f0c14` | 让 `init_cred` 在整个启动周期内存活（cred pin） |
| `55f3413` | 从内核镜像推导 lock anchor 区域（`--anchor-scan`） |
| `f08c49c` | cred pin 改为重试，且不再因它让整次运行失败 |

后两处 fd 修复是「写入能落地」与「整条链跑通」的分界：在此之前，路线的 `dup2` 过程会静默销毁
长期存活的描述符，导致 W2 的受害子进程在写入落地前一轮就看到 EOF 退出。

## 复现步骤

配置文件**不是**内置资源，而是以用户文档方式导入。

1. 在主机上提取（务必加 `--iomem /dev/null`——否则工具会去读**构建主机**的 `/proc/iomem`，
   并静默给出一个看似合理的错误 `kernel_phys_load`）：

   ```sh
   ghostlock-extract boot.img --iomem /dev/null --phys 0xa8000000 --format conf --out profile.conf
   ```

2. 在 App 中导入：**配置参数 → 导入 offsets.conf（v2）**。导入的用户文档优先于内置配置。
3. 用 root shell 设置 `settings_enable_monitor_phantom_procs = false`。否则 Android 的
   phantom-process 清理机制会在运行中途 SIGKILL 掉 native 进程（272 个 spray 子进程远超平台上限），
   其现象与漏洞利用失败无法区分。该设置需要 `WRITE_SECURE_SETTINGS`，`adb shell` 无法写入。
4. 运行。

profile 与具体的内核构建一一对应，请按上述步骤为自己的设备提取，而不要直接复用它人的文件——
各构建的取值并不相同，不匹配会在 W1 阶段失败。

## 目录

- [`docs/analysis/`](docs/analysis/) —— 本移植的设计笔记与分析，包括上文所述的回归问题。
- [`docs/kernel_profiles/`](docs/kernel_profiles/) —— 上游的移植指南与配置 schema，未改动。

## 反馈问题

请开 issue —— <https://github.com/Haoyu-UT/ghostlock-app-diting/issues/new/choose>。表单会要一张
**设置 → 关于手机 → 全部参数与信息** 的截图（记得向下滚动）：里面有你的内核版本和 ROM 渠道，
排查就是从这里开始的。每次运行后日志都会自动归档，通常只差选一次文件。

先核对 `uname -r` —— **内核不同不是 bug**，而是本移植从未为其推导过的设备。见[支持的设备](#支持的设备)。

## 致谢与许可

本仓库是 [YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app) 的 fork，
采用 Apache License 2.0（见 [LICENSE](LICENSE)）。上游另致谢：

- [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia)
- [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus)
- [x-spy/CVE-2026-43499-popsicle](https://github.com/x-spy/CVE-2026-43499-popsicle)
