# 让 GhostLock 在联发科机型上运行

> English: [MEDIATEK.md](MEDIATEK.md)

本文面向尚自定提取配置但未成功运行 GhostLock 的联发科（MediaTek）用户。若设备已在内置支持列表中按 `uname -r` 精确匹配且运行正常，则无需阅读本文。

联发科内核需要两个内核 `Image` 本身并不携带的物理地址：`kernel_phys_load`（内核物理加载地址）与 `kernel_phys_offset`（DRAM 基址，即线性映射的 `PHYS_OFFSET`）。二者缺失或填写错误时，攻击会在 W1 阶段失败：连续重试至上限后终止。

```
[*] W1 attempt 1/15
...
[*] W1 attempt 15/15
[-] Write 1 failed
```

这两个取值都存在于设备自身的 `vendor_boot.img` 中，因此**通常无需 root**：

| 取值 | 来源 |
|---|---|
| `kernel_phys_load` | 头部 `kernel_addr` 字段 |
| `kernel_phys_offset` | 头部 `dtb` 段中 DTB 的 `/memory` 节点 |

在联发科设备上，`dtb` 段是 DTBO 表（`dtbo.img` 的格式）；提取器会直接解析。若某镜像的 `dtb_size = 0`（引导程序从别处取 DTB），改用 `--dtbo` 传入手机的 `dtbo.img`（见下方命令）；其中包含同样的 `/memory` 节点。

## 第 1 步 —— 从 boot.img + vendor_boot.img 提取

### 在 App 中

开始解析，选择手机的 `boot.img`。联发科设备随后会提示提供 `vendor_boot.img`（推荐），请附加它。
若该 `vendor_boot` 没有可用的 `/memory`（或你跳过了它），App 会继续提示提供 `dtbo.img`。
只要其中一个镜像提供了值，解析出的 profile 就会包含这两个物理地址；随后照常完成解析流程。
两个都跳过时 `kernel_phys_offset` 会为空，运行会在 W1 失败。

### 在电脑上

```sh
ghostlock-extract boot.img --vendor-boot vendor_boot.img \
    --iomem /dev/null --format conf --out profile.conf
```

在电脑上 `--iomem /dev/null` 很重要：否则工具会读取**构建主机**的 `/proc/iomem`，并静默产生一组看起来合理的错误取值。

若镜像不带 DTB，再附加手机的 `dtbo.img`：

```sh
ghostlock-extract boot.img --vendor-boot vendor_boot.img --dtbo dtbo.img \
    --iomem /dev/null --format conf --out profile.conf
```

工具会打印所用来源：

```
info: vendor_boot; kernel_phys_load=0x40000000
info: vendor_boot DTB /memory; kernel_phys_offset=0x40000000
```

## 第 2 步 —— 有 root 时的回退方案（镜像不可用）

若没有固件镜像，或 `vendor_boot` 与 `dtbo.img` 都不带 DTB，可直接从运行中的设备读取。`/proc/iomem` 与 `/proc/kallsyms` 仅 root 可读，因此设备需能提供 root shell（userdebug/eng 构建下的 `adb root`，或等效的 root），无需任何管理器应用。

**请勿**使用 KernelSU、ReSukiSU 或 KowSU，**尤其不要使用通过修补内核启用 KernelSU 的方式**：被 KernelSU 修补过的内核会干扰攻击。脚本会自动检查 root 与 KernelSU，不满足时给出提示并停止。

`tools/mtk-phys/` 会读取设备，并以醒目颜色打印两个取值。请按你的环境选择下列方式。

### 安卓（在手机上运行）

若 `mtk-phys.sh` 已在手机上，用 root shell（带 `su` 的终端 App）运行：

```sh
su -c 'sh /data/local/tmp/mtk-phys.sh'
```

若脚本不在手机上，请改用下方对应电脑的入口。

### Windows（在电脑上运行）

需 `adb` 在 PATH 中且手机已连接。

```bat
tools\mtk-phys\extract_phys.bat
```

### macOS / Linux（在电脑上运行）

需 `adb` 在 PATH 中且手机已连接。

```sh
tools/mtk-phys/extract_phys.sh
```

若连接了多台设备，先指定其一：Windows 上 `set ANDROID_SERIAL=<serial>`，macOS/Linux 上在命令前加 `ANDROID_SERIAL=<serial>`。

## 第 3 步 —— 把脚本输出抄进 App

脚本执行完成后，会打印两个取值：

```
kernel_phys_load = <值>
kernel_phys_offset = <值>
```

打开 App 的 **「高级参数覆盖」** 页，把这两个字段填成上述取值。保存后即对下次运行生效，无需重新构建。

## 第 4 步 —— 运行并验证

执行一次攻击，随后查看调试日志的开头若干行
（`Download/ghostlock-debug-log/<时间>/*.log.txt`）：

```
[*] soc: mtk; kernel_phys_load=<值>
[+] p0 profile ... phys_offset=<值> kernel_phys_load=<值>
```

若 W1 仍持续失败，说明取值仍然不正确；请复核来源输出（或用匹配的 `vendor_boot.img` 重新提取）。

## 收录为内置 profile（维护者）

如需将该内核收录为内置，维护者按 [README_ZH.md](README_ZH.md) 操作，并用设备的 `boot.img` 与其 `vendor_boot.img` 运行提取器：

```sh
ghostlock-extract boot.img --vendor-boot vendor_boot.img \
    --iomem /dev/null --format conf --out profile.conf
```

提取器现已从这些镜像同时输出两个物理地址（当 `vendor_boot` 不带 DTB 时再加 `--dtbo`）。优先使用镜像内嵌 kallsyms，不要传入设备的 `/proc/kallsyms`。只有在没有任何镜像携带 DTB 时，`kernel_phys_offset` 才需要用 `--iomem`（root 设备转储）或手工填写，`kernel_phys_load` 可用 `--phys` 提供。
