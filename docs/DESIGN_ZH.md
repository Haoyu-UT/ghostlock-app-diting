# 设计与测量

> English: [DESIGN.md](DESIGN.md)

本文件是 [README](../README_ZH.md) 的技术说明：讲清机制、路线清单、免页面设计、提取器的
推导过程和验证级别，不引用内部证据路径。

## 1. 缺陷与链路

GhostLock 利用 **CVE-2026-43499**——Linux 5.7–7.1 的 futex 优先级继承代码中的一个
use-after-free。写入靠的是 rb-erase 的附带效果：一个没有子节点的树节点把 `pc` 设为
`target − 8`，于是向 `*(target)` 写入 NULL，而锁的树根不受污染；PI 遍历向下走时读到该节点
自身全零的子节点，随即退出。这个结构只有一个定义，即 `src/core/memory/payload_builder.h`
里的 waiter_tree_stamp()，路线的栈标记和 compact 编码都复用它。

整条链路是三次写入加一次交接：

| 阶段 | 结果 |
|---|---|
| W1 | SELinux 切到 permissive（`enforcing = 0`，`initialized` 置位） |
| W2 | 把一个活动子进程的凭据换成 `init_cred`（`child uid = 0`） |
| W3 | 清除子进程的 `TIF_SECCOMP` 与 `seccomp.mode` |
| 交接 | root 脚本以 `uid=0` 运行，并 late-load KernelSU |

一次运行要么完成交接，要么停在某个有名字的阶段；停在哪一步，App 的运行记录里会写明。

## 2. 路线

| 路线 | 适用的内核 | 投递方式 | 免页面 | 锚点 | 说明 |
|---|---|---|---|---|---|
| `select_stack` | 5.10.136+、6.1、6.6、6.12 | pselect / `_newselect` | 是 | 是 | 默认路线；在 5.10/6.1 上使用 compact waiter |
| `sigreturn` | 5.10.43 / 81 / 101 | `rt_sigreturn` 的 fpsimd 恢复 | 是 | 是 | 覆盖 5.10.136 之前的内核 |
| `tcp_zerocopy` | 6.1 | setsockopt / UDP | 否 | 否 | 天生依赖页面；select 是它的回退 |
| `multicast_waiter` | 个别内核 | IP multicast | 是 | 是 | 没有内置配置使用它 |
| `select_stack`（32 位兼容） | 5.10.43 / 81 / 101 | 32 位助手执行 pselect | 是 | 是 | select_stack 的 32 位投递 |

**路线判定。** 提取器读每个镜像自己的指令，判断哪些路线可行，并给出判定所依据的数值。
可行路线不止一条时，App 会让用户选，从不替用户静默决定。

**另外两条 5.10 投递路径。**

- `sigreturn` 借 `rt_sigreturn` 的 fpsimd 恢复投递标记，适用于 `do_futex` 栈帧太浅、pselect
  路线够不到的内核（5.10.43 / 81 / 101 这一代）。
- **`select_stack`（32 位兼容）** 补上同一代内核的另一半：陈旧的 waiter 栈条落在 64 位
  pselect 缓冲区的**下方**，于是改由静态链接的 AArch32 助手完成竞速、调用 compat 版的
  `_newselect` 停放等待，位图由 64 位 native 打包。内核地址、锚点分配器和配置仍然全是
  64 位。助手覆盖不了的几何一律拒绝——5.10.236 的 0x200 / 0x210 栈条就是例子，它会安全地
  失败，所以 236 继续走 64 位路线。

**multicast_waiter** 不是默认路线：个别 5.10 镜像（例如 5.10.246 候选）只有它走得通，但它
的几何套不到别的镜像上，因此没有任何内置配置依赖它。

## 3. 免页面路线

旧链路依赖喷射出来的载荷页：泄漏一个 slab 页，释放，再用受控内容回收，然后指望 frag 分配器
把同一页还回来。免页面设计让锚定路线不再依赖它：

- **锁锚点。** 内核里一个命名的全零 `.bss` 区域（`dump_skip.zeroes`、`bm_pmd`、
  `serial8250_ports` 等）为伪锁提供槽位。槽位按尝试轮换（一个 4 KiB 页、步长 32，共 128
  个槽）；只有失败的尝试会毒化槽位，成功的尝试不消耗。
- **W1 scratch。** 第二个全零区域提供 W1 要写入的值（`alias(scratch) + 0x100`）。这个值的
  第 0 字节必须是 0（`enforcing`），`initialized` 字节的第 0 位必须是 1。推导还要求物理差值
  （`kernel_phys_load − kernel_phys_offset`）按 64 KiB 对齐；对齐不了，或者谓词不成立，这个
  scratch 就不能用。`initialized` 字节在 5.10/5.15/6.1 上位于偏移 2，在 6.6/6.12 上位于
  偏移 1（`+0x100` 把它固定住）。区域满足不了这条规则时，不会作为自含方案提供。
- **区域安全策略。** `dump_skip.zeroes`、`bm_pmd`、`serial8250_ports` 无条件可用。
  `s3c24xx_serial_ports` 则是有条件的：没有三星串口硬件时它是死代码，但在三星设备上驱动
  可能已经绑定、数组可能是活的；因此只有在没有安全方案时才提供，并带黄色标签（三星手机上
  为红色）。
- **方案。** 提取器列出所有有效的（锚点，scratch）组合。只有一组安全方案时 App 直接采用；
  有多组时列出来让用户选择；一组安全的免页面方案都没有时，才显示"页面"一行。
- **回退。** 没有锚点也没有 scratch 的配置照旧走页面路径。`tcp_zerocopy` 天生就是页面
  路线：它的伪锁是一个精心构造的对象，全零锚点驱动不了。

运行日志会写明当前模式：`page_free=1 reason=policy+scratch+anchor`，或
`page_free=0 reason=<第一个缺失的条件>`。

## 4. 提取器

能覆盖哪些内核，由提取器决定。一次解析产出一份**选项超集**——每条可行路线及其几何、每个
命名锚点候选及其免页面方案、以及公共配置块。可运行的配置只是对这份文档做一次**切割**，不会
再做第二次推导。

输入可以是 `boot.img`、原始 arm64 `Image`、`payload.bin`、OTA zip 或 OTA 链接。物理加载
地址和偏移由平台镜像提供：高通用 `xbl_config.img`（或 `uefi.img`），联发科用
`vendor_boot.img`（以及 `dtbo.img`）。没有平台镜像时这两个值留空，由 native 的编译默认值
生效；`/proc/iomem` 永远不作为来源。

逐镜像推导：从镜像本身恢复 kallsyms；内核带 BTF 就用 BTF；再反汇编得到内核家族与路线几何。
路线判定、锚点扫描和 slab 跨度（在设备或 QEMU 上实测）也属于推导的一部分。每个值都带来源
和置信度记录（`--explain` 会打印）。

### 已验证的内核

"Device" 表示完整链路在该确切构建上跑通；"QEMU" 表示十个 `offset.*`、锚点与跨度都已对
QEMU 中运行的同一镜像核对过。

| 内核（`uname -r`） | 路线 | 验证 |
|---|---|---|
| `5.10.43-android12-9-gb8e472053352-ab8059253` | sigreturn | QEMU |
| `5.10.81-android12-9-00001-geba40aecb3b7-ab8534902` | sigreturn | QEMU |
| `5.10.81-android12-9-00001-g6cd504626bae-ab8485363` | sigreturn、select_stack（32 位兼容） | 设备 |
| `5.10.101-android12-9-00001-gf4c0e37dbcde-ab8596533` | sigreturn | QEMU |
| `5.10.101-android12-9-00027-g1292f517889e-ab8602202` | sigreturn | QEMU |
| `5.10.101-android12-9-00005-ga829d48e78bd-ab9206161` | sigreturn | QEMU |
| `5.10.136-android12-9-00020-gc9f59ef34367-ab9585114` | select_stack | QEMU |
| `5.10.136-android12-9-00021-g821df8f5bd36-ab9585204` | select_stack | QEMU |
| `5.10.177-android12-9-00001-g219d8dfbba07-ab10551810` | select_stack | QEMU |
| `5.10.198-android12-9-00085-g226a9632f13d-ab11136126` | select_stack | QEMU（候选配置） |
| `5.10.209-android12-9-00019-g4ea09a298bb4-ab12292661` | select_stack | 设备 |
| `5.10.226-android12-9-00064-gea4a6f067d3f-ab12969919` | select_stack | 设备 |
| `5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284` | select_stack、sigreturn | 设备 + QEMU 对照 |
| `5.10.236-android12-9-00003-gfb24cf99ad97-full-osize` | multicast_waiter | QEMU |
| `5.10.236-android12-9-00003-gfb24cf99ad97-full-none-os` | 无可行路线 | QEMU |
| `5.10.236-android12-9-00003-gfb24cf99ad97-ksun-osize` | multicast_waiter | 设备（RAM 启动） |
| `5.10.246-gki-g3e27bf130358` | multicast_waiter | QEMU 精确；设备尝试止于 W1——候选 |
| `5.15.194-android13-8-00019-gf4321180a397-ab15212794` | multicast_waiter | QEMU |
| `6.1.25-android14-11-g8744d1c0cf31-ab10888519` | select_stack、tcp_zerocopy | QEMU |
| `6.1.25-android14-11-g9f6af9a6c2cc-ab11205628` | select_stack、tcp_zerocopy | QEMU |
| `6.1.57-android14-11-g798323a4de21-ab11424362` | select_stack、tcp_zerocopy | QEMU |
| `6.1.75-android14-11-gd57efa708101-ab12102151` | select_stack、tcp_zerocopy | QEMU |
| `6.1.78-android14-11-gb6577b760481-ab12075023` | select_stack、tcp_zerocopy | QEMU |
| `6.1.99-android14-11-gd6f926cfde54-ab12786694` | select_stack、tcp_zerocopy | QEMU |
| `6.1.115-android14-11-gfaa9b1b32a11-ab13269000` | select_stack、tcp_zerocopy | QEMU |
| `6.1.118-android14-11-ga3b9c44908dd-ab13320413` | select_stack、tcp_zerocopy | QEMU |
| `6.1.118-android14-11-gca0ef6d17716-ab13624819` | select_stack、tcp_zerocopy | QEMU |
| `6.1.138-android14-11-g0c3d559bcd85-ab14529422` | select_stack、tcp_zerocopy | QEMU |
| `6.1.138-android14-11-g44bda9e8f6e9-ab13792638` | select_stack、tcp_zerocopy | 设备（duchamp）+ QEMU |
| `6.1.138-android14-11-g51f8c580613d-ab13911623` | select_stack、tcp_zerocopy | QEMU |
| `6.6.30-android15-8-g6b55ce738535-4k` | select_stack | QEMU |
| `6.6.56-android15-8-g443415d527b9-ab13130172-4k` | select_stack | QEMU |
| `6.6.66-android15-8-g29d86c5fc9dd-abogki428889875-4k` | select_stack | 设备（CPH2723，单次通过） |
| `6.6.77-android15-8-g4a507830d890-ab13636293-4k` | select_stack | QEMU |
| `6.6.89-android15-8-g096cdb6ecefc-ab14358676-4k` | select_stack | QEMU |
| `6.6.102-android15-8-g32d1c845cb64-abogki446052083-lotus-4k` | select_stack | QEMU |
| `6.12.23-android16-5-g16e473de48a3-abogki462654244-4k` | select_stack | QEMU（9/10；`security_hook_heads` 不存在） |
| `6.12.23-android16-5-g316453da9a9e-abogki441133159-4k` | select_stack | QEMU（9/10；原因同上） |
| `6.12.23-android16-5-g5a0e85dd9db0-ab14499855-4k` | select_stack | 设备（解析 + 跨度；尚无链路运行） |
| `6.12.30-android16-5-g6e872b4863d6-ab13847919-4k` | select_stack | QEMU（9/10；原因同上） |
| `6.12.38-android16-5-g3c4da6410bcb-ab13872285-4k` | select_stack | QEMU（9/10；原因同上） |
| `6.12.69-android16-6-g014ca48a80ee-ab15889839-4k` | select_stack | 已打补丁；提取器拒绝，锚点人工核对 |

说明：

- 6.12 上 `security_hook_heads` 已被逐 hook 的列表取代，不再存在，所以十个偏移里能核对
  九个，九个全部一致。
- 测试语料里还有一些只做过主机校验的内核（例如 5.10.157、5.10.189、5.10.214 和另一个
  5.10.209 构建）。它们的配置能生成、自洽，但没有运行时或设备见证，所以不在上表。
- 提取器的契约由两种语言共同校验：native 的 wire 摘要与 Kotlin 文档摘要保持一致，改掉
  任何一边，对应的测试都会失败。

## 5. 配置模型

- **内置配置**是 APK 里的资源，按确切的 `uname -r` 查找；对它所覆盖的内核来说，它就是
  权威来源。
- **外部配置**通过系统文件选择器选定；选定后优先于内置配置，读不了的文档会明确报错，绝不
  静默回退。
- **测量库**保存 root 阶段实测的 `mm_struct_sz`，只作为只读的事实来源，绝不充当优先级层。
  合并它会生成一份新文档，必须导出并选中之后才生效。
- 编辑器只在内存里；导出是唯一的保存方式。native 的 wire schema 与 Kotlin 文档靠同一个
  摘要保持同步。

## 6. 测量方法

- 每次全新启动只跑一次：重启，等 `sys.boot_completed=1`，等系统稳定，运行，再确认 boot id
  变了。
- 系列由 `sigret-run-once.sh` 驱动：运行前把 App 放回 `top-app` cpuset；在厂商暴露
  `core_ctl` 的设备上，还要让配置的 CPU 留在活跃掩码里。README 表里的数字都是在这个前提下
  测得的。
- 判定标准是 App 运行记录里的 `state=completed`（交接类运行还要 `native exited code=0`）；
  辅助判断看路线日志（`calls=… success=… clean=1/1`）和轮询到的内核日志里有没有 oops。
- 启动被拒绝的不计入统计，重启后重试；出现新的失败情况时，停下来排查。
- 成功率按 Wilson 95% 置信区间报告，失败类型一并列出，绝不靠平均掩盖。
- 提取器验证是另一条线：QEMU 逐个启动镜像，导出 `/proc/kallsyms` 与 `/proc/slabinfo`，
  把生成的配置和运行中的内核对照，并以设备验证过的 5.10.236 数值作为对照。

## 7. 构建与测试

工具链：ONDK r30.1（不是 Google 官方 NDK）、JDK 25 和 Android Rust target。

```sh
make -C src ghostlock          # native 载荷，零警告
make -C src compat-helper      # 静态 AArch32 助手（libghostlock32.so）
make -C src lint-tidy
make -C src native-host-tests
cargo test --release           # 提取器
./gradlew --offline :app:assembleDebug
./gradlew --offline :app:testDebugUnitTest :profile-core:test
```

APK 里打包 `libghostlock.so`、AArch32 的 `libghostlock32.so` 和提取器 `libextract.so`。
发布前还会用 `tools/cmp_disasm.py` 检查攻击路径；它有已知的对照失败（两个 `multicast_*`
符号在两个二进制里都不存在），这是预期内的，所以要看各个目标的指令计数，而不只是退出码。
