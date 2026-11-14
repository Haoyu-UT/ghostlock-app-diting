# 设计与测量

> English: [DESIGN.md](DESIGN.md)

本文件是 [README](../README_ZH.md) 的技术说明：讲清机制、两条 pipeline（GhostLock 与
DirtyFrag）、路线与实现方式清单、免页面设计、提取器的推导过程和验证级别，不引用内部证据
路径。

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

## 2. 第二条路线：DirtyFrag

GhostLock 不是唯一的链路。**DirtyFrag（CVE-2026-43284）**与它共用第一步——W1，把 SELinux
切到 permissive——之后写的是**文件页缓存**，不是内核内存。App 可以通过
`IpSecManager`/`IpSecService` 安装 transport 模式的 IPsec 变换，把文件页 splice 进 UDP 发送
路径；没有 ESP 修复的镜像会把文件页挂到 skb 上，载荷于是变成文件的页缓存。随后把一小段
stub 注入 init 的 libc++/libbase sentry 构造函数，init 以自己的 uid 0 运行它并开一个 root
守护进程（无内核模块），KernelSU 可选。这是三星手机的第二条路：KDP 会拒绝凭据写入，但当
凭据就是 init 自己的时，没有东西可拒绝。

配置携带**有序的 pipeline 列表**（`pipeline = [ "dirtyfrag", "ghostlock" ]`，优先级从高到
低）。App 在 W1 之前解析：镜像的静态判定、ROM 预检（libc++ hook 与 cave、策略/服务）、
阶段 2 的原语探针（`libdfprobe`，结果写入实测数据库）以及当前状态。第一条可行的条目运行；
W1 之后没有回退，KDP 镜像只带 `["dirtyfrag"]`。DirtyFrag 的每个失败退出都会把 SELinux 恢复
为 enforcing。可行性由发送路径决定：5.10 是 `splice() → udp_sendpage() →
ip_append_page()`，6.5+ 是 `skb_splice_from_iter`；6.1 镜像没有后者时只会拷贝页面，因此
那里 DirtyFrag 不可行。

## 3. 路线

路线是标记 waiter 的投递机制；**实现方式（carrier）**是这条机制在该镜像 ABI 下的具体实现。
两者都由提取器从镜像推导。

| 路线 | 实现方式 | 适用的内核 | 投递方式 | 免页面 | 说明 |
|---|---|---|---|---|---|
| `select_stack` | 64 位原生 | 5.10.136+、6.1、6.6、6.12 | pselect / `_newselect` | 是 | 默认路线；在 5.10/6.1 上使用 compact waiter |
| `select_stack` | 32 位兼容 | 5.10.43 / 81 / 101；6.1.138 | 32 位助手执行 pselect | 是 | select_stack 的 32 位投递 |
| `sigreturn` | 64 位原生 | 5.10.43 / 81 / 101 | `rt_sigreturn` 的 fpsimd 恢复 | 是 | 覆盖 5.10.136 之前的内核 |
| `tcp_zerocopy` | 64 位原生 | 6.1 | setsockopt / UDP | 否 | 天生依赖页面；select 是它声明的回退 |
| `multicast_waiter` | 64 位原生 | 5.15.194（fuxi）、个别 5.10 镜像 | IP multicast | 是 | 这些镜像实际跑的路线 |
| `multicast_waiter` | 32 位兼容 | 6.1.134、6.1.138 | AArch32 `MCAST_BLOCK_SOURCE` | 是 | 64 位拷贝覆盖不到的 6.1 镜像 |

**路线判定。** 提取器读每个镜像自己的指令，判断哪些路线可行、用哪种实现方式，并给出判定
所依据的数值。同一条路线可以出现两次——原生与 compat；每个选项只有两项：路线和实现方式
（`64-bit native` / `32-bit compat`）。右侧的等级是路线机制的提示，不是对某个内核或某种
实现方式的预测。可行路线不止一条时 App 会问用户；只有一条时直接采用该镜像的主实现方式。

**实现方式的分支。**

- `sigreturn` 借 `rt_sigreturn` 的 fpsimd 恢复投递标记，适用于 `do_futex` 栈帧太浅、pselect
  路线够不到的内核（5.10.43 / 81 / 101 这一代）。
- **`select_stack`（32 位兼容）** 补上同一代内核的另一半，并从 r11 起覆盖 compat 链成立的
  6.1 镜像：陈旧的 waiter 栈条落在 64 位 pselect 缓冲区的**下方**，于是改由静态链接的
  AArch32 助手完成竞速、调用 compat 版的 `_newselect` 停放等待，位图由 64 位 native 打包。
  内核地址、锚点分配器和配置仍然全是 64 位。助手覆盖不了的几何一律拒绝——5.10.236 的
  0x200 / 0x210 栈条就是例子，它会安全地失败，所以 236 继续走 64 位路线。6.1.138 是第一个
  6.1 设备门（4/4）。
- **`multicast_waiter`（32 位兼容）** 是 64 位 `group_source_req` 拷贝太深的 6.1 镜像的
  投递方式（6.1.138 上拷贝窗口在锁槽前 0x88 处结束）：AArch32 助手走
  `MCAST_BLOCK_SOURCE` 的 compat 分支，把 32 位结构拷到一个正好落在 waiter 上的局部变量。
  它已在 6.1.138 上通过设备门；这条路的拷贝窗口天生暴露（dead-frame 审计没有找到可停放的
  carrier），因此引用的是实测成功率。

**multicast_waiter** 不是默认路线：5.15.194（fuxi）与 6.1.134（Realme）的内置配置是推导
结果把它留作实际路线的镜像；在那里它是唯一能走通的路线，但它的几何套不到别的镜像上。

## 4. 免页面路线

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
- **策略能力。** W1 写入的值是一个内核地址，第 5–6 字节必然是 `0xff`；这两个字节是
  `policycap[3]`（`always_check_network`）与 `[4]`（`cgroup_seclabel`）。这次写入会把它们
  悄悄打开，网络数据路径可能到策略重新加载前都被拦截。因此 root 脚本在 root 成功后、任何
  KernelSU 交接之前立即重新加载策略；当活动策略不可读（已加载 KernelSU 的 warm run 返回
  `EINVAL`）时，App 显示 **建议重启** 并发送通知，重启即可恢复。能避免这次改写的
  “取值无关的 W1 写入”仍只是计划，尚未发布。
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

## 5. 提取器

能覆盖哪些内核，由提取器决定。一次解析产出一份**选项超集**——每条可行路线及其几何与实现
方式变体（`alternatives[]`）、pipeline 判定（`pipelines[]`，推导出的顺序）、每个命名锚点
候选及其免页面方案、以及公共配置块。可运行的配置只是对这份文档做一次**切割**，不会再做
第二次推导。

输入可以是 `boot.img`、原始 arm64 `Image`、`payload.bin`、OTA zip 或 OTA 链接。物理加载
地址和偏移由平台镜像提供：高通用 `xbl_config.img`（或 `uefi.img`），联发科用
`vendor_boot.img`（以及 `dtbo.img`）。没有平台镜像时这两个值留空，由 native 的编译默认值
生效；`/proc/iomem` 永远不作为来源。

逐镜像推导：从镜像本身恢复 kallsyms；内核带 BTF 就用 BTF；再反汇编得到内核家族与路线几何。
路线判定、锚点扫描和 slab 跨度（在设备或 QEMU 上实测）也属于推导的一部分。每个值都带来源
和置信度记录（`--explain` 会打印）。

pipeline 判定决定 DirtyFrag 是否可行：ESP 修复级别、splice 发送路径（5.10 的
`udp_sendpage`/`ip_append_page`，6.5+ 的 `skb_splice_from_iter`）以及镜像的 KDP 事实。App
的 W1 前解析器再加 ROM 预检（hook 与 cave）与实时探针。

### 已验证的内核

"Device" 表示完整链路在该确切构建上跑通；"QEMU" 表示十个 `offset.*`、锚点与跨度都已对
QEMU 中运行的同一镜像核对过。完整的逐内核清单（每份内置配置的路线与验证程度）见
[`kernel_profiles/BUNDLED_PROFILES_ZH.md`](kernel_profiles/BUNDLED_PROFILES_ZH.md)；下表是
设计验证时使用的推导语料。

| 内核（`uname -r`） | 路线 | 验证 |
|---|---|---|
| `5.10.43-android12-9-gb8e472053352-ab8059253` | sigreturn | QEMU |
| `5.10.66-android12-9-00001-g41ff3fa8fff9-ab8171928` | sigreturn | QEMU |
| `5.10.81-android12-9-00001-geba40aecb3b7-ab8534902` | sigreturn | QEMU |
| `5.10.81-android12-9-00001-g6cd504626bae-ab8485363` | sigreturn、select_stack（32 位兼容） | 设备 |
| `5.10.101-android12-9-00001-gf4c0e37dbcde-ab8596533` | sigreturn | QEMU |
| `5.10.101-android12-9-00027-g1292f517889e-ab8602202` | sigreturn | QEMU |
| `5.10.101-android12-9-00005-ga829d48e78bd-ab9206161` | sigreturn | QEMU |
| `5.10.136-android12-9-00020-gc9f59ef34367-ab9585114` | select_stack | QEMU |
| `5.10.136-android12-9-00021-g821df8f5bd36-ab9585204` | select_stack | QEMU |
| `5.10.168-android12-9-00002-gf3c080171fd5-ab10346004` | select_stack | QEMU |
| `5.10.177-android12-9-00001-g219d8dfbba07-ab10551810` | select_stack | QEMU |
| `5.10.198-android12-9-00085-g226a9632f13d-ab11136126` | select_stack | QEMU（候选配置） |
| `5.10.209-android12-9-00019-g4ea09a298bb4-ab12292661` | select_stack | 设备 |
| `5.10.226-android12-9-00064-gea4a6f067d3f-ab12969919` | select_stack | 设备 |
| `5.10.226-android12-9-00047-g4968e29b7f92-ab12786767` | select_stack | QEMU |
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
| `6.1.134-android14-11-o-gd252f36df142` | multicast_waiter（32 位兼容）、sigreturn | 报告者设备（镜像与配置一致）；compat 路线是推导出的修复，单元门待跑 |
| `6.1.138-android14-11-g0c3d559bcd85-ab14529422` | select_stack、tcp_zerocopy | QEMU |
| `6.1.138-android14-11-g44bda9e8f6e9-ab13792638` | select_stack（原生 + 32 位兼容）、tcp_zerocopy、multicast_waiter（32 位兼容）、sigreturn | 设备（duchamp：原生 select 10/10，compat select 4/4，compat multicast 8/10）+ QEMU |
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
| `6.12.23-android16-5-abA165MUBS6CYL1-4k` | select_stack + DirtyFrag pipeline | 设备（DirtyFrag 第二路线，操作者确认） |
| `6.12.30-android16-5-g6e872b4863d6-ab13847919-4k` | select_stack | QEMU（9/10；原因同上） |
| `6.12.38-android16-5-g3c4da6410bcb-ab13872285-4k` | select_stack | QEMU（9/10；原因同上） |
| `6.12.69-android16-6-g014ca48a80ee-ab15889839-4k` | select_stack | 已打补丁；提取器拒绝，锚点人工核对 |

说明：

- 6.12 上 `security_hook_heads` 已被逐 hook 的列表取代，不再存在，所以十个偏移里能核对
  九个，九个全部一致。
- 测试语料里还有一些只做过主机校验的内核（例如 5.10.157、5.10.189、5.10.214 和另一个
  5.10.209 构建）。它们的配置能生成、自洽，但没有运行时或设备见证，所以不在上表。
- 测试语料共 71 份；其中 60 份作为 golden 派生的内置配置发布。另有 7 份手工完成的 6.1
  配置只有家族证据（镜像不在 store 里），四份模板只是参考文档，永远不会匹配设备。
- 提取器的契约由两种语言共同校验：native 的 wire 摘要与 Kotlin 文档摘要保持一致，改掉
  任何一边，对应的测试都会失败。

## 6. 配置模型

- **内置配置**是 APK 里的资源，按确切的 `uname -r` 查找；对它所覆盖的内核来说，它就是
  权威来源。
- **外部配置**通过系统文件选择器选定；选定后优先于内置配置，读不了的文档会明确报错，绝不
  静默回退。
- **测量库**保存 root 阶段实测的 `mm_struct_sz`，只作为只读的事实来源，绝不充当优先级层。
  合并它会生成一份新文档，必须导出并选中之后才生效。
- 编辑器只在内存里；导出是唯一的保存方式。native 的 wire schema 与 Kotlin 文档靠同一个
  摘要保持同步。

## 7. 测量方法

- 每次全新启动只跑一次：重启，等 `sys.boot_completed=1`，等系统稳定，运行，再确认 boot id
  变了。
- 系列由 `series-run.sh`（每次全新启动一轮）包住 `sigret-run-once.sh` 驱动：运行前把 App
  放回 `top-app` cpuset；在厂商暴露 `core_ctl` 的设备上，还要让配置的 CPU 留在活跃掩码里。
  README 表里的数字都是在这个前提下测得的。
- 判定标准是 App 运行记录里的 `state=completed`（交接类运行还要 `native exited code=0`）；
  辅助判断看路线日志（`calls=… success=… clean=1/1`）和轮询到的内核日志里有没有 oops。
- 启动被拒绝的不计入统计，重启后重试；出现新的失败情况时，停下来排查。
- 成功率按 Wilson 95% 置信区间报告，失败类型一并列出，绝不靠平均掩盖。
- 提取器验证是另一条线：QEMU 逐个启动镜像，导出 `/proc/kallsyms` 与 `/proc/slabinfo`，
  把生成的配置和运行中的内核对照，并以设备验证过的 5.10.236 数值作为对照。

## 8. 构建与测试

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
store 语料测试只在 `GHOSTLOCK_IMAGE_DIR` 指向 `external/test-kernels` 时运行；不设置会静默
跳过。发布前还会用 `tools/cmp_disasm.py` 检查攻击路径；它有已知的对照失败（两个
`multicast_*` 符号在两个二进制里都不存在），这是预期内的，所以要看各个目标的指令计数，而
不只是退出码。发布本身还要过 `tools/ship_golden_profiles.py --check`（r11 时是 60 份
bundled、0 missing、0 mismatched、11 exempt）和最终构建上的一次全新启动冒烟。
