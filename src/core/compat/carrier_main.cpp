/*
 * GhostLock compat carrier helper (AArch32).
 *
 * The 64-bit native execs this binary, sends one CarrierCommand over an
 * inherited pipe and reads one CarrierResult back. In Run mode the helper is
 * the stack donor: it runs the waiter/owner/consumer dance and parks the
 * waiter in _newselect with the native-packed bitmap. All kernel addresses
 * and the bitmap itself are built by the native; this process never
 * interprets them.
 *
 * This first slice implements the delivery/seccomp smoke (gate G2): it proves,
 * under the app's own seccomp filter and SELinux domain, that a static armv7
 * process can be exec'd from nativeLibraryDir and that the syscalls the
 * carrier needs are allowed. Run mode follows the QEMU engine gate.
 */

#include "compat/carrier_engine.h"
#include "compat/carrier_protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* Raw numbers where the NDK's surface differs across API levels; the compat
 * ABI is fixed by the kernel, not by the toolchain headers. */
#ifndef __NR__newselect
#define __NR__newselect 142
#endif
#ifndef __NR_timerfd_create
#define __NR_timerfd_create 353
#endif
#ifndef __NR_sched_setattr
#define __NR_sched_setattr 380
#endif
#ifndef __NR_pipe2
#define __NR_pipe2 359
#endif

namespace {
    void say(const char *message) noexcept {
        const size_t length = strlen(message);
        (void) !write(1, message, length);
        (void) !write(1, "\n", 1);
    }

    void say_int(const char *label, long value) noexcept {
        char buffer[96];
        size_t used = 0;
        while (*label != '\0' && used + 1 < sizeof(buffer)) buffer[used++] = *label++;
        const char *prefix = " ";
        while (*prefix != '\0' && used + 1 < sizeof(buffer)) buffer[used++] = *prefix++;
        bool negative = value < 0;
        if (negative) value = -value;
        char digits[24];
        size_t count = 0;
        do {
            digits[count++] = static_cast<char>('0' + (value % 10));
            value /= 10;
        } while (value != 0 && count < sizeof(digits));
        if (negative && used + 1 < sizeof(buffer)) buffer[used++] = '-';
        while (count > 0 && used + 1 < sizeof(buffer)) buffer[used++] = digits[--count];
        buffer[used] = '\0';
        say(buffer);
    }

    bool read_all(int fd, void *data, size_t length) noexcept {
        auto *out = static_cast<uint8_t *>(data);
        size_t done = 0;
        while (done < length) {
            const ssize_t got = read(fd, out + done, length - done);
            if (got < 0) {
                if (errno == EINTR) continue;
                return false;
            }
            if (got == 0) return false;
            done += static_cast<size_t>(got);
        }
        return true;
    }

    bool write_all(int fd, const void *data, size_t length) noexcept {
        auto *in = static_cast<const uint8_t *>(data);
        size_t done = 0;
        while (done < length) {
            const ssize_t put = write(fd, in + done, length - done);
            if (put < 0) {
                if (errno == EINTR) continue;
                return false;
            }
            done += static_cast<size_t>(put);
        }
        return true;
    }

    long parse_fd(int argc, char **argv, const char *name, long fallback) noexcept {
        const size_t name_length = strlen(name);
        for (int i = 1; i < argc; i++) {
            if (strncmp(argv[i], name, name_length) != 0 || argv[i][name_length] != '=') continue;
            long value = 0;
            const char *p = argv[i] + name_length + 1;
            if (*p == '\0') return fallback;
            while (*p >= '0' && *p <= '9') {
                if (value > 1000000) return fallback;
                value = value * 10 + (*p - '0');
                p++;
            }
            return *p == '\0' ? value : fallback;
        }
        return fallback;
    }

    struct SchedAttr final {
        uint32_t size;
        uint32_t sched_policy;
        uint64_t sched_flags;
        int32_t sched_nice;
        uint32_t sched_priority;
        uint64_t sched_runtime;
        uint64_t sched_deadline;
        uint64_t sched_period;
    };

    /* Gate G2: the syscalls the run mode will use, each reported separately so
     * a SIGSYS names the one the filter refuses. The native logs the last
     * "smoke: calling <name>" line before a death. */
    void run_smoke(ghostlock::compat::CarrierResult *result) noexcept {
        int32_t *slot = result->smoke;

        say("smoke: calling futex");
        {
            uint32_t word = 0;
            errno = 0;
            const long ret = syscall(__NR_futex, &word, FUTEX_WAKE, 1, nullptr, nullptr, 0);
            slot[0] = ret == 0 ? 0 : -errno;
        }
        say_int("smoke: futex", slot[0]);

        say("smoke: calling timerfd_create");
        {
            errno = 0;
            const long fd = syscall(__NR_timerfd_create, CLOCK_MONOTONIC, TFD_CLOEXEC);
            slot[1] = fd >= 0 ? 0 : -errno;
            if (fd >= 0) (void) close(static_cast<int>(fd));
        }
        say_int("smoke: timerfd_create", slot[1]);

        say("smoke: calling _newselect");
        {
            uint8_t bitmaps[ghostlock::compat::kCarrierBitmapBytes];
            memset(bitmaps, 0, sizeof(bitmaps));
            struct timeval zero_timeout;
            memset(&zero_timeout, 0, sizeof(zero_timeout));
            errno = 0;
            const long ret = syscall(
                __NR__newselect, 320,
                bitmaps,
                bitmaps + 0x28,
                bitmaps + 0x50,
                &zero_timeout);
            slot[2] = ret == 0 ? 0 : -errno;
        }
        say_int("smoke: _newselect", slot[2]);

        say("smoke: calling sched_setattr");
        {
            SchedAttr attr;
            memset(&attr, 0, sizeof(attr));
            attr.size = sizeof(attr);
            attr.sched_policy = 3; /* SCHED_BATCH, same shape as the consumer */
            attr.sched_nice = 1;
            errno = 0;
            const long ret = syscall(__NR_sched_setattr, 0, &attr, 0);
            slot[3] = ret == 0 ? 0 : -errno;
        }
        say_int("smoke: sched_setattr", slot[3]);

        say("smoke: calling pipe2");
        int pipe_fds[2] = {-1, -1};
        {
            errno = 0;
            const long ret = syscall(__NR_pipe2, pipe_fds, O_CLOEXEC);
            slot[5] = ret == 0 ? 0 : -errno;
            if (ret != 0) {
                pipe_fds[0] = -1;
                pipe_fds[1] = -1;
            }
        }
        say_int("smoke: pipe2", slot[5]);

        say("smoke: calling fcntl_high");
        {
            errno = 0;
            const int high = pipe_fds[0] >= 0 ? fcntl(pipe_fds[0], F_DUPFD, 400) : -1;
            slot[6] = high >= 0 ? 0 : -errno;
            if (high >= 0) (void) close(high);
        }
        say_int("smoke: fcntl_high", slot[6]);

        say("smoke: calling dup2_319");
        {
            errno = 0;
            const int ret = pipe_fds[0] >= 0 ? dup2(pipe_fds[0], 319) : -1;
            slot[4] = ret == 319 ? 0 : -errno;
            if (ret == 319) (void) close(319);
        }
        say_int("smoke: dup2_319", slot[4]);

        say("smoke: calling prctl");
        {
            errno = 0;
            const int ret = prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
            slot[7] = ret == 0 ? 0 : -errno;
        }
        say_int("smoke: prctl", slot[7]);

        for (int i = 0; i < 8; i++) {
            if (slot[i] != 0) result->status = 1;
        }
        if (pipe_fds[0] >= 0) (void) close(pipe_fds[0]);
        if (pipe_fds[1] >= 0) (void) close(pipe_fds[1]);
    }
} // namespace

int main(int argc, char **argv) {
    (void) prctl(PR_SET_NAME, "ghostlock32", 0, 0, 0);
    (void) prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);

    const int log_fd = fcntl(1, F_DUPFD_CLOEXEC, 950);
    if (log_fd >= 0) ghostlock::compat::set_log_fd(log_fd);
    const int cmd_fd = static_cast<int>(parse_fd(argc, argv, "--cmd-fd", -1));
    const int res_fd = static_cast<int>(parse_fd(argc, argv, "--res-fd", -1));
    if (cmd_fd < 0 || res_fd < 0) {
        say("compat-helper: missing --cmd-fd/--res-fd");
        return 2;
    }

    ghostlock::compat::CarrierCommand command;
    if (!read_all(cmd_fd, &command, sizeof(command))) {
        say("compat-helper: cannot read command");
        return 2;
    }
    if (command.magic != ghostlock::compat::kCommandMagic ||
        command.version != ghostlock::compat::kProtocolVersion) {
        say("compat-helper: bad command magic/version");
        return 2;
    }

    ghostlock::compat::CarrierResult result;
    if (command.mode == static_cast<uint32_t>(ghostlock::compat::CarrierMode::Smoke)) {
        run_smoke(&result);
    } else {
        ghostlock::compat::run_carrier_attempt(command, &result);
    }

    if (!write_all(res_fd, &result, sizeof(result))) {
        say("compat-helper: cannot write result");
        return 2;
    }
    /* A dirty outcome mirrors the native's fail-stop: the caller maps exit 70
     * to RouteResultCode::DirtyFailure and stops the run. */
    if (result.status == 3U) return 70;
    return 0;
}
