/* Host test for the compat select carrier's bitmap packer.
 *
 * The measured geometry (docs/analysis/compat-select-carrier-plan.md): the
 * compat _newselect buffer's deepest byte is 0x1e0 below the entry sp; the
 * stale waiter strip sits at 0x1c0 (time64 chain) or 0x1b0 (time32 chain).
 * The kernel's compat_get_bitmap() packs two user 32-bit words into
 * (l2 << 32) | l1, so a little-endian 8-byte stream at the right offset is
 * exactly the kernel word -- these tests pin the offset, the word order, the
 * zero tail and the fail-closed edges. */

#include "route/compat_bitmap.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <span>

using namespace ghostlock;
using ghostlock::compat::CarrierFutexAbi;
using ghostlock::route::compat::BitmapFitError;
using ghostlock::route::compat::BitmapGeometry;
using ghostlock::route::compat::BitmapPlan;

namespace {
    memory::WaiterWords sample_words() noexcept {
        return memory::WaiterWords{
            .tree_pc = 0xffffff802a3a5908ULL,
            .tree_right = 0,
            .tree_left = 0xffffff802a3a5990ULL,
            .pi_pc = 0,
            .pi_right = 0,
            .pi_left = 0,
            .task = 0xffffff802b1c2e80ULL,
            .lock = 0xffffff802abbe100ULL,
            .prio = 3,
            .deadline = 0,
            .ww_ctx = 0,
        };
    }

    std::array<uint8_t, ghostlock::route::compat::kBitmapBytes> pack(
        const memory::WaiterWords &words, BitmapGeometry geometry,
        BitmapPlan *plan, BitmapFitError *error) noexcept {
        std::array<uint8_t, ghostlock::route::compat::kBitmapBytes> out{};
        const bool ok = ghostlock::route::compat::pack_compat_bitmap(
            words, geometry, std::span<uint8_t>(out), plan, error);
        assert(ok);
        return out;
    }

    uint32_t user_word(const uint8_t *bitmap, uint32_t word) noexcept {
        return static_cast<uint32_t>(bitmap[4U * word]) |
               (static_cast<uint32_t>(bitmap[4U * word + 1]) << 8) |
               (static_cast<uint32_t>(bitmap[4U * word + 2]) << 16) |
               (static_cast<uint32_t>(bitmap[4U * word + 3]) << 24);
    }

    /* What the kernel sees for stamp word `word`: two user words paired. */
    uint64_t kernel_word(const uint8_t *bitmap, uint32_t offset, uint32_t word) noexcept {
        const uint32_t low = user_word(bitmap, (offset + 8U * word) / 4U);
        const uint32_t high = user_word(bitmap, (offset + 8U * word) / 4U + 1U);
        return ghostlock::route::compat::pack_two_user_words(low, high);
    }
} // namespace

int main() {
    using namespace ghostlock::route::compat;

    const memory::WaiterWords words = sample_words();

    /* --- time64: full eleven-word user stamp, exact fit at 0x20 --- */
    {
        BitmapGeometry geometry{.waiter_home = 0x1c0, .select_dst_depth = 0x1e0};
        BitmapPlan plan{};
        BitmapFitError error = BitmapFitError::BufferMismatch;
        const auto bitmap = pack(words, geometry, &plan, &error);
        assert(error == BitmapFitError::None);
        assert(plan.futex_abi == CarrierFutexAbi::Time64);
        assert(plan.offset == 0x20);
        assert(plan.words == 11);
        assert(!plan.zero_tail);
        const std::array<uint64_t, 11> expected = {
            (uint64_t) words.tree_pc, (uint64_t) words.tree_right,
            (uint64_t) words.tree_left, (uint64_t) words.pi_pc,
            (uint64_t) words.pi_right, (uint64_t) words.pi_left,
            (uint64_t) words.task, (uint64_t) words.lock, words.prio,
            words.deadline, words.ww_ctx,
        };
        for (uint32_t word = 0; word < 11; word++) {
            assert(kernel_word(bitmap.data(), plan.offset, word) == expected[word]);
        }
        /* The strip exactly fills the user copy: nothing past 0x78 exists. */
        assert(plan.offset + kStripBytes == kBitmapBytes);
    }

    /* --- one step deeper: the shallow end no longer fits --- */
    {
        BitmapPlan plan{};
        BitmapFitError error = BitmapFitError::None;
        assert(!plan_compat_bitmap(
            BitmapGeometry{.waiter_home = 0x1c0, .select_dst_depth = 0x1e8},
            &plan, &error));
        assert(error == BitmapFitError::TooDeep);
    }

    /* --- time32: nine words at 0x30, zero deadline/ww_ctx tail --- */
    {
        BitmapGeometry geometry{.waiter_home = 0x1b0, .select_dst_depth = 0x1e0};
        BitmapPlan plan{};
        BitmapFitError error = BitmapFitError::BufferMismatch;
        const auto bitmap = pack(words, geometry, &plan, &error);
        assert(error == BitmapFitError::None);
        assert(plan.futex_abi == CarrierFutexAbi::Time32);
        assert(plan.offset == 0x30);
        assert(plan.words == 9);
        assert(plan.zero_tail);
        const std::array<uint64_t, 9> expected = {
            (uint64_t) words.tree_pc, (uint64_t) words.tree_right,
            (uint64_t) words.tree_left, (uint64_t) words.pi_pc,
            (uint64_t) words.pi_right, (uint64_t) words.pi_left,
            (uint64_t) words.task, (uint64_t) words.lock, words.prio,
        };
        for (uint32_t word = 0; word < 9; word++) {
            assert(kernel_word(bitmap.data(), plan.offset, word) == expected[word]);
        }
        /* The tail is what the kernel zeroes: the user bitmap must carry no
         * bytes past the ninth word (0x30 + 0x48 = 0x78 is the end). */
        assert(plan.offset + 9U * 8U == kBitmapBytes);
        for (size_t i = plan.offset + 9U * 8U; i < bitmap.size(); i++) {
            assert(bitmap[i] == 0);
        }
    }

    /* --- time32 refuses a non-zero deadline or ww_ctx --- */
    {
        memory::WaiterWords dirty = words;
        dirty.deadline = 1;
        std::array<uint8_t, kBitmapBytes> out{};
        BitmapPlan plan{};
        BitmapFitError error = BitmapFitError::None;
        assert(!pack_compat_bitmap(
            dirty, BitmapGeometry{.waiter_home = 0x1b0, .select_dst_depth = 0x1e0},
            std::span<uint8_t>(out), &plan, &error));
        assert(error == BitmapFitError::NonZeroTail);
        dirty = words;
        dirty.ww_ctx = 0x8000000000000000ULL;
        error = BitmapFitError::None;
        assert(!pack_compat_bitmap(
            dirty, BitmapGeometry{.waiter_home = 0x1b0, .select_dst_depth = 0x1e0},
            std::span<uint8_t>(out), &plan, &error));
        assert(error == BitmapFitError::NonZeroTail);
    }

    /* --- 5.10.236: the strip is deeper than the buffer, refuse --- */
    {
        BitmapPlan plan{};
        BitmapFitError error = BitmapFitError::None;
        assert(!plan_compat_bitmap(
            BitmapGeometry{.waiter_home = 0x200, .select_dst_depth = 0x1e0},
            &plan, &error));
        assert(error == BitmapFitError::HomeBelowDepth);
        error = BitmapFitError::None;
        assert(!plan_compat_bitmap(
            BitmapGeometry{.waiter_home = 0x210, .select_dst_depth = 0x1e0},
            &plan, &error));
        assert(error == BitmapFitError::HomeBelowDepth);
    }

    /* --- an unknown home is refused, not guessed at --- */
    {
        BitmapPlan plan{};
        BitmapFitError error = BitmapFitError::None;
        assert(!plan_compat_bitmap(
            BitmapGeometry{.waiter_home = 0x1c8, .select_dst_depth = 0x1e8},
            &plan, &error));
        assert(error == BitmapFitError::UnknownHome);
    }

    /* --- time32 tail outside the kernel's res_* window --- */
    {
        BitmapPlan plan{};
        BitmapFitError error = BitmapFitError::None;
        assert(!plan_compat_bitmap(
            BitmapGeometry{.waiter_home = 0x1b0, .select_dst_depth = 0x1d0},
            &plan, &error));
        assert(error == BitmapFitError::ZeroWindow);
    }

    /* --- wrong output length --- */
    {
        std::array<uint8_t, kBitmapBytes - 1> out{};
        BitmapFitError error = BitmapFitError::None;
        assert(!pack_compat_bitmap(
            words, BitmapGeometry{.waiter_home = 0x1c0, .select_dst_depth = 0x1e0},
            std::span<uint8_t>(out), nullptr, &error));
        assert(error == BitmapFitError::BufferMismatch);
    }

    /* --- the ABI map is exactly the measured family --- */
    assert(abi_for_waiter_home(0x1b0) == CarrierFutexAbi::Time32);
    assert(abi_for_waiter_home(0x1c0) == CarrierFutexAbi::Time64);
    assert(!abi_for_waiter_home(0x1a0));
    assert(!abi_for_waiter_home(0x200));
    return 0;
}
