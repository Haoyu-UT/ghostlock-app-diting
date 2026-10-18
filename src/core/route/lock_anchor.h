#ifndef LOCK_ANCHOR_H
#define LOCK_ANCHOR_H

/* The lock-anchor grid and its boot-scoped allocator, shared by every
 * stack-stamp route so one serial hands out each boot's slots. */

#include <cstdint>
#include <optional>

namespace ghostlock::route::anchor {
    struct Geometry final {
        std::uintptr_t stride = 0;
        std::uintptr_t bytes = 0;
        std::uintptr_t slots = 0;
    };

    /* Take this boot's next pristine slot and return the direct-map lock word
     * for it. 0 means the caller must fail the route, never walk a neighbour. */
    [[nodiscard]] std::uintptr_t acquire_lock_word(
        std::uint64_t image, std::optional<std::uint64_t> bytes,
        std::optional<std::uint64_t> stride, int32_t attempt,
        std::uintptr_t *slot_out) noexcept;
} // namespace ghostlock::route::anchor

#endif
