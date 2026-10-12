#ifndef LOCK_ANCHOR_H
#define LOCK_ANCHOR_H

/* The lock-anchor slot grid: the zero, writable, reference-free kernel region
 * the walk's fake `rt_mutex` lives in, plus the boot-scoped allocator that
 * hands out non-overlapping slots in it.
 *
 * Every stack-stamp route that points the fake waiter's `lock` word at an
 * anchor (rather than at the reclaimed payload page) must use the same grid
 * and the same allocation serial: the region is one shared kernel object, so
 * two routes drawing slots independently would hand out the same slot twice in
 * one boot and walk a slot the other route already poisoned. The API here is
 * the single drawing point; `route/select_stack_route.cpp` and
 * `route/sigreturn_route.cpp` both call it.
 *
 * Implementation (and every log line the analysis record quotes) lives in
 * lock_anchor.cpp, Android-only: it reads the profile-relative image offset,
 * converts through the measured KASLR slide and persists the boot-scoped
 * reservation file. */

#include <cstdint>
#include <optional>

namespace ghostlock::route::anchor {
    /* The grid one kernel build describes: `bytes` of usable region at `stride`
     * per slot. `slots == bytes / stride`. */
    struct Geometry final {
        std::uintptr_t stride = 0;
        std::uintptr_t bytes = 0;
        std::uintptr_t slots = 0;
    };

    /* Resolve the grid from the profile keys, take this boot's next pristine
     * slot and return the direct-map address of that slot -- the value the
     * waiter's `lock` word carries. `image` is the region's image-relative
     * offset (the caller has already established it is present); `slot_out`
     * receives the slot index for the caller's log.
     *
     * Returns 0 on every failure -- a contradictory grid, a spent boot budget
     * or an unrecordable reservation -- and logs why. A caller that gets 0 must
     * fail the route: the only alternatives are walking a neighbour slot or
     * walking past the zeroed region, and both are kernel crashes. */
    [[nodiscard]] std::uintptr_t acquire_lock_word(
        std::uint64_t image, std::optional<std::uint64_t> bytes,
        std::optional<std::uint64_t> stride, int32_t attempt,
        std::uintptr_t *slot_out) noexcept;
} // namespace ghostlock::route::anchor

#endif
