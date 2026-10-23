// The KernelSnitch leak address grid.
//
// A scan step reaches object j of a slab when it divides j*stride, and reaches
// every object exactly when it divides the stride. The observed family strides
// (960, 1024, 1088, 1216, 1280) are all multiples of 32, so 32 is the primary
// step; 8 is the universal last resort for any 8-aligned object.
#pragma once

#include <cstddef>

namespace ghostlock::kernelsnitch {
    inline constexpr std::size_t SCAN_PRIMARY_INNER = 32;
    inline constexpr std::size_t SCAN_LAST_RESORT_INNER = 8;
    /* 4 KiB instead of the order-3 32 KiB: removes the slab-order assumption
     * from the outer grid without changing the candidate count. */
    inline constexpr std::size_t SCAN_OUTER = 4096;

    constexpr bool scan_step_covers(std::size_t inner, std::size_t stride) {
        return inner != 0 && stride % inner == 0;
    }
} // namespace ghostlock::kernelsnitch
