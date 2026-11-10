/* Host fixed-vector test for the lock-anchor alignment rule.
 *
 * The walk reads the anchor word with an acquire load (`ldar`), which faults on
 * arm64 unless the address is 8-byte aligned. The 5.10.43 anchor is the
 * measured counter-example: `dump_skip.zeroes` sits at `...953c`, the walk
 * data-aborts in `rt_mutex_adjust_prio_chain`, and the aligned base `...9540`
 * passes under QEMU. The allocator must refuse a misaligned image base or
 * stride instead of handing the walk an address that faults. */

#include "../route/lock_anchor.h"

#include <cstdint>
#include <cstdio>

int32_t main(void) {
    using ghostlock::route::anchor::geometry_aligned;
    int32_t failures = 0;
    struct Vector {
        std::uint64_t image;
        std::uintptr_t stride;
        bool aligned;
        const char *what;
    } vectors[] = {
        /* The six compat/store anchors and the diting are 8-aligned. */
        {0x2c46940, 0x20, true, "5.10.43 after the round-up"},
        {0x2a3a590, 0x20, true, "diting 5.10.236"},
        /* The measured crash: the raw 5.10.43 symbol and its +4 sibling. */
        {0x2c4693c, 0x20, false, "5.10.43 raw (ldar data abort)"},
        {0x2a3a594, 0x20, false, "4-aligned image"},
        /* A stride that is not a multiple of 8 misaligns every slot after 0. */
        {0x2c46940, 0x24, false, "unaligned stride"},
        {0x2c46940, 0x10, true, "small but aligned stride"},
    };
    for (const auto &vector : vectors) {
        const bool got = geometry_aligned(vector.image, vector.stride);
        if (got != vector.aligned) {
            std::printf("FAIL: %s (image=0x%llx stride=0x%llx) expected %d got %d\n",
                        vector.what, static_cast<unsigned long long>(vector.image),
                        static_cast<unsigned long long>(vector.stride),
                        vector.aligned ? 1 : 0, got ? 1 : 0);
            failures++;
        }
    }
    if (failures == 0) std::printf("anchor_align_test: ok\n");
    return failures == 0 ? 0 : 1;
}
