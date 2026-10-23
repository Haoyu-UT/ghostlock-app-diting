/* Host test for the KernelSnitch scan-grid coverage arithmetic.
 *
 * This is the claim the stride-agnostic leak rests on: a step divides every
 * object position exactly when it divides the true stride. The observed
 * family strides must all be covered by the primary step (32); 8 is the
 * universal fallback for any 8-aligned object.
 */
#include "../kernelsnitch/scan_grid.h"

#include <cassert>
#include <cstddef>

using ghostlock::kernelsnitch::scan_step_covers;

int main() {
    constexpr std::size_t strides[] = {960, 1024, 1088, 1216, 1280};
    for (std::size_t stride : strides) {
        assert(scan_step_covers(32, stride));
        assert(scan_step_covers(8, stride));
    }

    /* A step that does not divide the stride leaves object j=1 unreachable,
     * so no set of such steps can be a coverage guarantee. */
    assert(!scan_step_covers(960, 1088));
    assert(!scan_step_covers(1024, 1088));
    assert(!scan_step_covers(1280, 1088));

    /* Every 8-aligned object is reachable with the universal step. */
    for (std::size_t stride = 8; stride <= 4096; stride += 8)
        assert(scan_step_covers(8, stride));

    /* The grid arithmetic, stated directly: with inner dividing stride, every
     * j*stride is a multiple of inner. */
    for (std::size_t stride : strides) {
        const std::size_t objects = 32768 / stride;
        for (std::size_t j = 0; j < objects; ++j)
            assert(((j * stride) % 32) == 0);
    }
    return 0;
}
