/* Host test for the slab-stride verifier.
 *
 * The clean-line leaks are the control: the five recorded offsets identify
 * 960 and leave only partial votes for 1088/1280. The test also pins the
 * no-threshold contract (every candidate with a vote is reported), the
 * zero-offset rule, the sizeof floor and the early-stop decision.
 */
#include "../kernelsnitch/stride_verify.h"

#include <cassert>
#include <cstddef>

using ghostlock::kernelsnitch::STRIDE_MAX_ROUNDS;
using ghostlock::kernelsnitch::StrideVerifier;

int main() {
    /* The window is the 64-multiple grid inside [800, 1400]. */
    {
        StrideVerifier v;
        assert(v.window_size() == 9);
        assert(v.window_value(0) == 832);
        assert(v.window_value(8) == 1344);
        assert(!v.any_votes());
        assert(!v.decided());
    }

    /* The clean-line offsets: 960 wins every nonzero round; 1088 and 1280
     * keep their partial votes and stay in the table. */
    {
        StrideVerifier v;
        const std::size_t offsets[] = {0x3fc0, 0x1e00, 0, 0x7bc0, 0x3fc0};
        for (std::size_t o : offsets) assert(v.add_offset(o));
        assert(v.rounds() == 5);
        assert(v.samples() == 4);
        assert(v.gcd() == 960);
        assert(v.voted_count() == 3);
        assert(v.voted(0).value == 960 && v.voted(0).votes == 4);
        assert(v.voted(1).value == 1088 && v.voted(1).votes == 2);
        assert(v.voted(2).value == 1280 && v.voted(2).votes == 1);
        assert(v.decided());
        assert(v.best_value() == 960);
        assert(v.best_votes() == 4);
    }

    /* One leak at object 17 leaves 960 and 1088 both unanimous; the second
     * leak (object 8) kills 1088. */
    {
        StrideVerifier v;
        assert(v.add_offset(0x3fc0));
        assert(v.samples() == 1);
        assert(!v.decided());
        assert(v.voted_count() == 2);
        assert(v.voted(0).value == 960 && v.voted(1).value == 1088);
        assert(v.add_offset(0x1e00));
        assert(v.decided());
        assert(v.best_value() == 960);
        assert(v.best_votes() == 2);
        assert(v.votes_for(1088) == 1);
    }

    /* A slab-base leak (offset 0) votes for nothing and is not a sample. */
    {
        StrideVerifier v;
        assert(v.add_offset(0));
        assert(v.rounds() == 1);
        assert(v.samples() == 0);
        assert(!v.any_votes());
        assert(v.gcd() == 0);
        assert(!v.decided());
    }

    /* sizeof(mm_struct) floors the window. */
    {
        StrideVerifier v(0x3c0); /* 960 */
        assert(v.window_size() == 7);
        assert(v.window_value(0) == 960);
        assert(v.window_value(6) == 1344);
    }
    {
        StrideVerifier v(992); /* 0x3e0: the first 64-multiple is 1024. */
        assert(v.window_size() == 6);
        assert(v.window_value(0) == 1024);
    }
    {
        StrideVerifier v(1408); /* beyond the window */
        assert(v.window_size() == 0);
        assert(!v.any_votes());
    }

    /* The round cap. */
    {
        StrideVerifier v;
        for (std::size_t i = 0; i < STRIDE_MAX_ROUNDS; ++i)
            assert(v.add_offset(960));
        assert(!v.add_offset(960));
        assert(v.rounds() == STRIDE_MAX_ROUNDS);
        assert(v.decided());
    }

    /* One sample is below the consistency floor even when only one candidate
     * divides it (the device probe's first round was exactly this shape:
     * offset 0xb40 = 3 * 960). */
    {
        StrideVerifier v;
        assert(v.add_offset(0xb40));
        assert(v.voted_count() == 1);
        assert(v.voted(0).value == 960 && v.voted(0).votes == 1);
        assert(!v.decided());
        assert(v.add_offset(0x1e00)); /* 8 * 960 */
        assert(v.decided());
        assert(v.best_value() == 960 && v.best_votes() == 2);
    }

    /* No vote threshold filters the table: one round votes for both 960 and
     * 1280, and both are reported for the user's pick. */
    {
        StrideVerifier v;
        assert(v.add_offset(7680)); /* 8 * 960; also 6 * 1280 */
        assert(v.voted_count() == 2);
        assert(v.voted(0).value == 960 && v.voted(1).value == 1280);
        assert(!v.decided());
    }

    return 0;
}
