/* Host test for the sigreturn-stamp route's frame geometry and lifecycle.
 *
 * The device half (signal delivery, the re-stamp loop, the race handshake) runs
 * only on Android; what is testable here is the part the route's correctness
 * rests on: where the strip lands inside a delivered sigframe's fpsimd record,
 * which restore path the frame selects, and that the route refuses a geometry
 * it cannot stamp through instead of writing to an unverified depth. */

#include "route/sigreturn_route.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>

using namespace ghostlock;

namespace {
    constexpr std::uint32_t kFpsimdMagic = 0x46508001;
    constexpr std::uint32_t kSveMagic = 0x53564501;
    /* bionic's `ucontext_t.uc_mcontext.__reserved`. */
    constexpr std::size_t kReservedBytes = 4096;

    void put32(std::array<std::byte, kReservedBytes> &frame, std::size_t offset,
               std::uint32_t value) {
        std::memcpy(frame.data() + offset, &value, sizeof(value));
    }

    std::uint64_t get64(const std::array<std::byte, kReservedBytes> &frame,
                        std::size_t offset) {
        std::uint64_t value = 0;
        std::memcpy(&value, frame.data() + offset, sizeof(value));
        return value;
    }

    /* The two frames the kernel builds: a plain one (fpsimd record at 0, then
     * the zero-magic terminator) and an SVE one (the sve record, then the
     * fpsimd record) -- arch/arm64/kernel/signal.c's setup_sigframe. */
    std::array<std::byte, kReservedBytes> plain_frame() {
        std::array<std::byte, kReservedBytes> frame{};
        put32(frame, 0, kFpsimdMagic);
        put32(frame, 4, 0x210);
        return frame;
    }

    std::array<std::byte, kReservedBytes> sve_frame() {
        std::array<std::byte, kReservedBytes> frame{};
        put32(frame, 0, kSveMagic);
        put32(frame, 4, 0x10);
        put32(frame, 0x10, kFpsimdMagic);
        put32(frame, 0x14, 0x210);
        return frame;
    }

    /* An all-keys-stated layout: the route's layout carries the anchor keys as
     * well, and a key set the case does not mean to exercise stays absent. */
    ghostlock::profile::SigreturnLayout layout_with(
        std::optional<std::uint64_t> sve, std::optional<std::uint64_t> plain) {
        ghostlock::profile::SigreturnLayout layout{};
        layout.waiter_off_sve = sve;
        layout.waiter_off_plain = plain;
        return layout;
    }
} // namespace

int32_t main(void) {
    using namespace ghostlock::route;
    using sigreturn::FpState;
    using sigreturn::Geometry;

    /* ---- geometry_from: fail closed on every unusable key set. ---- */
    {
        Geometry geometry{};
        assert(sigreturn::geometry_from(layout_with(0x150, 0x140), &geometry));
        assert(geometry.off_sve == 0x150 && geometry.off_plain == 0x140);

        /* Both the pre-floor (0x150/0x140) and the 5.10.236 (0x100/0xf0)
         * geometries are in band; the largest offset the window can carry is
         * kCopyBytes - kStripBytes = 0x1a8. */
        assert(sigreturn::geometry_from(layout_with(0x100, 0xf0), &geometry));
        assert(sigreturn::geometry_from(layout_with(0x1a8, 0x1a8), &geometry));
        assert(geometry.off_sve == 0x1a8);

        const profile::SigreturnLayout bad_cases[] = {
            layout_with(std::nullopt, std::nullopt),
            layout_with(std::nullopt, 0x140),
            layout_with(0x150, std::nullopt),
            layout_with(0, 0x140),
            layout_with(0x150, 0),
            layout_with(0x151, 0x140),
            layout_with(0x150, 0x144),
            layout_with(0x1b0, 0x140),
        };
        for (const profile::SigreturnLayout &bad : bad_cases) {
            assert(!sigreturn::geometry_from(bad, &geometry));
        }
    }

    /* ---- locate_fpstate: which restore helper the frame selects. ---- */
    {
        const auto plain = plain_frame();
        FpState state{};
        assert(sigreturn::locate_fpstate(plain.data(), plain.size(), &state));
        assert(state.vregs_offset == 0x10 && !state.sve);

        const auto sve = sve_frame();
        assert(sigreturn::locate_fpstate(sve.data(), sve.size(), &state));
        assert(state.vregs_offset == 0x20 && state.sve);

        /* An SVE-only frame has no fpsimd record: the kernel would refuse it
         * too, so the handler must not pretend it found one. */
        auto sve_only = sve_frame();
        put32(sve_only, 0x10, 0);
        assert(!sigreturn::locate_fpstate(sve_only.data(), sve_only.size(), &state));

        /* A record whose size walks off the buffer ends the walk. */
        auto truncated = plain_frame();
        put32(truncated, 4, 0x10000);
        assert(!sigreturn::locate_fpstate(truncated.data(), truncated.size(), &state));

        std::array<std::byte, kReservedBytes> empty{};
        assert(!sigreturn::locate_fpstate(empty.data(), empty.size(), &state));
    }

    /* ---- patch_fpstate: the stamp itself. ---- */
    {
        const Geometry geometry = {.off_sve = 0x150, .off_plain = 0x140};
        const std::uintptr_t target = 0xffffff8000129000ULL;
        const std::uintptr_t fake_task = 0xffffff8800005800ULL;
        const std::uintptr_t anchor = 0xffffff802aa3a590ULL;
        const memory::PayloadWriteLayout layout = {
            .parent = target - 8, .right = 0, .left = 0,
        };
        const memory::WaiterWords words =
            memory::waiter_words(layout, fake_task, anchor, 140);
        std::array<std::byte, sigreturn::kStripBytes> strip{};
        assert(memory::encode_waiter_words(strip, 0, words));

        /* Plain path: the strip lands at vregs (frame +0x10) + off_plain, and
         * nothing else in the frame moves. */
        auto frame = plain_frame();
        const auto untouched = frame;
        bool sve = true;
        assert(sigreturn::patch_fpstate(frame.data(), frame.size(), strip.data(),
                                        strip.size(), geometry, &sve));
        assert(!sve);
        const std::size_t base = 0x10 + 0x140;
        assert(get64(frame, base + 0x00) == target - 8); /* tree_pc: leaf shape */
        assert(get64(frame, base + 0x08) == 0);
        assert(get64(frame, base + 0x10) == 0);
        assert(get64(frame, base + 0x18) == 0); /* pi triple parks */
        assert(get64(frame, base + 0x20) == 0);
        assert(get64(frame, base + 0x28) == 0);
        assert(get64(frame, base + 0x30) == fake_task);
        assert(get64(frame, base + 0x38) == anchor);
        assert(get64(frame, base + 0x40) == 140);
        assert(get64(frame, base + 0x48) == 0);
        assert(get64(frame, base + 0x50) == 0);
        /* Every byte outside the strip is byte-identical to the delivered
         * frame -- the copy's other 0x1a8 bytes come straight from the frame. */
        for (std::size_t i = 0; i < frame.size(); i++) {
            if (i >= base && i < base + strip.size()) continue;
            assert(frame[i] == untouched[i]);
        }

        /* SVE path: same strip, the other offset, and the record after the SVE
         * record found by the walk. */
        auto sve_assert = sve_frame();
        sve = false;
        assert(sigreturn::patch_fpstate(sve_assert.data(), sve_assert.size(), strip.data(),
                                        strip.size(), geometry, &sve));
        assert(sve);
        assert(get64(sve_assert, 0x20 + 0x150 + 0x38) == anchor);

        /* Refusals: a wrong-sized strip, a frame with no fpsimd record, and a
         * placement the copy window cannot hold. */
        bool unused = false;
        assert(!sigreturn::patch_fpstate(frame.data(), frame.size(), strip.data(),
                                         strip.size() - 1, geometry, &unused));
        auto no_fpsimd = plain_frame();
        put32(no_fpsimd, 0, 0);
        assert(!sigreturn::patch_fpstate(no_fpsimd.data(), no_fpsimd.size(), strip.data(),
                                         strip.size(), geometry, &unused));
        const Geometry oversize = {.off_sve = 0x150, .off_plain = 0x1b0};
        assert(!sigreturn::patch_fpstate(frame.data(), frame.size(), strip.data(),
                                         strip.size(), oversize, &unused));
        /* A frame too small for the record it claims is refused, not followed. */
        assert(!sigreturn::patch_fpstate(frame.data(), 0x20, strip.data(), strip.size(),
                                         geometry, &unused));
    }

    /* ---- lifecycle: the parts the host can drive. ---- */
    {
        race::PiRace race;
        assert(race.reset(0, 0, 1));
        const memory::WriteRequest request{};
        const profile::TargetProfile profile{};
        const profile::SigreturnLayout layout = layout_with(0x150, 0x140);
        sigreturn::SigreturnRoute context(&race, &request, profile, layout);
        assert(context.race == &race && context.request == &request);
        assert(&context.profile == &profile);
        assert(context.layout.waiter_off_plain == 0x140);
        assert(context.handler_installed == 0 && context.mask_changed == 0);
        assert(context.stamp_misses == 0 && context.stamps == 0);
        assert(context.status.code == ROUTE_RETRYABLE);

        /* disarm is idempotent and marks the route disarmed; destroy without
         * an installed handler just reports clean. */
        context.disarm();
        context.disarm();
        assert(context.status.kernel_disarmed == 1);
        assert(race.consumer_go.load() == 0);
        context.destroy();
        context.destroy();
        assert(context.status.userspace_clean == 1);
        assert(context.status.code == ROUTE_FALLBACK_SAFE);

        /* fail() records step and errno for the caller's log. */
        assert(context.fail(46, 5) == -1);
        assert(context.status.step == 46 && context.status.error_number == 5);

        /* A stuck consumer is a dirty failure, not a fallback-safe one. */
        race::PiRace stuck_race;
        assert(stuck_race.reset(0, 0, 1));
        stuck_race.consumer_inflight.store(1);
        sigreturn::SigreturnRoute stuck(&stuck_race, &request, profile, layout);
        stuck.consumer_stuck = 1;
        stuck.destroy();
        assert(stuck.status.code == ROUTE_DIRTY_FAILURE);
        assert(stuck.status.step == 38);
        stuck_race.consumer_inflight.store(0);
    }

    puts("sigreturn_route_test: ok");
    return 0;
}
