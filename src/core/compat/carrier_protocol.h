#ifndef GHOSTLOCK_COMPAT_CARRIER_PROTOCOL_H
#define GHOSTLOCK_COMPAT_CARRIER_PROTOCOL_H

/*
 * Wire protocol between the 64-bit native and the armv7 compat carrier helper:
 * one fixed-width command in, one fixed-width result out, over inherited pipe
 * descriptors above the route's fd range.
 *
 * The helper never receives a kernel address it must interpret. The native
 * packs the complete 0x78-byte fd_set bitmap (stamp included) because it owns
 * the profile, the anchor allocator and every 64-bit address computation; the
 * helper only places that bitmap on the compat select stack and runs the race
 * threads. See docs/analysis/compat-select-carrier-plan.md (option B').
 *
 * Both sides are the same repository, so this is a static struct contract, not
 * an extensible format: the magic/version fields make a stale helper refuse
 * instead of misreading a command.
 */

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace ghostlock::compat {
    inline constexpr uint32_t kCommandMagic = 0x31434c47U; /* "GLC1" */
    inline constexpr uint32_t kResultMagic = 0x31524c47U;  /* "GLR1" */
    inline constexpr uint32_t kProtocolVersion = 1U;

    /* nfds is fixed at 320: it keeps the kernel's six bitmaps on the 256-byte
     * stack path (6 * FDS_BYTES(320) = 240 bytes) and gives the measured
     * 0x1e0/0x168 user region the stamp was placed in. */
    inline constexpr uint32_t kCarrierNfds = 320U;
    inline constexpr uint32_t kCarrierWordsPerSet = kCarrierNfds / 32U;
    inline constexpr uint32_t kCarrierBitmapBytes = 3U * kCarrierWordsPerSet * 4U;

    enum class CarrierMode : uint32_t {
        Smoke = 0,
        Run = 1,
    };

    /* Which futex entry the waiter calls. The ABI follows the strip home the
     * profile measured: the 32-bit time ABI (240) enters through
     * __arm64_sys_futex_time32 and puts the strip at 0x1b0; the time64 entry
     * (422) uses __arm64_sys_futex and puts it at 0x1c0. */
    enum class CarrierFutexAbi : uint32_t {
        Time32 = 0,
        Time64 = 1,
    };

    struct CarrierCommand final {
        uint32_t magic = kCommandMagic;
        uint32_t version = kProtocolVersion;
        uint32_t mode = static_cast<uint32_t>(CarrierMode::Smoke);
        uint32_t futex_abi = static_cast<uint32_t>(CarrierFutexAbi::Time32);
        uint32_t nfds = kCarrierNfds;
        uint32_t select_timeout_us = 0;
        uint32_t delay_us = 0;
        uint32_t consumer_max_calls = 0;
        uint32_t consumer_burst_calls = 0;
        uint32_t waiter_cpu = 0;
        uint32_t consumer_cpu = 0;
        uint32_t route_wait_ms = 0;
        uint32_t state_poll_us = 0;
        uint32_t route_done_timeout_ms = 0;
        uint32_t bitmap_bytes = kCarrierBitmapBytes;
        uint32_t setup_settle_us = 0;
        /* in/out/ex, each kCarrierWordsPerSet little-endian 32-bit words. */
        uint8_t bitmap[kCarrierBitmapBytes] = {};
        uint8_t pad[8] = {};
    };

    /* The helper reports the same five RouteStatus fields the 64-bit route
     * produces, plus the counters the stage logs and the smoke results the
     * delivery gate reads. */
    struct CarrierResult final {
        uint32_t magic = kResultMagic;
        uint32_t version = kProtocolVersion;
        uint32_t status = 0; /* ghostlock::route::RouteResultCode */
        int32_t step = 0;
        int32_t error_number = 0;
        int32_t select_result = 0;
        int32_t select_errno = 0;
        int32_t calls = 0;
        int32_t successes = 0;
        int32_t drain_ms = 0;
        uint32_t userspace_clean = 0;
        uint32_t kernel_disarmed = 0;
        /* Smoke mode only: futex, timerfd_create, _newselect, sched_setattr,
         * dup2_high, pipe2, fcntl_high, prctl. A SIGSYS-killed syscall never
         * fills its slot; the native sees the helper die instead. */
        int32_t smoke[8] = {};
        uint32_t reserved = 0;
    };

    static_assert(std::is_standard_layout_v<CarrierCommand>);
    static_assert(std::is_trivially_copyable_v<CarrierCommand>);
    static_assert(offsetof(CarrierCommand, futex_abi) == sizeof(uint32_t) * 3);
    static_assert(offsetof(CarrierCommand, bitmap) == sizeof(uint32_t) * 16);
    static_assert(offsetof(CarrierCommand, pad) == sizeof(uint32_t) * 16 + kCarrierBitmapBytes);
    static_assert(sizeof(CarrierCommand) == sizeof(uint32_t) * 16 + kCarrierBitmapBytes + 8);

    static_assert(std::is_standard_layout_v<CarrierResult>);
    static_assert(std::is_trivially_copyable_v<CarrierResult>);
    static_assert(offsetof(CarrierResult, smoke) == sizeof(uint32_t) * 12);
    static_assert(sizeof(CarrierResult) == sizeof(uint32_t) * 21);
} // namespace ghostlock::compat

#endif
