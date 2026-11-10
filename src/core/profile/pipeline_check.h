/* The wire `meta.pipeline` cross-check.
 *
 * The app resolves the profile's ordered pipeline list to one entry before W1
 * and writes it into the binary document. The native must be invoked in the
 * matching mode: a resolved DirtyFrag run is the `--w1-only` invocation (the
 * DirtyFrag stage follows as its own process), and a resolved GhostLock run is
 * the full chain. A mismatch means the two sides disagree about the run's
 * shape, so the native refuses rather than runs the wrong one.
 *
 * Header-only so the host test exercises the exact policy main.cpp applies. */

#pragma once

#include <cstdint>
#include <optional>

namespace ghostlock::profile {
    /* Wire values of `meta.pipeline`; NativeProfile.kt mirrors them. */
    constexpr uint32_t kPipelineGhostlock = 1;
    constexpr uint32_t kPipelineDirtyfrag = 2;

    enum class PipelineCheck {
        /* The document predates the cross-check; keep the legacy behaviour. */
        NotDeclared,
        Match,
        Mismatch,
        /* A value this build does not know: refuse rather than guess. */
        Unknown,
    };

    constexpr PipelineCheck check_pipeline(std::optional<uint32_t> declared,
                                           bool w1_only) noexcept {
        if (!declared.has_value()) return PipelineCheck::NotDeclared;
        if (*declared != kPipelineGhostlock && *declared != kPipelineDirtyfrag) {
            return PipelineCheck::Unknown;
        }
        const bool dirtyfrag = *declared == kPipelineDirtyfrag;
        return dirtyfrag == w1_only ? PipelineCheck::Match : PipelineCheck::Mismatch;
    }
}
