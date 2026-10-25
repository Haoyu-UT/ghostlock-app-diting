#ifndef GHOSTLOCK_RUNTIME_CONFIG_H
#define GHOSTLOCK_RUNTIME_CONFIG_H

#include "profile/model.h"


#include <cstdint>
#include <string>
#include <string_view>

namespace ghostlock::config {
    /* User-authoritative tri-state for a vr.ko behaviour. Auto consults the
     * version/probe recommendation; On and Off are final. */
    enum class VrKoMode : uint8_t {
        Auto = 0,
        On = 1,
        Off = 2,
    };

    constexpr const char *vr_ko_mode_name(VrKoMode mode) noexcept {
        switch (mode) {
            case VrKoMode::On: return "on";
            case VrKoMode::Off: return "off";
            case VrKoMode::Auto: break;
        }
        return "auto";
    }

    /* Lenient parser for GHOSTLOCK_VRKO_TAG_CLEAR /
     * GHOSTLOCK_VRKO_SELINUX_BLOCK: on/1/true and off/0/false are the explicit
     * values; anything else is Auto. */
    inline VrKoMode parse_vr_ko_mode(const char *value) noexcept {
        if (value == nullptr) return VrKoMode::Auto;
        const std::string_view v(value);
        if (v == "on" || v == "1" || v == "true") return VrKoMode::On;
        if (v == "off" || v == "0" || v == "false") return VrKoMode::Off;
        return VrKoMode::Auto;
    }

    /* One runtime snapshot captured once from the environment. Paths own their
 * storage; callers convert to c_str() only at syscall/exec boundaries so no
 * temporary string pointer can outlive the snapshot. */
    class RuntimeConfig final {
    public:
        int32_t main_cpu = 0;
        int32_t consumer_cpu = 1;
        std::string home_dir = "/data/local/tmp";
        std::string root_script_path = "/data/local/tmp/.ghostlock_root.sh";
        /* Per-run KernelSU log (U01-S14): Kotlin passes GHOSTLOCK_KSU_LOG so a
   * previous run's markers can never be misread; falls back to the legacy
   * home-dir name for CLI runs. */
        std::string ksu_log_path = "/data/local/tmp/.ghostlock_ksu.log";
        /* Kernel-log dump directory from --dump-kernel-log; empty disables the dump. */
        std::string debug_dir;
        /* The app's run folder from GHOSTLOCK_RUN_DIR (direct entry only); the
         * exporter zips every file in it, so diagnostic sidecars written here
         * travel with the run log. Empty disables the sidecars. */
        std::string run_dir;
        /* GHOSTLOCK_ANCHOR_TRUSTED: the app proved this install's data predates
 * the current boot, so a missing anchor state file means no run has happened
 * since the region was zeroed, and slot 0 is safe. Without it a missing file
 * is refused -- see select_stack_anchor_slot(). */
        bool anchor_trusted = false;

        /* GHOSTLOCK_VRKO_TAG_CLEAR: clear the vendor's per-task tags. Auto asks
         * the backend for the probe/version recommendation; On/Off are final. */
        VrKoMode vrko_tag_clear = VrKoMode::Auto;

        /* GHOSTLOCK_VRKO_SELINUX_BLOCK: block only the /proc/vrp 0/1 enforce
         * write. Auto recommends it only for 5.10.198 + the node. */
        VrKoMode vrko_selinux_block = VrKoMode::Auto;

        RuntimeConfig() noexcept = default;

        /* Capture the process environment exactly once. */
        int32_t init();

        /* Merge the profile's recommended CPU pair (validated). */
        int32_t apply_profile(const ghostlock::profile::TargetProfile *profile);

        void log() const;
    };

    /* The process snapshot is owned by ExploitSession. Callers reach it through
 * this accessor; the public reference alias is gone (CPP12/SESSION-01). */
    RuntimeConfig &runtime_config_snapshot() noexcept;
} // namespace ghostlock::config

#endif
