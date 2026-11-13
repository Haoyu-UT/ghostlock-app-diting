/*
 * DirtyFrag stage verdict parsing.
 *
 * The stage runs the root script over the shell the init stub hands it as
 * `sh root.sh; echo DFRC=$?` and then asks the same shell for the final SELinux
 * state. Both readings go into the RESULT line: a failed root phase (missing
 * ksud, a late-load the vendor gate refused) must not be logged as success just
 * because the shell command returned, and a run that leaves the device
 * permissive is not success either.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

namespace ghostlock::session::dirtyfrag_verdict {
    /* Returns false when the marker is absent or carries no digits — the root
     * script did not finish. The last marker wins: script output cannot contain
     * one, but a combined read may. */
    inline bool parse_script_exit(std::string_view output, int32_t *code) noexcept {
        const std::size_t marker = output.rfind("DFRC=");
        if (marker == std::string_view::npos) return false;
        const std::size_t first = marker + 5U;
        std::size_t end = first;
        while (end < output.size() && output[end] >= '0' && output[end] <= '9') end++;
        if (end == first) return false;
        *code = std::atoi(std::string(output.substr(first, end - first)).c_str());
        return true;
    }

    /* `e=$(cat /sys/fs/selinux/enforce 2>/dev/null); echo "ENFORCE=${e:-unreadable}"`.
     * The state is "1", "0" or "unreadable". */
    inline bool parse_enforce(std::string_view reply, std::string *state) noexcept {
        const std::size_t marker = reply.rfind("ENFORCE=");
        if (marker == std::string_view::npos) return false;
        const std::size_t first = marker + 8U;
        std::size_t end = first;
        while (end < reply.size() && reply[end] != '\r' && reply[end] != '\n') end++;
        if (end == first) return false;
        state->assign(std::string(reply.substr(first, end - first)));
        return true;
    }

    /* The root script's own restore report:
     *   ENFORCE-RESTORE reason=<why> before=<state> wrote=<0|1> readback=<state>
     * A successful write to the enforce node is proof the state is enforcing;
     * on the DirtyFrag shell (toolbox) it is the only proof, because that
     * domain may set the node but not read it. */
    struct EnforceRestore {
        bool present = false;
        bool wrote = false;
        std::string readback;
    };

    inline bool parse_enforce_restore(std::string_view output, EnforceRestore *result) noexcept {
        const std::size_t marker = output.rfind("ENFORCE-RESTORE ");
        if (marker == std::string_view::npos) return false;
        std::size_t end = output.find('\n', marker);
        if (end == std::string_view::npos) end = output.size();
        const std::string_view line = output.substr(marker, end - marker);
        result->present = true;
        result->wrote = line.find("wrote=1") != std::string_view::npos;
        const std::size_t readback = line.find("readback=");
        if (readback != std::string_view::npos) {
            const std::size_t first = readback + 9U;
            std::size_t stop = first;
            while (stop < line.size() && line[stop] != ' ' && line[stop] != '\r') stop++;
            result->readback.assign(std::string(line.substr(first, stop - first)));
        }
        return true;
    }

    /* What the script's report means for the device. A successful write is
     * enforcing. A denied read is enforcing too: SELinux checks are bypassed
     * while permissive, so only an enforcing device can refuse the read (the
     * same convention as the first way's handoff probe). Only a readable "0"
     * is permissive. */
    inline std::string enforce_state_from_restore(const EnforceRestore &restore) {
        if (restore.wrote) return "1";
        if (restore.readback == "1") return "1";
        if (restore.readback == "0") return "0";
        if (restore.readback == "unreadable") return "1";
        return "unknown";
    }
} // namespace ghostlock::session::dirtyfrag_verdict
