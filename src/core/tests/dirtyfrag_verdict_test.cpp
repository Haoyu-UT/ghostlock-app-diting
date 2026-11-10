/* Host fixed-vector test for the DirtyFrag stage verdict parsing.
 *
 * `DFRC=` carries the root script's exit code and `ENFORCE=` carries the final
 * SELinux state read back over the root shell. A missing marker, a split
 * marker/value pair and a non-numeric value must all keep the verdict honest
 * instead of being read as success. */

#include "../session/dirtyfrag_verdict.hpp"

#include <cstdint>
#include <cstdio>
#include <string>

int32_t main(void) {
    using ghostlock::session::dirtyfrag_verdict::parse_enforce;
    using ghostlock::session::dirtyfrag_verdict::parse_script_exit;
    int32_t failures = 0;
    const auto check = [&failures](bool ok, const char *what, const char *detail) {
        if (!ok) {
            std::printf("FAIL: %s (%s)\n", what, detail);
            failures++;
        }
    };

    struct ScriptVector {
        const char *output;
        bool parsed;
        int32_t code;
    } scripts[] = {
        {"DFRC=0\n", true, 0},
        {"[ksu] log lines\nDFRC=1\n", true, 1},
        {"DFRC=137", true, 137},
        {"DFRC=", false, 0},
        {"[ksu] no exit marker here\n", false, 0},
        {"DFRC= not a number", false, 0},
    };
    for (const auto &vector : scripts) {
        int32_t code = -1;
        const bool parsed = parse_script_exit(vector.output, &code);
        check(parsed == vector.parsed, "script parse status", vector.output);
        check(!parsed || code == vector.code, "script exit code", vector.output);
    }

    struct EnforceVector {
        const char *reply;
        bool parsed;
        const char *state;
    } enforces[] = {
        {"ENFORCE=1\n", true, "1"},
        {"ENFORCE=0\r\n", true, "0"},
        {"ENFORCE=unreadable\n", true, "unreadable"},
        {"ENFORCE=", false, ""},
        {"no state marker\n", false, ""},
    };
    for (const auto &vector : enforces) {
        std::string state;
        const bool parsed = parse_enforce(vector.reply, &state);
        check(parsed == vector.parsed, "enforce parse status", vector.reply);
        check(!parsed || state == vector.state, "enforce state", vector.reply);
    }

    /* A leftover newline from the DFRC line and the probe reply can arrive in
     * one read; the parser must take the ENFORCE value, not the stale byte. */
    std::string state;
    check(parse_enforce("0\nENFORCE=1\n", &state) && state == "1",
          "enforce after leftover", "0\\nENFORCE=1");

    /* The script's restore report: a successful write is the fact; a failed
     * write falls back to the readback, and neither confirming is "unknown". */
    using ghostlock::session::dirtyfrag_verdict::EnforceRestore;
    using ghostlock::session::dirtyfrag_verdict::enforce_state_from_restore;
    using ghostlock::session::dirtyfrag_verdict::parse_enforce_restore;
    struct RestoreVector {
        const char *output;
        bool present;
        const char *state;
    } restores[] = {
        {"x\nENFORCE-RESTORE reason=already-loaded before=0 wrote=1 readback=unreadable\nDFRC=0\n",
         true, "1"},
        {"ENFORCE-RESTORE reason=fixup-failed before=0 wrote=0 readback=0\n", true, "0"},
        /* A denied read is enforcing (permissive cannot deny); the OnePlus
         * late-load path reads and writes nothing but is already enforcing. */
        {"ENFORCE-RESTORE reason=late-loaded before=unreadable wrote=0 readback=unreadable\n",
         true, "1"},
        {"ENFORCE-RESTORE reason=ksud-missing before=0 wrote=0 readback=1\n", true, "1"},
        {"ENFORCE-RESTORE reason=ksud-missing before=0 wrote=0\n", true, "unknown"},
        {"nothing here\n", false, ""},
    };
    for (const auto &vector : restores) {
        EnforceRestore restore;
        const bool present = parse_enforce_restore(vector.output, &restore);
        check(present == vector.present, "restore parse status", vector.output);
        check(!present || enforce_state_from_restore(restore) == vector.state,
              "restore state", vector.output);
    }

    if (failures == 0) std::printf("dirtyfrag_verdict_test: ok\n");
    return failures == 0 ? 0 : 1;
}
