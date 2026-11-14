package com.ghostlock.app.ui

/**
 * Post-run safety check for the page-free W1.
 *
 * The page-free W1 stores the scratch alias over `selinux_state + 0`. The
 * value is a kernel address, so its bytes 5 and 6 are `0xff`; those bytes are
 * `policycap[3]` (`always_check_network`) and `policycap[4]`
 * (`cgroup_seclabel`). With `always_check_network` on, SELinux runs netif /
 * peer / packet checks the policy has no rules for, and the data path dies
 * until the policy is reloaded. The root script's policy load re-derives the
 * caps from the policy itself; when the run never reached root or the load
 * failed, only a reboot repairs them.
 *
 * The markers are the native's own log lines (the app's log sheet and the run
 * store carry them verbatim):
 *  - `page_free=1` — the profile selected the page-free W1;
 *  - `SELinux permissive` / `SELinux already permissive` — W1 is in effect;
 *  - `policy fixup rc=0` — the post-root policy load landed.
 */
internal object RunSafety {
    fun pageFreeW1Passed(log: String): Boolean =
        log.contains("page_free=1") &&
            (log.contains("SELinux permissive") || log.contains("SELinux already permissive"))

    fun policyFixLanded(log: String): Boolean = log.contains("policy fixup rc=0")

    /**
     * The post-root load failed. The `rc=1` line is written after the ten-attempt
     * loop, which on the warm path can land after the native has already exited;
     * the per-attempt read error is the line the app reliably sees.
     */
    fun policyFixFailed(log: String): Boolean =
        log.contains("policy fixup rc=1") ||
            log.contains("cat: /sys/fs/selinux/policy: Invalid argument")

    /**
     * True when the device was left with the policy-capability bytes changed:
     * page-free W1 passed, the post-root load did not land, and either the
     * native exited with an error or the load itself failed (the myron case,
     * where an already-loaded KernelSU lets the native exit 0).
     */
    fun needsRebootPrompt(log: String, exitCode: Int): Boolean =
        pageFreeW1Passed(log) &&
            !policyFixLanded(log) &&
            (exitCode != 0 || policyFixFailed(log))
}
