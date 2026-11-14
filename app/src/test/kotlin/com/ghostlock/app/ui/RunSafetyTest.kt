package com.ghostlock.app.ui

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The reboot recommendation is a safety net, not a run verdict: it must fire
 * only when a page-free W1 actually changed the policy-capability bytes and
 * the post-root policy load did not repair them.
 */
class RunSafetyTest {
    private val pageFreeW1 = """
        [*] page_free=1 reason=policy+scratch+anchor
        [+] SELinux permissive
    """.trimIndent()

    @Test
    fun completedRunWithLandedFixupDoesNotPrompt() {
        val log = pageFreeW1 + "\n[ksu] [*] policyload before=0 after=2\n[ksu] [*] policy fixup rc=0\n"
        assertFalse(RunSafety.needsRebootPrompt(log, 0))
    }

    @Test
    fun failedNativeAfterPageFreeW1Prompts() {
        assertTrue(RunSafety.needsRebootPrompt(pageFreeW1 + "\nW2: cred attempt 15/15\n", 255))
    }

    @Test
    fun failedFixupPromptsEvenWhenTheNativeExitedZero() {
        /* The myron shape: KernelSU was already loaded, so the run completed
         * and the native exited 0, but the policy dump was unreadable and the
         * caps stayed flipped. */
        val log = pageFreeW1 + "\n[ksu] [*] policy fixup rc=1\n[+] KernelSU ready\n"
        assertTrue(RunSafety.needsRebootPrompt(log, 0))
    }

    @Test
    fun unreadablePolicyDumpPromptsWhenTheRcLineIsLost() {
        /* The warm device run: the ten read errors are in the app log, but
         * the script's rc=1 line is written after the native exits. */
        val log = pageFreeW1 +
            "\n[ksu] [*] fixup: attempt 10\n" +
            "[ksu] cat: /sys/fs/selinux/policy: Invalid argument\n" +
            "[-] enforce=0 (still permissive)\n[+] KernelSU ready\n"
        assertTrue(RunSafety.needsRebootPrompt(log, 0))
    }

    @Test
    fun anEarlyReadErrorWithALandedFixupDoesNotPrompt() {
        val log = pageFreeW1 +
            "\n[ksu] cat: /sys/fs/selinux/policy: Invalid argument\n" +
            "[ksu] [*] policyload before=0 after=2\n[ksu] [*] policy fixup rc=0\n"
        assertFalse(RunSafety.needsRebootPrompt(log, 0))
    }

    @Test
    fun alreadyPermissiveW1StillCounts() {
        val log = "[*] page_free=1 reason=policy+scratch+anchor\n[+] SELinux already permissive\n"
        assertTrue(RunSafety.needsRebootPrompt(log, 1))
    }

    @Test
    fun aPageBasedRunDoesNotPrompt() {
        val log = "[*] page_free=0 reason=policy\n[+] SELinux permissive\n"
        assertFalse(RunSafety.needsRebootPrompt(log, 255))
    }

    @Test
    fun aRunThatNeverReachedW1DoesNotPrompt() {
        assertFalse(RunSafety.needsRebootPrompt("[*] page_free=1 reason=policy+scratch+anchor\n", 1))
    }

    @Test
    fun anErrorExitWithALandedFixupDoesNotPrompt() {
        val log = pageFreeW1 + "\n[ksu] [*] policy fixup rc=0\n"
        assertFalse(RunSafety.needsRebootPrompt(log, 255))
    }
}
