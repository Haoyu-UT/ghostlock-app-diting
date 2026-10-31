package com.ghostlock.app.data.profile

import com.ghostlock.app.data.asValueMap
import com.ghostlock.app.data.valueMapOf
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ProfileResolverTest {
    @Test
    fun `nativeValue folds selected cpus into the recommended slots`() {
        val profile = valueMapOf(
            "execution" to valueMapOf("selected_cpus" to valueMapOf("main" to 3)),
        )
        assertEquals(
            3L,
            ProfileResolver.nativeValue(profile, "tcp_zerocopy", "none", "execution.recommended_cpus.main"),
        )
    }

    @Test
    fun `nativeValue maps the branch fields onto route then fallback`() {
        val profile = valueMapOf(
            "route" to valueMapOf("tcp_zerocopy" to valueMapOf("compact_waiter" to 1)),
        )
        assertEquals(1L, ProfileResolver.nativeValue(profile, "tcp_zerocopy", "none", "compact_waiter"))

        val fallbackOnly = valueMapOf(
            "fallback" to valueMapOf(
                "route" to valueMapOf("select_stack" to valueMapOf("waiter_shift" to -2)),
            ),
        )
        assertEquals(
            -2L,
            ProfileResolver.nativeValue(fallbackOnly, "tcp_zerocopy", "select_stack", "pselect_waiter_shift"),
        )
    }

    @Test
    fun `nativeValue maps mcast fields onto the route branch`() {
        val profile = valueMapOf(
            "route" to valueMapOf("multicast_waiter" to valueMapOf("waiter_off" to 96)),
        )
        assertEquals(96L, ProfileResolver.nativeValue(profile, "multicast_waiter", "none", "mcast.waiter_off"))
    }

    @Test
    fun `nativeValue maps the anchor keys onto the multicast route branch`() {
        /* The anchor trio is stated in the route's own section (`mcast.` is
         * only the geometry's lookup prefix; the anchor keys are
         * branch-relative like the select route's). */
        val profile = valueMapOf(
            "route" to valueMapOf(
                "multicast_waiter" to valueMapOf(
                    "lock_anchor_image" to 0x400000,
                    "lock_anchor_bytes" to 0x600,
                    "lock_anchor_stride" to 0x20,
                ),
            ),
        )
        assertEquals(
            0x400000L,
            ProfileResolver.nativeValue(profile, "multicast_waiter", "none", "lock_anchor_image"),
        )
        assertEquals(
            0x600L,
            ProfileResolver.nativeValue(profile, "multicast_waiter", "none", "lock_anchor_bytes"),
        )
        assertEquals(
            0x20L,
            ProfileResolver.nativeValue(profile, "multicast_waiter", "none", "lock_anchor_stride"),
        )

        /* Another route's section is not a source: the decoder never merges
         * across routes, and the resolver must not either. */
        val foreign = valueMapOf(
            "route" to valueMapOf("select_stack" to valueMapOf("lock_anchor_image" to 0x400000)),
        )
        assertEquals(
            null,
            ProfileResolver.nativeValue(foreign, "multicast_waiter", "none", "lock_anchor_image"),
        )

        /* The declared fallback branch is a source, as it is for the other
         * routes' keys. */
        val fallbackOnly = valueMapOf(
            "fallback" to valueMapOf(
                "route" to valueMapOf("multicast_waiter" to valueMapOf("lock_anchor_image" to 0x400000)),
            ),
        )
        assertEquals(
            0x400000L,
            ProfileResolver.nativeValue(fallbackOnly, "tcp_zerocopy", "multicast_waiter", "lock_anchor_image"),
        )
    }

    @Test
    fun `validateMerged rejects an unknown top level key`() {
        val errors = ProfileResolver.validateMerged(validProfile() + ("bogus" to 1L), "select_stack", "none")
        assertTrue(errors.any { it.fieldPath == "bogus" })
    }

    @Test
    fun `validateMerged rejects a missing required task field`() {
        val profile = validProfile()
        profile["task_struct"].asValueMap()!!.remove("prio")
        val errors = ProfileResolver.validateMerged(profile, "select_stack", "none")
        assertTrue(errors.any { it.fieldPath == "task_struct.prio" })
    }

    @Test
    fun `validateMerged reports a missing required cred field`() {
        val profile = validProfile()
        profile["cred"].asValueMap()!!.remove("copy_size")
        val errors = ProfileResolver.validateMerged(profile, "select_stack", "none")
        assertTrue(errors.any { it.fieldPath == "cred.copy_size" && it.message == "missing" })
    }

    @Test
    fun `validateMerged accepts a minimal valid profile`() {
        assertEquals(emptyList<ConfigError>(), ProfileResolver.validateMerged(validProfile(), "select_stack", "none"))
    }

    @Test
    fun `validateMerged accepts the stage-3 layout keys`() {
        val profile = validProfile()
        profile["waiter_layout"] = valueMapOf(
            "compact" to 0,
            "pi_tree" to 40,
            "task" to 80,
            "lock" to 88,
            "wake_state" to 96,
        )
        profile["cred"].asValueMap()!!.apply {
            this["usage_size"] = 8
            this["uid_offset"] = 8
            this["security_offset"] = 128
        }
        profile["kernelsnitch"] = valueMapOf("rt_mutex_size" to 32)
        assertEquals(
            emptyList<ConfigError>(),
            ProfileResolver.validateMerged(profile, "select_stack", "none"),
        )
    }

    @Test
    fun `executionFromMerged flattens nested values`() {
        val profile = valueMapOf(
            "execution" to valueMapOf(
                "stages" to valueMapOf("w1_attempts" to 15),
                "recommended_cpus" to valueMapOf("main" to 0),
            ),
        )
        val flat = ProfileResolver.executionFromMerged(profile)
        assertEquals(15uL, flat["stages.w1_attempts"])
        assertEquals(0uL, flat["recommended_cpus.main"])
    }

    @Test
    fun `layout groups accept the 6,6 and 6,1 BTF shapes`() {
        val sixSix = validProfile()
        sixSix["cred"].asValueMap()!!.apply {
            this["copy_size"] = 136L
            this["caps_offset"] = 48L
            this["usage_size"] = 8L
            this["uid_offset"] = 8L
            this["security_offset"] = 128L
        }
        sixSix["kernelsnitch"] = valueMapOf("rt_mutex_size" to 32L)
        (sixSix["route"].asValueMap()!!["select_stack"].asValueMap()!!)["lock_anchor_stride"] = 32L
        sixSix["waiter_layout"] = valueMapOf(
            "compact" to 0L,
            "pi_tree" to 40L,
            "task" to 80L,
            "lock" to 88L,
            "wake_state" to 96L,
        )
        assertEquals(
            emptyList<ConfigError>(),
            ProfileResolver.validateMerged(sixSix, "select_stack", "none"),
        )

        assertEquals(
            emptyList<ConfigError>(),
            ProfileResolver.validateMerged(sixOneBtfProfile(), "select_stack", "none"),
        )
    }

    @Test
    fun `cred group rejects a copy that does not cover security`() {
        val profile = validProfile()
        profile["cred"].asValueMap()!!.apply {
            this["copy_size"] = 124L
            this["caps_offset"] = 40L
            this["usage_size"] = 4L
            this["uid_offset"] = 4L
            this["security_offset"] = 120L
        }
        val errors = ProfileResolver.validateMerged(profile, "select_stack", "none")
        assertTrue(errors.any { it.fieldPath == "cred.copy_size" })
    }

    @Test
    fun `cred group accepts a 5,x copy that spans the fields after security`() {
        val profile = validProfile()
        profile["cred"].asValueMap()!!.apply {
            this["copy_size"] = 176L
            this["caps_offset"] = 48L
            this["usage_size"] = 4L
            this["uid_offset"] = 4L
            this["security_offset"] = 120L
        }
        /* 5.x has user/user_ns/ucounts/group_info and the rcu head after
         * `security`: sizeof(cred) is 176, not security + 8 = 128. */
        assertEquals(
            emptyList<ConfigError>(),
            ProfileResolver.validateMerged(profile, "select_stack", "none"),
        )
    }

    @Test
    fun `waiter group rejects a compact flag that differs from the route`() {
        val profile = sixOneBtfProfile()
        profile["waiter_layout"].asValueMap()!!["compact"] = 0L
        val errors = ProfileResolver.validateMerged(profile, "select_stack", "none")
        assertTrue(errors.any { it.fieldPath == "waiter_layout.compact" })
    }

    @Test
    fun `waiter group rejects out-of-order offsets`() {
        val profile = sixOneBtfProfile()
        profile["waiter_layout"].asValueMap()!!["task"] = 80L
        val errors = ProfileResolver.validateMerged(profile, "select_stack", "none")
        assertTrue(errors.any { it.fieldPath == "waiter_layout.task" })
    }

    @Test
    fun `rt_mutex group rejects a stride below the object size`() {
        val profile = sixOneBtfProfile()
        val route = profile["route"].asValueMap()!!["select_stack"].asValueMap()!!
        route["lock_anchor_stride"] = 16L
        val errors = ProfileResolver.validateMerged(profile, "select_stack", "none")
        assertTrue(errors.any { it.fieldPath == "route.select_stack.lock_anchor_stride" })
    }

    @Test
    fun `validateMerged accepts the page-free stage-1 blocks`() {
        val profile = validProfile()
        profile["selinux"] = valueMapOf("enforcing" to 0L, "initialized" to 2L)
        profile["w1_scratch"] = valueMapOf("image" to 0x2a3a600L)
        assertEquals(emptyList<ConfigError>(), ProfileResolver.validateMerged(profile, "select_stack", "none"))
        assertEquals(2L, ProfileResolver.nativeValue(profile, "select_stack", "none", "selinux.initialized"))
        assertEquals(0L, ProfileResolver.nativeValue(profile, "select_stack", "none", "selinux.enforcing"))
        assertEquals(0x2a3a600L, ProfileResolver.nativeValue(profile, "select_stack", "none", "w1_scratch.image"))
    }

    @Test
    fun `validateMerged rejects a selinux block that is not the known layout`() {
        val profile = validProfile()
        profile["selinux"] = valueMapOf("enforcing" to 1L, "initialized" to 8L)
        val errors = ProfileResolver.validateMerged(profile, "select_stack", "none")
        assertTrue(errors.any { it.fieldPath == "selinux.enforcing" })
        assertTrue(errors.any { it.fieldPath == "selinux.initialized" })
    }

    @Test
    fun `validateMerged rejects a scratch whose window leaves the anchor region`() {
        val profile = validProfile()
        val route = profile["route"].asValueMap()!!["select_stack"].asValueMap()!!
        route["lock_anchor_image"] = 0x2a3a590L
        route["lock_anchor_bytes"] = 0x1000L
        route["lock_anchor_stride"] = 0x20L
        profile["w1_scratch"] = valueMapOf("image" to 0x2a3a590L + 0xf00L)
        val errors = ProfileResolver.validateMerged(profile, "select_stack", "none")
        assertTrue(errors.any { it.fieldPath == "w1_scratch.image" })
    }

    @Test
    fun `validateMerged accepts a scratch inside the anchor with a fitting window`() {
        val profile = validProfile()
        val route = profile["route"].asValueMap()!!["select_stack"].asValueMap()!!
        route["lock_anchor_image"] = 0x2a3a590L
        route["lock_anchor_bytes"] = 0x1000L
        route["lock_anchor_stride"] = 0x20L
        profile["w1_scratch"] = valueMapOf("image" to 0x2a3a600L)
        assertEquals(emptyList<ConfigError>(), ProfileResolver.validateMerged(profile, "select_stack", "none"))
    }

    private fun sixOneBtfProfile(): MutableMap<String, Any?> {
        val profile = validProfile()
        profile["cred"].asValueMap()!!.apply {
            this["copy_size"] = 128L
            this["caps_offset"] = 40L
            this["usage_size"] = 4L
            this["uid_offset"] = 4L
            this["security_offset"] = 120L
        }
        profile["kernelsnitch"] = valueMapOf("rt_mutex_size" to 32L)
        (profile["route"].asValueMap()!!["select_stack"].asValueMap()!!).apply {
            this["compact_waiter"] = 1L
            this["lock_anchor_stride"] = 32L
        }
        profile["waiter_layout"] = valueMapOf(
            "compact" to 1L,
            "pi_tree" to 24L,
            "task" to 48L,
            "lock" to 56L,
            "wake_state" to 64L,
        )
        return profile
    }

    private fun validProfile(): MutableMap<String, Any?> = valueMapOf(
        "release" to "test",
        "schema_version" to 1,
        "kernel_major" to 6,
        "route" to valueMapOf("select_stack" to valueMapOf("waiter_shift" to 0)),
        "task_struct" to valueMapOf(
            "prio" to 1, "normal_prio" to 1, "sched_task_group" to 1, "pi_lock" to 1,
            "pi_waiters" to 1, "pi_top_task" to 1, "pi_blocked_on" to 1, "pid" to 1,
            "tgid" to 1, "atomic_flags" to 1, "real_cred" to 1, "cred" to 1,
            "comm" to 1, "tasks" to 1, "seccomp" to 1,
        ),
        "cred" to valueMapOf("copy_size" to 136, "caps_count" to 5),
        "offset" to valueMapOf(
            "init_task" to 1, "init_cred" to 1, "root_task_group" to 1, "selinux_enforcing" to 1,
        ),
    )
}
