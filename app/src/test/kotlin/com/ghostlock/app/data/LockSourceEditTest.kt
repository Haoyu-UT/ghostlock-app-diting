package com.ghostlock.app.data

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class LockSourceEditTest {
    private val document = """
        release = "6.1.138-test"
        kernel_major = 6
        cred {
          copy_size = 128
          caps_offset = 40
          caps_count = 5
        }
        route {
          select_stack {
            waiter_shift = -2
            lock_anchor_image = 35947744
            lock_anchor_bytes = 7392
            lock_anchor_stride = 32
          }
        }
        fallback {
          to = "select_stack"
          route {
            select_stack {
              waiter_shift = -2
              lock_anchor_image = 1
              lock_anchor_bytes = 4096
              lock_anchor_stride = 32
            }
          }
        }
    """.trimIndent()

    @Test
    fun `page mode removes every lock anchor branch`() {
        val out = stripLockAnchor(document)
        assertNotNull(out)
        assertFalse(out!!.contains("lock_anchor"))
        assertTrue(out.contains("waiter_shift = -2"))
        assertTrue(out.contains("copy_size = 128"))
        assertTrue(out.contains("fallback"))
    }

    @Test
    fun `a document without an anchor round-trips`() {
        val out = stripLockAnchor(
            """
            release = "5.10.test"
            route {
              select_stack {
                waiter_shift = 0
              }
            }
            """.trimIndent(),
        )
        assertTrue(out!!.contains("waiter_shift = 0"))
        assertFalse(out.contains("lock_anchor"))
    }
}
