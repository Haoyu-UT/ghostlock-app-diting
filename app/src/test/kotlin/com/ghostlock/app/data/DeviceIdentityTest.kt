package com.ghostlock.app.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The profile write key is the first non-generic identity in the order the app
 * uses — Build.DEVICE, vendor device, boot-image device. On `myron`
 * `Build.DEVICE=myron` while the vendor property is `mivendor`; on the mainline
 * `spinel` `Build.DEVICE=missi` while the vendor is `spinel`. When every
 * candidate is a mainline/vendor placeholder the caller writes a v1 all-device
 * profile instead of a fake key.
 */
class DeviceIdentityTest {
    @Test
    fun `Build DEVICE wins when it is the unique codename`() {
        assertEquals(
            "myron",
            DeviceIdentity.chooseProfileKey(listOf("myron", "mivendor", "mivendor")),
        )
        assertEquals(
            "myron",
            DeviceIdentity.chooseProfileKey(listOf("myron", "mivendor_mt6991", "myron")),
        )
        assertEquals(
            "diting",
            DeviceIdentity.chooseProfileKey(listOf("diting", "diting", "generic_arm64")),
        )
        assertEquals(
            "duchamp",
            DeviceIdentity.chooseProfileKey(listOf("duchamp", "duchamp", "missi")),
        )
    }

    @Test
    fun `mainline Build DEVICE falls through to the vendor codename`() {
        assertEquals(
            "spinel",
            DeviceIdentity.chooseProfileKey(listOf("missi", "spinel", "spinel")),
        )
    }

    @Test
    fun `all-generic identities have no profile key`() {
        assertNull(
            DeviceIdentity.chooseProfileKey(
                listOf("missi", "mgvi_64_armv82", "generic_arm64"),
            ),
        )
        assertNull(
            DeviceIdentity.chooseProfileKey(
                listOf("ossi", "qssi_64", "mivendor"),
            ),
        )
    }

    @Test
    fun `names are trimmed and empties skipped`() {
        assertEquals("myron", DeviceIdentity.chooseProfileKey(listOf("", " myron ")))
    }

    @Test
    fun `the generic set is the observed mainline and vendor names`() {
        assertTrue(DeviceIdentity.isGenericIdentity("missi"))
        assertTrue(DeviceIdentity.isGenericIdentity("mivendor"))
        assertTrue(DeviceIdentity.isGenericIdentity("mivendor_mt6789"))
        assertTrue(DeviceIdentity.isGenericIdentity("MGVI_64_ARMV82"))
        assertTrue(DeviceIdentity.isGenericIdentity("generic_arm64"))
        assertTrue(DeviceIdentity.isGenericIdentity("ossi"))
        assertTrue(DeviceIdentity.isGenericIdentity("qssi_64"))
        assertTrue(DeviceIdentity.isGenericIdentity("alps"))
        assertTrue(DeviceIdentity.isGenericIdentity(" generic "))
        assertFalse(DeviceIdentity.isGenericIdentity("myron"))
        assertFalse(DeviceIdentity.isGenericIdentity("spinel"))
        assertFalse(DeviceIdentity.isGenericIdentity("diting"))
        assertFalse(DeviceIdentity.isGenericIdentity("duchamp"))
    }
}
