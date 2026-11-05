package com.ghostlock.app.data

import android.app.Application
import androidx.core.content.edit
import com.ghostlock.app.data.profile.PerDevicePhys
import com.ghostlock.app.domain.model.CpuPair
import com.ghostlock.app.domain.model.ProfileConfig
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/**
 * The bundled 5.10 profiles leave their timing null and their physical pair in
 * a per-device map. The app must supply the measured diting defaults only on a
 * diting, and the generic tuning everywhere else.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class DeviceDefaultsTest {
    private val context: Application = RuntimeEnvironment.getApplication()
    private val release = "5.10.198-android12-9-00085-g226a9632f13d-ab11136126"

    private fun controller(device: String): AndroidProfileConfigController =
        AndroidProfileConfigController(
            context = context,
            externalProfiles = FakeExternalProfileStore(),
            preferences = context.getSharedPreferences("device-defaults", 0)
                .also { it.edit().clear().commit() },
            deviceCodename = device,
        )

    private fun value(config: ProfileConfig, path: String): Long =
        config.general.first { it.path == path }.value

    @Test
    fun `diting gets the measured route timing`() = runBlocking {
        val config = controller("diting").load(release, CpuPair(4, 5))
        assertEquals(30L, value(config, "execution.race.route_wait_ms"))
        assertEquals(10000L, value(config, "execution.race.setup_settle_us"))
        assertEquals(5000L, value(config, "execution.routes.select_stack.enter_delay_us"))
    }

    @Test
    fun `a device without an entry gets the generic timing`() = runBlocking {
        val config = controller("not-diting").load(release, CpuPair(0, 1))
        assertEquals(1000L, value(config, "execution.race.route_wait_ms"))
        assertEquals(50000L, value(config, "execution.race.setup_settle_us"))
        assertEquals(50000L, value(config, "execution.routes.select_stack.enter_delay_us"))
    }

    @Test
    fun `the bundled physical maps resolve diting, yunluo and rubens`() {
        val releases = listOf(
            release,
            "5.10.209-android12-9-00019-g4ea09a298bb4-ab12292661",
        )
        for (r in releases) {
            val text = AssetConfigLoader(context).load("kernel_profiles/$r.conf")
            val document = HoconSupport.parseValue(text).asValueMap()
                ?: error("$r is not an object")
            val diting = PerDevicePhys.resolve(document, "diting")
            val yunluo = PerDevicePhys.resolve(document, "yunluo")
            val rubens = PerDevicePhys.resolve(document, "rubens")
            assertEquals(2818572288L, diting["kernel_phys_load"])
            assertEquals(2147483648L, diting["kernel_phys_offset"])
            assertEquals(1073741824L, yunluo["kernel_phys_load"])
            assertEquals(1073741824L, yunluo["kernel_phys_offset"])
            assertEquals(1073741824L, rubens["kernel_phys_load"])
            assertEquals(1073741824L, rubens["kernel_phys_offset"])
            assertNull(PerDevicePhys.resolve(document, "some-other-device")["kernel_phys_load"])
        }
    }

    @Test
    fun `the measured 6x device maps resolve`() {
        val cases = mapOf(
            "6.1.138-android14-11-g44bda9e8f6e9-ab13792638" to
                Triple("duchamp", 1073741824L, 1073741824L),
            "6.12.30-android16-5-g6e872b4863d6-ab13847919-4k" to
                Triple("spinel", 1073741824L, 1073741824L),
            "6.6.89-android15-8-g5a0ffb447c1d-ab13771415-4k" to
                Triple("dew", 1074266112L, 1073741824L),
        )
        for ((r, spec) in cases) {
            val (device, load, offset) = spec
            val text = AssetConfigLoader(context).load("kernel_profiles/$r.conf")
            val document = HoconSupport.parseValue(text).asValueMap()
                ?: error("$r is not an object")
            val resolved = PerDevicePhys.resolve(document, device)
            assertEquals("$r $device load", load, resolved["kernel_phys_load"])
            assertEquals("$r $device offset", offset, resolved["kernel_phys_offset"])
        }
    }

    @Test
    fun `the vendor-device alias resolves the spinel map when Build_DEVICE is missi`() = runBlocking {
        val spinelRelease = "6.12.30-android16-5-g6e872b4863d6-ab13847919-4k"
        val controller = AndroidProfileConfigController(
            context = context,
            externalProfiles = FakeExternalProfileStore(),
            preferences = context.getSharedPreferences("device-defaults-alias", 0)
                .also { it.edit().clear().commit() },
            deviceCodename = "missi",
            deviceAliases = listOf("spinel"),
        )
        val config = controller.load(spinelRelease, CpuPair(0, 1))
        assertEquals(1073741824L, config.physLoad)
        assertEquals(1073741824L, config.physOffset)
    }
}
