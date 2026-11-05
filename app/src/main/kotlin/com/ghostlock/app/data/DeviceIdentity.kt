package com.ghostlock.app.data

import android.annotation.SuppressLint
import android.os.Build

/**
 * Device identities used to look up the per-device physical pair and timing.
 *
 * `Build.DEVICE` (`ro.product.device`) is normally the unique codename, but on
 * MediaTek mainline builds it can be a generic identity: the Redmi Note 15 4G
 * (`spinel`) reports `ro.product.device=missi`, while the unique hardware
 * codename is `ro.product.vendor.device=spinel` (and the boot image's
 * `ro.product.bootimage.device=spinel`). The lookup therefore tries the
 * canonical identity first and falls back to the vendor and boot-image
 * identities.
 *
 * The identity *written* into a generated profile must be the unique codename.
 * The live/package evidence makes `Build.DEVICE` the best first source: it is
 * the codename on diting/duchamp/myron/OnePlus/Nubia/Asus/tegu and on every
 * store package except the mainline `spinel` (which reports `missi`); the
 * vendor property is right on spinel but generic on `myron` (`mivendor`), and
 * the boot-image property is generic on the diting (`generic_arm64`) and the
 * duchamp (`missi`). The order is therefore `Build.DEVICE`, vendor, boot image,
 * skipping the observed mainline/vendor placeholders (`missi`, `generic*`,
 * `generic_arm64`, `mivendor*`, `mgvi_*`, `ossi*`, `qssi*`, `alps*`,
 * `mainline*`, `unknown*`). When every candidate is a placeholder there is no
 * unique key: the caller writes a v1 all-device profile rather than inventing
 * one.
 */
internal object DeviceIdentity {
    @SuppressLint("PrivateApi")
    fun systemProperty(key: String): String = try {
        val properties = Class.forName("android.os.SystemProperties")
        properties.getMethod("get", String::class.java).invoke(null, key) as? String ?: ""
    } catch (_: Throwable) {
        ""
    }

    /** The fallback identities, in priority order. */
    fun aliases(): List<String> = listOf(
        systemProperty("ro.product.vendor.device"),
        systemProperty("ro.product.bootimage.device"),
    ).map { it.trim() }.filter { it.isNotEmpty() }.distinct()

    /** The primary identity followed by the fallbacks, deduplicated. */
    fun candidates(primary: String?, aliases: List<String>): List<String> =
        (listOfNotNull(primary?.trim()) + aliases.map { it.trim() })
            .filter { it.isNotEmpty() }
            .distinct()

    /**
     * Mainline/vendor image names observed in the corpus, as prefixes:
     * `missi` (MTK mainline product), `generic`/`generic_arm64` (AOSP
     * placeholders, the diting/diting boot image), `mivendor*`/`mgvi_*`/`alps*`
     * (MTK vendor layer), `ossi*`/`qssi*` (Qualcomm SSI system/product names),
     * `mainline*` and `unknown*`. None is a retail codename; a generated
     * profile keyed with one would be shared by every device on the same image.
     */
    private val GenericPrefixes = listOf(
        "missi",
        "generic",
        "mainline",
        "unknown",
        "mivendor",
        "mgvi_",
        "ossi",
        "qssi",
        "alps",
    )

    internal fun isGenericIdentity(value: String): Boolean {
        val name = value.trim().lowercase()
        return name.isEmpty() || GenericPrefixes.any { name.startsWith(it) }
    }

    /** The first non-generic identity, in priority order; null when all are generic. */
    internal fun chooseProfileKey(candidates: List<String>): String? =
        candidates.asSequence()
            .map { it.trim() }
            .firstOrNull { !isGenericIdentity(it) }

    /**
     * The key written into a generated v2 profile: `Build.DEVICE` first (the
     * codename on every non-mainline device), then the vendor identity (the
     * unique codename on the mainline `spinel`), then the boot-image identity.
     * Null when every candidate is a mainline/vendor placeholder; the caller
     * must then write a v1 all-device profile instead of a fake device key.
     */
    fun uniqueProfileKey(): String? {
        val vendor = systemProperty("ro.product.vendor.device").trim()
        val bootimage = systemProperty("ro.product.bootimage.device").trim()
        return chooseProfileKey(listOf(Build.DEVICE, vendor, bootimage))
    }
}
