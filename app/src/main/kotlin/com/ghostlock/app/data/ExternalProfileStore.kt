package com.ghostlock.app.data

import android.content.Context
import android.content.Intent
import androidx.core.net.toUri
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import android.provider.OpenableColumns

/**
 * A profile document on the SD card, reached through the system picker.
 *
 * There is deliberately no directory listing: the app owns no folder on the
 * SD card and copies nothing into app data (measured-db-plan §1). It keeps the
 * URI the user picked, reads it on every resolution, and holds the persisted
 * read grant so the selection survives restarts.
 */
internal interface ExternalProfileStore {
    /** The document text, or null when it is gone, unreadable or revoked. */
    fun read(uri: String): String?

    /** Keeps the read grant across restarts; false when the provider refuses. */
    fun persistReadPermission(uri: String): Boolean

    /** Display name for the stored reference; falls back to the URI tail. */
    fun displayName(uri: String): String
}

internal class AndroidExternalProfileStore(private val context: Context) : ExternalProfileStore {
    override fun read(uri: String): String? = runCatching {
        context.contentResolver.openInputStream(uri.toUri())
            ?.bufferedReader(StandardCharsets.UTF_8)
            ?.use { it.readText() }
    }.getOrNull()

    override fun persistReadPermission(uri: String): Boolean = runCatching {
        context.contentResolver.takePersistableUriPermission(
            uri.toUri(),
            Intent.FLAG_GRANT_READ_URI_PERMISSION,
        )
        true
    }.getOrDefault(false)

    override fun displayName(uri: String): String {
        val parsed = uri.toUri()
        if (parsed.scheme == "content") {
            runCatching {
                context.contentResolver.query(
                    parsed,
                    arrayOf(OpenableColumns.DISPLAY_NAME),
                    null,
                    null,
                    null,
                )?.use { cursor ->
                    if (cursor.moveToFirst()) cursor.getString(0) else null
                }
            }.getOrNull()?.takeIf { it.isNotBlank() }?.let { return it }
        }
        return parsed.lastPathSegment?.substringAfterLast('/')?.takeIf { it.isNotBlank() } ?: uri
    }
}

/**
 * Parses one profile document (HOCON text, an object or a list of objects) and
 * converts every entry to the current layout. `include` targets are resolved
 * through [loadInclude] — the bundled assets in the app; SD-card documents are
 * not searched for siblings, because the model has no folder to search. An
 * app export is self-contained and never needs one.
 */
internal object ProfileDocumentParser {
    fun entries(
        text: String,
        loadInclude: ((String) -> String?)? = null,
    ): List<ValueMap>? {
        val expanded = expandIncludes(text, loadInclude, emptyList()) ?: return null
        val value = HoconSupport.parseValue(expanded) ?: return null
        val maps = when (value) {
            is Map<*, *> -> listOfNotNull(value.asValueMap())
            is List<*> -> value.mapNotNull { it.asValueMap() }
            else -> return null
        }
        val entries = maps.filter { it["release"] is String }
        return entries.takeIf { it.isNotEmpty() }?.onEach { LegacyProfileConverter.convertValue(it) }
    }

    /** First entry carrying [release], converted; null when absent. */
    fun entryForRelease(text: String, release: String, loadInclude: ((String) -> String?)? = null): ValueMap? =
        entries(text, loadInclude)?.firstOrNull { it["release"] == release }

    private fun expandIncludes(
        text: String,
        loadInclude: ((String) -> String?)?,
        visiting: List<String>,
    ): String? {
        if (!text.contains("include ")) return text
        val expanded = StringBuilder()
        for (line in text.lineSequence()) {
            val trimmed = line.trim()
            if (!trimmed.startsWith("include ")) {
                expanded.append(line).append('\n')
                continue
            }
            val target = trimmed.removePrefix("include ").trim().trim('"')
            val key = target.substringAfterLast('/')
            if (key in visiting) continue
            val included = loadInclude?.invoke(target) ?: return null
            val nested = expandIncludes(included, loadInclude, visiting + key) ?: return null
            expanded.append(nested).append('\n')
        }
        return expanded.toString()
    }
}

/** SHA-256 of a document text, the profile reference's identity. */
internal fun sha256Of(text: String): String {
    val digest = MessageDigest.getInstance("SHA-256")
    return digest.digest(text.toByteArray(StandardCharsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
}

/**
 * Lineage comment an app export carries as its first line. A comment, never a
 * schema key: the native wire and `ProfileResolver` stay unchanged.
 */
internal object ProfileLineage {
    private val Line = Regex("^#\\s*ghostlock-profile\\s+(.*)$")
    private val Field = Regex("(\\w+)=([^\\s]+)")

    data class Parent(val label: String, val sha256: String?)

    fun parse(text: String): Parent? {
        val header = text.lineSequence().take(5).firstOrNull { Line.containsMatchIn(it) }
            ?: return null
        val body = Line.find(header)?.groupValues?.get(1) ?: return null
        val fields = Field.findAll(body).associate { it.groupValues[1] to it.groupValues[2] }
        val parent = fields["parent"] ?: return null
        return Parent(parent, fields["parent_sha256"])
    }

    fun header(parent: Parent?): String =
        if (parent == null) {
            "# ghostlock-profile (no parent recorded)"
        } else {
            "# ghostlock-profile parent=${parent.label}" +
                (parent.sha256?.let { " parent_sha256=$it" } ?: "")
        }
}
