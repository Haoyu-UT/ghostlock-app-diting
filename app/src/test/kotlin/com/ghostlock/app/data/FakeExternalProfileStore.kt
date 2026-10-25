package com.ghostlock.app.data

/**
 * In-memory SD-card documents for controller tests. The controller reads and
 * persists references only, so a map is enough to model a selected file.
 */
internal class FakeExternalProfileStore : ExternalProfileStore {
    val documents = linkedMapOf<String, String>()

    fun add(uri: String, text: String): String {
        documents[uri] = text
        return uri
    }

    override fun read(uri: String): String? = documents[uri]

    override fun persistReadPermission(uri: String): Boolean = true

    override fun displayName(uri: String): String = uri.substringAfterLast('/')
}
