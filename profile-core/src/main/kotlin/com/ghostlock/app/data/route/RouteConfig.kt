package com.ghostlock.app.data.route

/**
 * Route-specific configuration. One subtype per route, each owning the wire
 * key names of its v2 route section. Never part of the shared document.
 *
 * Entries carry the wire's raw 64-bit bit-pattern: unsigned fields use their
 * exact bits, signed fields use two's complement. Typed fields are restored
 * with explicit bit casts and never clamped; out-of-range values are rejected
 * by the validation pass instead of being silently rewritten.
 */
sealed interface RouteConfig {
    /** Entries the document carries; a key absent here is omitted from the wire. */
    fun entries(): List<Pair<String, ULong>>

    /**
     * Every key this section can carry, whether or not it has a value. This is
     * the section's half of the wire **schema**: the profile digest hashes it
     * on both sides of the transport, so a key one side declares and the other
     * does not is a detectable mismatch rather than a silent drop.
     */
    fun keys(): List<String>

    fun apply(key: String, value: ULong): RouteConfig
}

object NoRouteConfig : RouteConfig {
    override fun entries(): List<Pair<String, ULong>> = emptyList()

    override fun keys(): List<String> = emptyList()

    override fun apply(key: String, value: ULong): RouteConfig = this
}
