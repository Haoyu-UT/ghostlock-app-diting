package com.ghostlock.app.domain.model

/** One KernelSU-family manager found on the device, as the UI lists it. */
data class RootManagerCandidate(
    val packageName: String,
    val label: String,
    val path: String,
    val builtin: Boolean,
    val suitable: Boolean,
    val verdict: String,
)
