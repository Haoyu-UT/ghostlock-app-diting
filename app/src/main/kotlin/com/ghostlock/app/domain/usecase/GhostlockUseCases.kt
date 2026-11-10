package com.ghostlock.app.domain.usecase

import com.ghostlock.app.domain.model.CpuPair
import com.ghostlock.app.domain.repository.GhostlockRepository

class LoadKernelSnapshotUseCase(private val repository: GhostlockRepository) {
    suspend operator fun invoke() = repository.snapshot()
}

class SelectCpuPairUseCase(private val repository: GhostlockRepository) {
    operator fun invoke(index: Int) = repository.selectCpuPair(index)
}

class ParseSourceUseCase(private val repository: GhostlockRepository) {
    suspend operator fun invoke(
        input: String,
        xblPath: String? = null,
        uefiPath: String? = null,
        vendorBootPath: String? = null,
        dtboPath: String? = null,
        overwrite: Boolean = false,
        route: String? = null,
        onLog: (String) -> Unit = {},
    ) = repository.parseSource(
        input, xblPath, uefiPath, vendorBootPath, dtboPath, overwrite, route, onLog,
    )
}

class RunExploitUseCase(private val repository: GhostlockRepository) {
    suspend operator fun invoke(pair: CpuPair, useShizuku: Boolean, onLog: (String) -> Unit) =
        if (useShizuku) repository.runExploitWithShizuku(pair, onLog)
        else repository.runExploit(pair, onLog)
}

class ReadDocumentUseCase(private val repository: GhostlockRepository) {
    suspend operator fun invoke(uri: String) = repository.readDocument(uri)
    suspend fun cache(uri: String, fileName: String) = repository.cacheDocument(uri, fileName)
}
