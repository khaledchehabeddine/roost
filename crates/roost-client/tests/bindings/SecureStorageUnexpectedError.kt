package io.github.relaynet.roost

private const val injectedReason = "injected foreign storage failure"

private class ThrowingSecureStorage : SecureStorage {
    private var throwOnNextLoad = true

    override fun store(key: String, value: ByteArray) = Unit

    override fun load(key: String): ByteArray? {
        val shouldThrow = throwOnNextLoad
        throwOnNextLoad = false

        if (shouldThrow) {
            throw IllegalStateException(injectedReason)
        }
        return null
    }

    override fun delete(key: String) = Unit
}

private fun requireRegression(condition: Boolean, message: String) {
    if (!condition) {
        throw IllegalStateException("secure storage unexpected-error regression failed: $message")
    }
}

fun main() {
    val store = Client(ThrowingSecureStorage())

    try {
        store.identity().hasIdentity()
        throw IllegalStateException("expected unexpected foreign storage exception")
    } catch (error: ClientException.Storage) {
        requireRegression(
            error.reason.contains("unexpected foreign callback failure"),
            "storage error reason",
        )
    }

    requireRegression(!store.identity().hasIdentity(), "storage mutex remains usable")
    println("Kotlin SecureStorage unexpected-error regression passed")
}
