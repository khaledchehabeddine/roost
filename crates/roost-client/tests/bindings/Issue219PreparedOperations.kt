package io.github.relaynet.roost

private class MemorySecureStorage : SecureStorage {
    private val values = mutableMapOf<String, ByteArray>()

    override fun store(key: String, value: ByteArray) {
        values[key] = value.copyOf()
    }

    override fun load(key: String): ByteArray? = values[key]?.copyOf()

    override fun delete(key: String) {
        values.remove(key)
    }
}

private fun checkCoverage(condition: Boolean, message: String) {
    if (!condition) {
        throw IllegalStateException("issue 219 prepared-operation coverage failed: $message")
    }
}

fun main() {
    val storage = MemorySecureStorage()
    var store: Client? = Client(storage)

    val orphan = store!!.identity().prepareGenerateIdentity()
    checkCoverage(orphan.operation.identifier.size == 16, "operation identifier must be 16 bytes")
    checkCoverage(
        orphan.operation.secureStoragePreconditions.isNotEmpty(),
        "preparation must expose SecureStorage preconditions",
    )
    checkCoverage(!store.identity().hasIdentity(), "prepared identity must remain provisional")

    store = null
    val recovered = Client(storage)
    val unfinished = recovered.unfinishedOperations()
    checkCoverage(
        unfinished.size == 1 &&
            unfinished[0].operation.identifier.contentEquals(orphan.operation.identifier),
        "a new Client instance must discover the orphaned stage",
    )
    recovered.abortOperation(orphan.operation.identifier)
    recovered.abortOperation(orphan.operation.identifier)
    checkCoverage(recovered.unfinishedOperations().isEmpty(), "abort must clear recovery work")

    val winner = recovered.identity().prepareGenerateIdentity()
    val stale = recovered.identity().prepareGenerateIdentity()
    recovered.commitOperation(winner.operation.identifier)
    recovered.commitOperation(winner.operation.identifier)
    try {
        recovered.identity().hasIdentity()
        checkCoverage(false, "ordinary Client work must stop until committed recovery finishes")
    } catch (error: ClientException.OperationRecoveryRequired) {
        checkCoverage(
            error.operationIdentifier.contentEquals(winner.operation.identifier),
            "recovery error must name the operation",
        )
    }
    recovered.finalizeOperation(winner.operation.identifier)
    recovered.finalizeOperation(winner.operation.identifier)
    checkCoverage(recovered.identity().hasIdentity(), "finalization must make the identity authoritative")

    try {
        recovered.commitOperation(stale.operation.identifier)
        checkCoverage(false, "a stale prepared operation must not commit")
    } catch (error: ClientException.SecureStoragePreconditionChanged) {
        // Expected.
    }
    recovered.abortOperation(stale.operation.identifier)

    val signedPreKey = recovered.identity().prepareRotateSignedPrekeyNow()
    recovered.commitOperation(signedPreKey.operation.identifier)
    recovered.finalizeOperation(signedPreKey.operation.identifier)
    val noOp = recovered.identity().prepareRotateSignedPrekeyIfStale()
    checkCoverage(noOp.signedPrekey == null, "fresh signed pre-key rotation must report no change")
    checkCoverage(
        recovered.unfinishedOperations().any {
            it.operation.identifier.contentEquals(noOp.operation.identifier)
        },
        "a no-op result must still own an unfinished operation",
    )
    recovered.commitOperation(noOp.operation.identifier)
    recovered.finalizeOperation(noOp.operation.identifier)

    val cappedIdentifiers = mutableListOf<ByteArray>()
    repeat(16) {
        cappedIdentifiers += recovered.identity().prepareRotateSignedPrekeyIfStale().operation.identifier
    }
    try {
        recovered.identity().prepareRotateSignedPrekeyIfStale()
        checkCoverage(false, "the bounded unfinished-operation journal must reject a seventeenth operation")
    } catch (error: ClientException.TooManyUnfinishedOperations) {
        // Expected.
    }
    cappedIdentifiers.forEach { recovered.abortOperation(it) }

    println("Kotlin issue 219 prepared-operation coverage passed")
}
