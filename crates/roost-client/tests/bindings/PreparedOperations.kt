package io.github.relaynet.roost

private class MemorySecureStorage : SecureStorage {
    private val values = mutableMapOf<String, ByteArray>()
    var loseNextStoreReply = false

    @Synchronized override fun store(key: String, value: ByteArray) {
        values[key] = value.copyOf()
        if (loseNextStoreReply) {
            loseNextStoreReply = false
            error("lost storage reply")
        }
    }
    @Synchronized override fun load(key: String): ByteArray? = values[key]?.copyOf()
    @Synchronized override fun delete(key: String) { values.remove(key) }
}

fun main() {
    val storage = MemorySecureStorage()
    val orphan = Client(storage).identity().prepareGenerateIdentity()
    val client = Client(storage)
    val unfinished = client.unfinishedOperations()
    check(unfinished.size == 1)
    check(unfinished[0].operation.identifier.contentEquals(orphan.operation.identifier))
    check(!client.identity().hasIdentity())
    client.abortOperation(orphan.operation.identifier)
    client.abortOperation(orphan.operation.identifier)

    val winner = client.identity().prepareGenerateIdentity()
    val stale = client.identity().prepareGenerateIdentity()
    check(winner.operation.secureStoragePreconditions.isNotEmpty())
    // The foreign store persists the reservation, then loses its reply.
    storage.loseNextStoreReply = true
    try {
        client.commitOperation(winner.operation.identifier)
        error("expected lost storage reply")
    } catch (_: ClientException.Storage) { }

    val recovered = Client(storage)
    check(recovered.unfinishedOperations().any {
        it.operation.identifier.contentEquals(winner.operation.identifier)
    })
    try {
        recovered.identity().hasIdentity()
        error("reserved operation did not gate ordinary work")
    } catch (error: ClientException.OperationRecoveryRequired) {
        check(error.operationIdentifier.contentEquals(winner.operation.identifier))
    }
    // The host has confirmed its durable transaction committed before finalizing.
    recovered.commitOperation(winner.operation.identifier)
    storage.loseNextStoreReply = true
    try {
        recovered.finalizeOperation(winner.operation.identifier)
        error("expected lost finalization reply")
    } catch (_: ClientException.Storage) { }
    val restarted = Client(storage)
    restarted.finalizeOperation(winner.operation.identifier)
    restarted.finalizeOperation(winner.operation.identifier)
    check(restarted.identity().loadIdentity().ed25519VerifyingKey
        .contentEquals(winner.identity.ed25519VerifyingKey))
    try {
        restarted.commitOperation(stale.operation.identifier)
        error("stale SecureStorage precondition committed")
    } catch (_: ClientException.SecureStoragePreconditionChanged) { }
    restarted.abortOperation(stale.operation.identifier)
    check(restarted.unfinishedOperations().isEmpty())
    println("Kotlin prepared-operation recovery passed")
}
