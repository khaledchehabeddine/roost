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

private data class StateAddress(val kind: ProtocolStateKind, val key: List<Byte>)

private class MemoryProtocolStateStore {
    private var values = mutableMapOf<StateAddress, ByteArray>()

    fun snapshot(addresses: List<ProtocolStateAddress>): List<ProtocolStateEntry> =
        addresses.mapNotNull { address ->
            values[StateAddress(address.kind, address.key.toList())]?.let {
                ProtocolStateEntry(address.kind, address.key, it.copyOf())
            }
        }

    fun commit(updates: List<ProtocolStateUpdate>) {
        val next = values.toMutableMap()
        for (update in updates) {
            val address = StateAddress(update.kind, update.key.toList())
            val current = values[address]
            when (val check = update.commitCheck) {
                is ProtocolStateCommitCheck.Absent -> if (current != null) {
                    throw ClientException.ProtocolStateFault("stale protocol-state commit")
                }
                is ProtocolStateCommitCheck.Digest -> if (current == null || !protocolStateBlobDigest(current).contentEquals(check.expectedBlobDigest)) {
                    throw ClientException.ProtocolStateFault("stale protocol-state commit")
                }
            }
            val blob = update.blob
            if (blob == null) next.remove(address) else next[address] = blob.copyOf()
        }
        values = next
    }
}

private fun complete(store: Client, operation: KeyStoreOperation) {
    store.commitOperation(operation.identifier)
    store.finalizeOperation(operation.identifier)
}

private fun generateIdentity(store: Client): Identity {
    val prepared = store.identity().prepareGenerateIdentity()
    complete(store, prepared.operation)
    return prepared.identity
}

private fun rotateSignedPrekeyNow(store: Client) {
    val prepared = store.identity().prepareRotateSignedPrekeyNow()
    complete(store, prepared.operation)
}

private fun replenishOneTimePrekeys(store: Client): List<OneTimePreKeyBundle> {
    val prepared = store.identity().prepareReplenishOneTimePrekeys()
    complete(store, prepared.operation)
    return prepared.oneTimePrekeys
}

private fun importEncryptedBackup(store: Client, data: ByteArray, passphrase: String) {
    complete(store, store.identity().prepareImportEncryptedBackup(data, passphrase))
}

fun main() {
    val alice = Client(MemorySecureStorage())
    val bob = Client(MemorySecureStorage())
    val contacts = alice.contacts()
    val messaging = bob.messaging()
    requireCoverage(messaging.hardeningLimits().maxEncodedMessageLen > 0uL, "hardening limits")

    val protocolStore = MemoryProtocolStateStore()
    val dedupKey = "dedup".encodeToByteArray()
    protocolStore.commit(listOf(messaging.initializeDeduplicationSet(dedupKey)))
    expectStaleProtocolStateCommit(protocolStore, messaging.initializeDeduplicationSet(dedupKey))
    val digestKey = "digest".encodeToByteArray()
    protocolStore.commit(
        listOf(
            ProtocolStateUpdate(
                ProtocolStateKind.DEDUPLICATION_SET,
                digestKey,
                ProtocolStateCommitCheck.Absent,
                byteArrayOf(0x01),
            ),
        ),
    )
    expectStaleProtocolStateCommit(
        protocolStore,
        ProtocolStateUpdate(
            ProtocolStateKind.DEDUPLICATION_SET,
            digestKey,
            ProtocolStateCommitCheck.Digest(protocolStateBlobDigest(byteArrayOf(0x02))),
            byteArrayOf(0x03),
        ),
    )
    val loaded = protocolStore.snapshot(
        listOf(ProtocolStateAddress(ProtocolStateKind.DEDUPLICATION_SET, dedupKey)),
    )
    requireCoverage(loaded.size == 1, "protocol state store load")

    val aliceIdentity = generateIdentity(alice)
    val bobIdentity = generateIdentity(bob)
    rotateSignedPrekeyNow(alice)
    rotateSignedPrekeyNow(bob)
    val alicePublication = alice.identity().currentPublicationBundle()
    val bobPublication = bob.identity().currentPublicationBundle()
    val replenished = replenishOneTimePrekeys(bob)
    requireCoverage(replenished.size == 100, "prekey replenishment")
    val bobOneTimePrekey = replenished[0]
    requireCoverage(bobPublication.signedPrekey.identifier == 0uL, "published signed prekey identifier")
    requireCoverage(bobOneTimePrekey.identifier == 0uL, "published one-time prekey identifier")

    val backup = alice.identity().exportEncryptedBackup("passphrase")
    val restored = Client(MemorySecureStorage())
    importEncryptedBackup(restored, backup, "passphrase")
    requireCoverage(restored.identity().hasIdentity(), "backup import")
    expectBackupFailure(restored)

    val sessionKey = ByteArray(16) { 0x45 }
    val initiation = alice.messaging().initiateSession(
        sessionKey,
        bobIdentity,
        bobPublication,
        bobOneTimePrekey,
        "alice certificate".encodeToByteArray(),
        "alice signature".encodeToByteArray(),
        "hello bob".encodeToByteArray(),
            TransportBinding("test-route".encodeToByteArray())
)
    val decodedInitial = decodeMessage(encodeMessage(initiation.message))
    // The stranger path: read who sent it before accepting, because the session
    // key is derived from both identities and acceptance stages one-time-prekey
    // consumption, so it should not be run merely to find out.
    val hinted = bob.messaging().initiatorIdentityHint(decodedInitial,
            TransportBinding("test-route".encodeToByteArray()), PreKeySelection(bobPublication.signedPrekey.identifier, bobOneTimePrekey.identifier)
)
    requireCoverage(
        hinted.x25519PublicKey.contentEquals(aliceIdentity.x25519PublicKey) &&
            hinted.ed25519VerifyingKey.contentEquals(aliceIdentity.ed25519VerifyingKey) &&
            hinted.identityBindingSignature.contentEquals(aliceIdentity.identityBindingSignature),
        "initiator identity hint",
    )

    val acceptancePreparation = bob.messaging().prepareAcceptSession(sessionKey, null, decodedInitial,
            TransportBinding("test-route".encodeToByteArray()), PreKeySelection(bobPublication.signedPrekey.identifier, bobOneTimePrekey.identifier)
)
    bob.commitOperation(acceptancePreparation.operation.identifier)
    val acceptance = acceptancePreparation.acceptance
    val bobSnapshot = mutableListOf<ProtocolStateEntry>()
    applyUpdates(bobSnapshot, acceptance.stateUpdates)
    bob.finalizeOperation(acceptancePreparation.operation.identifier)
    requireCoverage(acceptance.plaintext.contentEquals("hello bob".encodeToByteArray()), "session accept plaintext")

    val aliceSnapshot = mutableListOf<ProtocolStateEntry>()
    applyUpdates(aliceSnapshot, initiation.stateUpdates)
    val recorded = contacts.recordContact(emptyList(), contactIdentity(bobIdentity, bobPublication))
    protocolStore.commit(recorded.stateUpdates)
    applyUpdates(aliceSnapshot, recorded.stateUpdates)
    val acceptedContact = contacts.acceptContact(aliceSnapshot.toList(), identityKey(bobIdentity))
    protocolStore.commit(acceptedContact.stateUpdates)
    applyUpdates(aliceSnapshot, acceptedContact.stateUpdates)
        ?: failCoverage("accepted contact should produce a state update")

    val outbound = alice.messaging().encryptMessage(
        aliceSnapshot.toList(),
        sessionKey,
        ByteArray(16) { 0x46 },
        identityKey(bobIdentity),
        bobPublication.discoveryKey.publicKey,
        42uL,
        "alice certificate".encodeToByteArray(),
        "alice signature".encodeToByteArray(),
        "follow-up".encodeToByteArray(),
            TransportBinding("test-route".encodeToByteArray())
)
    applyUpdates(aliceSnapshot, outbound.stateUpdates)
    requireCoverage(messaging.pendingAcknowledgments(aliceSnapshot.toList(), sessionKey).size == 1, "pending ack")
    requireCoverage(
        messaging.retryInstructions(aliceSnapshot.toList(), sessionKey, 43uL, 0uL).instructions.size == 1,
        "retry instruction",
    )

    val preparedBlock = alice.contacts().prepareBlockContact(aliceSnapshot.toList(), identityKey(bobIdentity))
    val blocked = preparedBlock.block.contact
    alice.commitOperation(preparedBlock.operation.identifier)
    alice.finalizeOperation(preparedBlock.operation.identifier)
    val blockedSnapshot = aliceSnapshot.toMutableList()
    applyUpdates(blockedSnapshot, blocked.stateUpdates)
    expectBlockedSend(alice, blockedSnapshot.toList(), sessionKey, bobIdentity, bobPublication)

    applyUpdates(bobSnapshot, listOf(messaging.initializeDeduplicationSet(dedupKey)))
    expectMissingCertificateValidation(
        bob,
        bobSnapshot.toList(),
        sessionKey,
        dedupKey,
        outbound.message,
        alicePublication,
    )

    expectCertificateRejection()
    expectInvalidMessageKey()
    println("Kotlin issue 122 coverage passed")
}

private fun identityKey(identity: Identity) = IdentityKey(
    identity.x25519PublicKey,
    identity.ed25519VerifyingKey,
)

private fun contactIdentity(identity: Identity, publication: PublicationBundle) = ContactIdentity(
    identityKey(identity),
    ContactDiscoveryKey(
        publication.discoveryKey.publicKey,
        publication.discoveryKey.verifyingKey,
        publication.discoveryKey.epoch,
        publication.discoveryKey.createdAt,
        publication.discoveryKey.signature,
    ),
)

private fun applyUpdates(snapshot: MutableList<ProtocolStateEntry>, updates: List<ProtocolStateUpdate>) {
    for (update in updates) {
        snapshot.removeAll { it.kind == update.kind && it.key.contentEquals(update.key) }
        update.blob?.let { snapshot.add(ProtocolStateEntry(update.kind, update.key, it)) }
    }
}

private fun expectStaleProtocolStateCommit(store: MemoryProtocolStateStore, update: ProtocolStateUpdate) {
    try {
        store.commit(listOf(update))
        failCoverage("stale protocol-state commit should reject")
    } catch (error: ClientException.ProtocolStateFault) {
    }
}


private fun expectBackupFailure(store: Client) {
    try {
        store.identity().prepareImportEncryptedBackup(byteArrayOf(0x01), "bad")
        failCoverage("backup import should fail")
    } catch (error: ClientException.InvalidData) {
    } catch (error: ClientException.UnsupportedVersion) {
    } catch (error: ClientException.DecryptionFailed) {
    } catch (error: ClientException.BackupImportFailed) {
    }
}

private fun expectBlockedSend(
    alice: Client,
    snapshot: List<ProtocolStateEntry>,
    sessionKey: ByteArray,
    bobIdentity: Identity,
    bobPublication: PublicationBundle,
) {
    try {
        alice.messaging().encryptMessage(
            snapshot,
            sessionKey,
            ByteArray(16) { 0x47 },
            identityKey(bobIdentity),
            bobPublication.discoveryKey.publicKey,
            44uL,
            "alice certificate".encodeToByteArray(),
            "alice signature".encodeToByteArray(),
            "blocked".encodeToByteArray(),
            TransportBinding("test-route".encodeToByteArray())
)
        failCoverage("blocked contact should reject send")
    } catch (error: ClientException.BlockedContact) {
    }
}

private fun expectMissingCertificateValidation(
    bob: Client,
    snapshot: List<ProtocolStateEntry>,
    sessionKey: ByteArray,
    dedupKey: ByteArray,
    message: Message,
    alicePublication: PublicationBundle,
) {
    try {
        bob.messaging().decryptMessage(
            snapshot,
            sessionKey,
            dedupKey,
            message,
            ByteArray(16) { 0x48 },
            alicePublication.discoveryKey.publicKey,
            45uL,
            "bob certificate".encodeToByteArray(),
            "bob signature".encodeToByteArray(),
            null,
            TransportBinding("test-route".encodeToByteArray()), TransportBinding("test-route".encodeToByteArray())
)
        failCoverage("missing certificate validation should reject receive")
    } catch (error: ClientException.InvalidData) {
    }
}

private fun expectCertificateRejection() {
    try {
        validateSenderCertificate(
            byteArrayOf(0x01),
            byteArrayOf(),
            emptyList(),
            "relay.test".toByteArray(),
            RevocationState(true, emptyList()),
            0uL,
            0uL,
        )
        failCoverage("malformed certificate should reject")
    } catch (error: ClientException.CertificateRejected) {
    }
}

private fun expectInvalidMessageKey() {
    try {
        encodeMessage(
            Message(
                1u,
                ByteArray(31) { 0x01 },
                null,
                ByteArray(32) { 0x02 },
                byteArrayOf(),
            ),
        )
        failCoverage("invalid public key should reject")
    } catch (error: ClientException.InvalidData) {
    }
}

private fun requireCoverage(condition: Boolean, message: String) {
    if (!condition) {
        failCoverage(message)
    }
}

private fun failCoverage(message: String): Nothing {
    throw IllegalStateException("issue 122 coverage failed: $message")
}
