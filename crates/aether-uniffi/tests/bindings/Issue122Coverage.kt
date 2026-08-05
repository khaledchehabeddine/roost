package com.aurelion.aether

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

private class MemoryProtocolStateStore : ProtocolStateStore {
    private val values = mutableMapOf<StateAddress, ByteArray>()

    override fun load(kind: ProtocolStateKind, key: ByteArray): ByteArray? =
        values[StateAddress(kind, key.toList())]?.copyOf()

    override fun commit(updates: List<ProtocolStateUpdate>) {
        for (update in updates) {
            val address = StateAddress(update.kind, update.key.toList())
            val current = values[address]
            when (update.commitCheck) {
                ProtocolStateCommitCheck.ABSENT -> {
                    if (current != null) {
                        throw AetherException.ProtocolStateFault("stale protocol-state commit")
                    }
                }
                ProtocolStateCommitCheck.DIGEST -> {
                    val expected = update.expectedBlobDigest
                    if (current == null || expected == null || !protocolStateBlobDigest(current).contentEquals(expected)) {
                        throw AetherException.ProtocolStateFault("stale protocol-state commit")
                    }
                }
                ProtocolStateCommitCheck.UNCHECKED -> {
                }
            }
            val blob = update.blob
            if (blob == null) {
                values.remove(address)
            } else {
                values[address] = blob.copyOf()
            }
        }
    }
}

fun main() {
    val engine = ProtocolStateEngine()
    requireCoverage(engine.hardeningLimits().maxEncodedMessageLen > 0uL, "hardening limits")

    val protocolStore = MemoryProtocolStateStore()
    val dedupKey = "dedup".encodeToByteArray()
    protocolStore.commit(listOf(engine.initializeDeduplicationSet(dedupKey)))
    expectStaleProtocolStateCommit(protocolStore, engine.initializeDeduplicationSet(dedupKey))
    val digestKey = "digest".encodeToByteArray()
    protocolStore.commit(
        listOf(
            ProtocolStateUpdate(
                ProtocolStateKind.DEDUPLICATION_SET,
                digestKey,
                ProtocolStateCommitCheck.ABSENT,
                null,
                byteArrayOf(0x01),
            ),
        ),
    )
    expectStaleProtocolStateCommit(
        protocolStore,
        ProtocolStateUpdate(
            ProtocolStateKind.DEDUPLICATION_SET,
            digestKey,
            ProtocolStateCommitCheck.DIGEST,
            protocolStateBlobDigest(byteArrayOf(0x02)),
            byteArrayOf(0x03),
        ),
    )
    val loaded = engine.loadSnapshot(
        protocolStore,
        listOf(ProtocolStateAddress(ProtocolStateKind.DEDUPLICATION_SET, dedupKey)),
    )
    requireCoverage(loaded.size == 1, "protocol state store load")

    val alice = KeyStore(MemorySecureStorage())
    val bob = KeyStore(MemorySecureStorage())
    val aliceIdentity = alice.generateIdentity()
    val bobIdentity = bob.generateIdentity()
    alice.rotateSignedPrekeyNow()
    bob.rotateSignedPrekeyNow()
    val alicePublication = alice.currentPublicationBundle()
    val bobPublication = bob.currentPublicationBundle()
    val replenished = bob.replenishOneTimePrekeys()
    requireCoverage(replenished.size == 100, "prekey replenishment")
    val bobOneTimePrekey = replenished[0]

    val backup = alice.exportEncryptedBackup("passphrase")
    val restored = KeyStore(MemorySecureStorage())
    restored.importEncryptedBackup(backup, "passphrase")
    requireCoverage(restored.hasIdentity(), "backup import")
    expectBackupFailure(restored)

    val sessionKey = ByteArray(16) { 0x45 }
    val initiation = alice.initiateSession(
        sessionKey,
        bobIdentity,
        bobPublication,
        bobOneTimePrekey,
        "alice certificate".encodeToByteArray(),
        "alice signature".encodeToByteArray(),
        "hello bob".encodeToByteArray(),
    )
    val decodedInitial = decodeMessage(encodeMessage(initiation.message))
    val acceptance = bob.acceptSession(sessionKey, aliceIdentity, decodedInitial)
    requireCoverage(acceptance.plaintext.contentEquals("hello bob".encodeToByteArray()), "session accept plaintext")

    val aliceSnapshot = mutableListOf<ProtocolStateEntry>()
    applyUpdates(aliceSnapshot, initiation.stateUpdates)
    val recorded = engine.recordContact(emptyList(), contactIdentity(bobIdentity, bobPublication))
    applyUpdates(aliceSnapshot, recorded.stateUpdates)
    val acceptedContact = engine.acceptContact(aliceSnapshot.toList(), identityKey(bobIdentity))
    applyUpdates(aliceSnapshot, acceptedContact.stateUpdates)

    val outbound = alice.encryptMessage(
        aliceSnapshot.toList(),
        sessionKey,
        ByteArray(16) { 0x46 },
        identityKey(bobIdentity),
        bobPublication.discoveryKey.publicKey,
        42uL,
        "alice certificate".encodeToByteArray(),
        "alice signature".encodeToByteArray(),
        "follow-up".encodeToByteArray(),
    )
    applyUpdates(aliceSnapshot, outbound.stateUpdates)
    requireCoverage(engine.pendingAcknowledgments(aliceSnapshot.toList(), sessionKey).size == 1, "pending ack")
    requireCoverage(
        engine.retryInstructions(aliceSnapshot.toList(), sessionKey, 43uL, 0uL).instructions.size == 1,
        "retry instruction",
    )

    val blocked = engine.blockContact(aliceSnapshot.toList(), identityKey(bobIdentity))
    val blockedSnapshot = aliceSnapshot.toMutableList()
    applyUpdates(blockedSnapshot, blocked.stateUpdates)
    expectBlockedSend(alice, blockedSnapshot.toList(), sessionKey, bobIdentity, bobPublication)

    val bobSnapshot = mutableListOf<ProtocolStateEntry>()
    applyUpdates(bobSnapshot, acceptance.stateUpdates)
    applyUpdates(bobSnapshot, listOf(engine.initializeDeduplicationSet(dedupKey)))
    expectMissingCertificateValidation(
        bob,
        bobSnapshot.toList(),
        sessionKey,
        dedupKey,
        outbound.message,
        alicePublication,
    )

    exerciseEvents(acceptedContact.contact)
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
    } catch (error: AetherException.ProtocolStateFault) {
    }
}

private fun exerciseEvents(contact: ContactState) {
    val stream = ContactEventStream.withObserverCapacity(listOf(contact), 1uL)
    val observer = stream.subscribe()
    val event = ContactEvent(ContactEventKind.CHANGED, contact)
    stream.emit(event, listOf(contact))
    stream.emit(event, listOf(contact))
    val item = observer.pollNext()
    requireCoverage(item?.kind == ContactEventStreamItemKind.LAGGED, "event lag")
    observer.resumeAfter(stream.currentState())
}

private fun expectBackupFailure(store: KeyStore) {
    try {
        store.importEncryptedBackup(byteArrayOf(0x01), "bad")
        failCoverage("backup import should fail")
    } catch (error: AetherException.InvalidData) {
    } catch (error: AetherException.UnsupportedVersion) {
    } catch (error: AetherException.DecryptionFailed) {
    } catch (error: AetherException.BackupImportFailed) {
    }
}

private fun expectBlockedSend(
    alice: KeyStore,
    snapshot: List<ProtocolStateEntry>,
    sessionKey: ByteArray,
    bobIdentity: Identity,
    bobPublication: PublicationBundle,
) {
    try {
        alice.encryptMessage(
            snapshot,
            sessionKey,
            ByteArray(16) { 0x47 },
            identityKey(bobIdentity),
            bobPublication.discoveryKey.publicKey,
            44uL,
            "alice certificate".encodeToByteArray(),
            "alice signature".encodeToByteArray(),
            "blocked".encodeToByteArray(),
        )
        failCoverage("blocked contact should reject send")
    } catch (error: AetherException.BlockedContact) {
    }
}

private fun expectMissingCertificateValidation(
    bob: KeyStore,
    snapshot: List<ProtocolStateEntry>,
    sessionKey: ByteArray,
    dedupKey: ByteArray,
    message: Message,
    alicePublication: PublicationBundle,
) {
    try {
        bob.decryptMessage(
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
        )
        failCoverage("missing certificate validation should reject receive")
    } catch (error: AetherException.InvalidData) {
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
    } catch (error: AetherException.CertificateRejected) {
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
    } catch (error: AetherException.InvalidData) {
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
