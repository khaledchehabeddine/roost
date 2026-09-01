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

private fun complete(store: KeyStore, operation: KeyStoreOperation) {
    store.commitOperation(operation.identifier)
    store.finalizeOperation(operation.identifier)
}

private fun generateIdentity(store: KeyStore): Identity {
    val prepared = store.prepareGenerateIdentity()
    complete(store, prepared.operation)
    return prepared.identity
}

private fun rotateSignedPrekeyNow(store: KeyStore) {
    val prepared = store.prepareRotateSignedPrekeyNow()
    complete(store, prepared.operation)
}

private fun replenishOneTimePrekeys(store: KeyStore): List<OneTimePreKeyBundle> {
    val prepared = store.prepareReplenishOneTimePrekeys()
    complete(store, prepared.operation)
    return prepared.oneTimePrekeys
}

private fun importEncryptedBackup(store: KeyStore, data: ByteArray, passphrase: String) {
    complete(store, store.prepareImportEncryptedBackup(data, passphrase))
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
    val aliceIdentity = generateIdentity(alice)
    val bobIdentity = generateIdentity(bob)
    rotateSignedPrekeyNow(alice)
    rotateSignedPrekeyNow(bob)
    val alicePublication = alice.currentPublicationBundle()
    val bobPublication = bob.currentPublicationBundle()
    val replenished = replenishOneTimePrekeys(bob)
    requireCoverage(replenished.size == 100, "prekey replenishment")
    val bobOneTimePrekey = replenished[0]

    val backup = alice.exportEncryptedBackup("passphrase")
    val restored = KeyStore(MemorySecureStorage())
    importEncryptedBackup(restored, backup, "passphrase")
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
    // The stranger path: read who sent it before accepting, because the session
    // key is derived from both identities and acceptance stages one-time-prekey
    // consumption, so it should not be run merely to find out.
    val hinted = bob.initiatorIdentityHint(decodedInitial)
    requireCoverage(
        hinted.x25519PublicKey.contentEquals(aliceIdentity.x25519PublicKey) &&
            hinted.ed25519VerifyingKey.contentEquals(aliceIdentity.ed25519VerifyingKey) &&
            hinted.identityBindingSignature.contentEquals(aliceIdentity.identityBindingSignature),
        "initiator identity hint",
    )

    val acceptancePreparation = bob.prepareAcceptSession(sessionKey, null, decodedInitial)
    bob.commitOperation(acceptancePreparation.operation.identifier)
    val acceptance = acceptancePreparation.acceptance
    val bobSnapshot = mutableListOf<ProtocolStateEntry>()
    applyUpdates(bobSnapshot, acceptance.stateUpdates)
    bob.finalizeOperation(acceptancePreparation.operation.identifier)
    requireCoverage(acceptance.plaintext.contentEquals("hello bob".encodeToByteArray()), "session accept plaintext")

    val aliceSnapshot = mutableListOf<ProtocolStateEntry>()
    applyUpdates(aliceSnapshot, initiation.stateUpdates)
    val recorded = engine.recordContact(emptyList(), contactIdentity(bobIdentity, bobPublication))
    protocolStore.commit(recorded.stateUpdates)
    applyUpdates(aliceSnapshot, recorded.stateUpdates)
    val acceptedContact = engine.acceptContact(aliceSnapshot.toList(), identityKey(bobIdentity))
    protocolStore.commit(acceptedContact.stateUpdates)
    applyUpdates(aliceSnapshot, acceptedContact.stateUpdates)
    val contactUpdate = acceptedContact.stateUpdates.firstOrNull()
        ?: failCoverage("accepted contact should produce a state update")
    val contactAddress = ProtocolStateAddress(contactUpdate.kind, contactUpdate.key)

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

    applyUpdates(bobSnapshot, listOf(engine.initializeDeduplicationSet(dedupKey)))
    expectMissingCertificateValidation(
        bob,
        bobSnapshot.toList(),
        sessionKey,
        dedupKey,
        outbound.message,
        alicePublication,
    )

    exerciseEvents(engine, protocolStore, contactAddress, acceptedContact.contact)
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

private fun exerciseEvents(
    engine: ProtocolStateEngine,
    store: MemoryProtocolStateStore,
    address: ProtocolStateAddress,
    contact: ContactState,
) {
    val stream = ContactEventStream.withObserverCapacity(listOf(contact), 1uL)
    val observer = stream.subscribe()
    val event = ContactEvent(ContactEventKind.CHANGED, contact)
    stream.emit(event, listOf(contact))
    stream.emit(event, listOf(contact))
    val item = observer.pollNext()
    requireCoverage(item?.kind == ContactEventStreamItemKind.LAGGED, "event lag")
    observer.resumeAfter(stream.currentState())

    val otherStream = ContactEventStream.withObserverCapacity(listOf(contact), 1uL)
    otherStream.emit(event, listOf(contact))
    otherStream.emit(event, listOf(contact))
    otherStream.emit(event, listOf(contact))
    stream.emit(event, listOf(contact))
    try {
        observer.resumeAfter(otherStream.currentState())
        failCoverage("another stream's snapshot should reject")
    } catch (error: AetherException.ForeignEventSnapshot) {
    }
    requireCoverage(observer.pollNext()?.event?.id == 3uL, "foreign snapshot preserves local events")

    val extensionEngine = ProtocolStateEngine()
    val extensionSnapshot = extensionEngine.loadSnapshot(store, listOf(address))
    val blocked = extensionEngine.blockContact(extensionSnapshot, contact.identity.identityKey)
    store.commit(blocked.stateUpdates)
    val reloaded = engine.loadSnapshot(store, listOf(address))
    val rebuilt = engine.contactStates(reloaded)
    requireCoverage(rebuilt.size == 1 && rebuilt[0].blocked, "rebuilds committed extension state")
    val firstImport = stream.importCurrentState(rebuilt)
    requireCoverage(firstImport.eventId() == 3uL, "state import preserves local event ID")
    requireCoverage(firstImport.stateRevision() == 1uL, "state import revision")
    requireCoverage(firstImport.state().single().blocked, "imported snapshot state")
    requireCoverage(
        observer.pollNext()?.kind == ContactEventStreamItemKind.STALE,
        "state import marks observer stale",
    )

    val secondImport = stream.importCurrentState(rebuilt)
    try {
        observer.resumeAfter(firstImport)
        failCoverage("stale imported snapshot should reject")
    } catch (error: AetherException.StaleEventSnapshot) {
        requireCoverage(
            error.snapshotRevision == 1uL && error.currentRevision == 2uL,
            "stale imported snapshot revisions",
        )
    }
    requireCoverage(
        observer.pollNext()?.kind == ContactEventStreamItemKind.STALE,
        "repeated import stays explicit",
    )
    observer.resumeAfter(secondImport)

    val restarted = ContactEventStream.withObserverCapacity(rebuilt, 1uL)
    val restartSnapshot = restarted.currentState()
    requireCoverage(restartSnapshot.eventId() == 0uL, "restart uses a new local event sequence")
    requireCoverage(restartSnapshot.stateRevision() == 0uL, "restart uses a new local state revision")
}

private fun expectBackupFailure(store: KeyStore) {
    try {
        store.prepareImportEncryptedBackup(byteArrayOf(0x01), "bad")
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
