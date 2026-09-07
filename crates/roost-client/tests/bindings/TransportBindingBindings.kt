package com.aurelion.aether

private class TransportBindingMemoryStorage : SecureStorage {
    private val values = mutableMapOf<String, ByteArray>()

    override fun store(key: String, value: ByteArray) {
        values[key] = value.copyOf()
    }

    override fun load(key: String): ByteArray? = values[key]?.copyOf()

    override fun delete(key: String) {
        values.remove(key)
    }
}

fun main() {
    val alice = KeyStore(TransportBindingMemoryStorage())
    val bob = KeyStore(TransportBindingMemoryStorage())
    val aliceIdentity = generateIdentity(alice)
    val bobIdentity = generateIdentity(bob)
    rotateSignedPrekey(alice)
    rotateSignedPrekey(bob)
    val alicePublication = alice.currentPublicationBundle()
    val bobPublication = bob.currentPublicationBundle()
    val bobOneTimePrekey = replenishOneTimePrekeys(bob)[0]
    val initialBinding = TransportBinding("consumer-owned initial metadata".encodeToByteArray())
    val prekeySelection = PreKeySelection(
        bobPublication.signedPrekey.identifier,
        bobOneTimePrekey.identifier,
    )
    val sessionKey = ByteArray(16) { 0x58 }
    expectInvalidData("empty Transport Binding") {
        alice.initiateSessionWithTransportBinding(
            sessionKey,
            bobIdentity,
            bobPublication,
            bobOneTimePrekey,
            "alice certificate".encodeToByteArray(),
            "alice signature".encodeToByteArray(),
            "rejected".encodeToByteArray(),
            TransportBinding(ByteArray(0)),
        )
    }
    expectInvalidData("oversized Transport Binding") {
        alice.initiateSessionWithTransportBinding(
            sessionKey,
            bobIdentity,
            bobPublication,
            bobOneTimePrekey,
            "alice certificate".encodeToByteArray(),
            "alice signature".encodeToByteArray(),
            "rejected".encodeToByteArray(),
            TransportBinding(ByteArray(1_025) { 0x41 }),
        )
    }
    val initiation = alice.initiateSessionWithTransportBinding(
        sessionKey,
        bobIdentity,
        bobPublication,
        bobOneTimePrekey,
        "alice certificate".encodeToByteArray(),
        "alice signature".encodeToByteArray(),
        "transport-bound hello".encodeToByteArray(),
        initialBinding,
    )
    val hint = bob.initiatorIdentityHintWithTransportBinding(
        initiation.message,
        initialBinding,
        prekeySelection,
    )
    requireCoverage(
        hint.ed25519VerifyingKey.contentEquals(aliceIdentity.ed25519VerifyingKey),
        "transport-bound initiator identity hint",
    )

    expectMismatchedPrekeySelection(bob, initiation.message, initialBinding, prekeySelection)
    expectAuthenticationFailed("maximum unsigned prekey identifiers") {
        bob.initiatorIdentityHintWithTransportBinding(
            initiation.message,
            initialBinding,
            PreKeySelection(ULong.MAX_VALUE, ULong.MAX_VALUE),
        )
    }

    val prepared = bob.prepareAcceptSessionWithTransportBinding(
        sessionKey,
        null,
        initiation.message,
        initialBinding,
        prekeySelection,
    )
    bob.commitOperation(prepared.operation.identifier)
    bob.finalizeOperation(prepared.operation.identifier)
    requireCoverage(
        prepared.acceptance.plaintext.contentEquals("transport-bound hello".encodeToByteArray()),
        "transport-bound Session acceptance",
    )

    val engine = ProtocolStateEngine()
    val aliceSnapshot = mutableListOf<ProtocolStateEntry>()
    applyUpdates(aliceSnapshot, initiation.stateUpdates)
    val bobSnapshot = mutableListOf<ProtocolStateEntry>()
    applyUpdates(bobSnapshot, prepared.acceptance.stateUpdates)
    applyUpdates(
        aliceSnapshot,
        engine.recordContact(
            aliceSnapshot.toList(),
            contactIdentity(bobIdentity, bobPublication),
        ).stateUpdates,
    )
    applyUpdates(
        aliceSnapshot,
        engine.acceptContact(aliceSnapshot.toList(), identityKey(bobIdentity)).stateUpdates,
    )

    val authority = DevelopmentCertificateAuthority(
        "transport-bindings".encodeToByteArray(),
        "relay.test".encodeToByteArray(),
    )
    val aliceCertificate = authority.issue(aliceIdentity, 1_800_000_000uL)
    val bobCertificate = authority.issue(bobIdentity, 1_800_000_000uL)
    val validation = authority.senderCertificateValidation(1_700_000_000uL, 0uL)
    val messageBinding = TransportBinding("consumer-owned message metadata".encodeToByteArray())
    val acknowledgmentBinding =
        TransportBinding("consumer-owned acknowledgment metadata".encodeToByteArray())
    val outbound = alice.encryptMessageWithTransportBinding(
        aliceSnapshot.toList(),
        sessionKey,
        ByteArray(16) { 0x59 },
        identityKey(bobIdentity),
        bobPublication.discoveryKey.publicKey,
        1_700_000_000_100uL,
        aliceCertificate.certificate,
        aliceCertificate.signature,
        "transport-bound follow-up".encodeToByteArray(),
        messageBinding,
    )
    applyUpdates(aliceSnapshot, outbound.stateUpdates)
    val deduplicationKey = "binding-dedup".encodeToByteArray()
    applyUpdates(
        bobSnapshot,
        listOf(engine.initializeDeduplicationSet(deduplicationKey)),
    )
    val changedMessageBinding =
        TransportBinding("changed consumer-owned message metadata".encodeToByteArray())
    expectAuthenticationFailed("established decryption with changed binding bytes") {
        bob.decryptMessageWithTransportBindings(
            bobSnapshot.toList(),
            sessionKey,
            deduplicationKey,
            outbound.message,
            ByteArray(16) { 0x5a },
            alicePublication.discoveryKey.publicKey,
            1_700_000_000_101uL,
            bobCertificate.certificate,
            bobCertificate.signature,
            validation,
            changedMessageBinding,
            acknowledgmentBinding,
        )
    }
    val inbound = bob.decryptMessageWithTransportBindings(
        bobSnapshot.toList(),
        sessionKey,
        deduplicationKey,
        outbound.message,
        ByteArray(16) { 0x5a },
        alicePublication.discoveryKey.publicKey,
        1_700_000_000_101uL,
        bobCertificate.certificate,
        bobCertificate.signature,
        validation,
        messageBinding,
        acknowledgmentBinding,
    )
    val accepted = (inbound as? InboundMessageOutcome.Accepted)?.result ?: failCoverage("expected accepted Message")
    requireCoverage(
        accepted.plaintext.contentEquals("transport-bound follow-up".encodeToByteArray()) == true,
        "transport-bound Message plaintext",
    )
    val acknowledgment = accepted.acknowledgment
    val changedAcknowledgmentBinding =
        TransportBinding("changed consumer-owned acknowledgment metadata".encodeToByteArray())
    expectAuthenticationFailed("acknowledgment with changed binding bytes") {
        alice.processAcknowledgmentWithTransportBinding(
            aliceSnapshot.toList(),
            sessionKey,
            acknowledgment,
            changedAcknowledgmentBinding,
        )
    }
    val acknowledgmentOutcome = alice.processAcknowledgmentWithTransportBinding(
        aliceSnapshot.toList(),
        sessionKey,
        acknowledgment,
        acknowledgmentBinding,
    )
    requireCoverage(
        acknowledgmentOutcome is AcknowledgmentOutcome.Cleared,
        "transport-bound acknowledgment clearing",
    )

    println("Kotlin Transport Binding coverage passed")
}

private fun expectMismatchedPrekeySelection(
    store: KeyStore,
    message: Message,
    transportBinding: TransportBinding,
    prekeySelection: PreKeySelection,
) {
    val oneTimeIdentifier = prekeySelection.oneTimePrekeyIdentifier
        ?: failCoverage("selected prekeys should include a one-time-prekey identifier")
    val mismatched = PreKeySelection(
        prekeySelection.signedPrekeyIdentifier,
        oneTimeIdentifier + 1uL,
    )
    try {
        store.initiatorIdentityHintWithTransportBinding(message, transportBinding, mismatched)
        failCoverage("mismatched one-time-prekey identifier should reject")
    } catch (_: ClientException.AuthenticationFailed) {
    }
}

private fun expectInvalidData(message: String, operation: () -> Unit) {
    try {
        operation()
        failCoverage("$message should reject")
    } catch (_: ClientException.InvalidData) {
    }
}

private fun expectAuthenticationFailed(message: String, operation: () -> Unit) {
    try {
        operation()
        failCoverage("$message should reject")
    } catch (_: ClientException.AuthenticationFailed) {
    }
}

private fun generateIdentity(store: KeyStore): Identity {
    val prepared = store.prepareGenerateIdentity()
    completeOperation(store, prepared.operation)
    return prepared.identity
}

private fun rotateSignedPrekey(store: KeyStore) {
    val prepared = store.prepareRotateSignedPrekeyNow()
    completeOperation(store, prepared.operation)
}

private fun replenishOneTimePrekeys(store: KeyStore): List<OneTimePreKeyBundle> {
    val prepared = store.prepareReplenishOneTimePrekeys()
    completeOperation(store, prepared.operation)
    return prepared.oneTimePrekeys
}

private fun completeOperation(store: KeyStore, operation: KeyStoreOperation) {
    store.commitOperation(operation.identifier)
    store.finalizeOperation(operation.identifier)
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

private fun applyUpdates(
    snapshot: MutableList<ProtocolStateEntry>,
    updates: List<ProtocolStateUpdate>,
) {
    for (update in updates) {
        snapshot.removeAll { it.kind == update.kind && it.key.contentEquals(update.key) }
        update.blob?.let { snapshot.add(ProtocolStateEntry(update.kind, update.key, it)) }
    }
}

private fun requireCoverage(condition: Boolean, message: String) {
    if (!condition) {
        failCoverage(message)
    }
}

private fun failCoverage(message: String): Nothing {
    throw IllegalStateException("Transport Binding coverage failed: $message")
}
