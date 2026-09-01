package com.aurelion.aether

private class RelayRouteMemoryStorage : SecureStorage {
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
    exerciseRouteEncodingBoundaries()

    val alice = KeyStore(RelayRouteMemoryStorage())
    val bob = KeyStore(RelayRouteMemoryStorage())
    val aliceIdentity = generateRouteIdentity(alice)
    val bobIdentity = generateRouteIdentity(bob)
    rotateRouteSignedPrekey(alice)
    rotateRouteSignedPrekey(bob)
    val alicePublication = alice.currentPublicationBundle()
    val bobPublication = bob.currentPublicationBundle()
    val bobOneTimePrekey = replenishRouteOneTimePrekeys(bob)[0]
    val initialRoute = RelayRoute(
        1u,
        RelayRouteKind.INITIAL,
        bobPublication.discoveryKey.verifyingKey,
        RelayPreKeyReference(
            bobPublication.signedPrekey.identifier,
            bobOneTimePrekey.identifier,
        ),
    )
    val sessionKey = ByteArray(16) { 0x58 }
    val initiation = alice.initiateSessionWithRelayRoute(
        sessionKey,
        bobIdentity,
        bobPublication,
        bobOneTimePrekey,
        "alice certificate".encodeToByteArray(),
        "alice signature".encodeToByteArray(),
        "route-bound hello".encodeToByteArray(),
        initialRoute,
    )
    val hint = bob.initiatorIdentityHintWithRelayRoute(initiation.message, initialRoute)
    requireRoute(
        hint.ed25519VerifyingKey.contentEquals(aliceIdentity.ed25519VerifyingKey),
        "route-bound initiator identity hint",
    )

    expectRejectedRoute(bob, initiation.message, initialRoute)

    val prepared = bob.prepareAcceptSessionWithRelayRoute(
        sessionKey,
        null,
        initiation.message,
        initialRoute,
    )
    bob.commitOperation(prepared.operation.identifier)
    bob.finalizeOperation(prepared.operation.identifier)
    requireRoute(
        prepared.acceptance.plaintext.contentEquals("route-bound hello".encodeToByteArray()),
        "route-bound Session acceptance",
    )

    val engine = ProtocolStateEngine()
    val aliceSnapshot = mutableListOf<ProtocolStateEntry>()
    applyRouteUpdates(aliceSnapshot, initiation.stateUpdates)
    val bobSnapshot = mutableListOf<ProtocolStateEntry>()
    applyRouteUpdates(bobSnapshot, prepared.acceptance.stateUpdates)
    applyRouteUpdates(
        aliceSnapshot,
        engine.recordContact(
            aliceSnapshot.toList(),
            routeContactIdentity(bobIdentity, bobPublication),
        ).stateUpdates,
    )
    applyRouteUpdates(
        aliceSnapshot,
        engine.acceptContact(aliceSnapshot.toList(), routeIdentityKey(bobIdentity)).stateUpdates,
    )

    val authority = DevelopmentCertificateAuthority(
        "route-bindings".encodeToByteArray(),
        "relay.test".encodeToByteArray(),
    )
    val aliceCertificate = authority.issue(aliceIdentity, 1_800_000_000uL)
    val bobCertificate = authority.issue(bobIdentity, 1_800_000_000uL)
    val validation = authority.senderCertificateValidation(1_700_000_000uL, 0uL)
    val messageRoute = RelayRoute(
        1u,
        RelayRouteKind.ESTABLISHED,
        bobIdentity.ed25519VerifyingKey,
        null,
    )
    val acknowledgmentRoute = RelayRoute(
        1u,
        RelayRouteKind.ESTABLISHED,
        aliceIdentity.ed25519VerifyingKey,
        null,
    )
    val wrongMessageRecipientRoute = RelayRoute(
        1u,
        RelayRouteKind.ESTABLISHED,
        ByteArray(32) { 0x60 },
        null,
    )
    expectRelayRouteRejected("established encryption with the wrong recipient") {
        alice.encryptMessageWithRelayRoute(
            aliceSnapshot.toList(),
            sessionKey,
            ByteArray(16) { 0x61 },
            routeIdentityKey(bobIdentity),
            bobPublication.discoveryKey.publicKey,
            1_700_000_000_099uL,
            aliceCertificate.certificate,
            aliceCertificate.signature,
            "wrong route".encodeToByteArray(),
            wrongMessageRecipientRoute,
        )
    }
    val outbound = alice.encryptMessageWithRelayRoute(
        aliceSnapshot.toList(),
        sessionKey,
        ByteArray(16) { 0x59 },
        routeIdentityKey(bobIdentity),
        bobPublication.discoveryKey.publicKey,
        1_700_000_000_100uL,
        aliceCertificate.certificate,
        aliceCertificate.signature,
        "route-bound follow-up".encodeToByteArray(),
        messageRoute,
    )
    applyRouteUpdates(aliceSnapshot, outbound.stateUpdates)
    val deduplicationKey = "route-dedup".encodeToByteArray()
    applyRouteUpdates(
        bobSnapshot,
        listOf(engine.initializeDeduplicationSet(deduplicationKey)),
    )
    val changedMessageVersionRoute = RelayRoute(
        2u,
        RelayRouteKind.ESTABLISHED,
        bobIdentity.ed25519VerifyingKey,
        null,
    )
    expectAuthenticationFailed("established decryption with a changed route version") {
        bob.decryptMessageWithRelayRoutes(
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
            changedMessageVersionRoute,
            acknowledgmentRoute,
        )
    }
    val inbound = bob.decryptMessageWithRelayRoutes(
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
        messageRoute,
        acknowledgmentRoute,
    )
    requireRoute(inbound.kind == InboundMessageOutcomeKind.ACCEPTED, "route-bound Message acceptance")
    requireRoute(
        inbound.plaintext?.contentEquals("route-bound follow-up".encodeToByteArray()) == true,
        "route-bound Message plaintext",
    )
    val acknowledgment = inbound.acknowledgment
        ?: failRoute("accepted Message should return an acknowledgment")
    val wrongAcknowledgmentRecipientRoute = RelayRoute(
        1u,
        RelayRouteKind.ESTABLISHED,
        ByteArray(32) { 0x62 },
        null,
    )
    expectRelayRouteRejected("acknowledgment with the wrong recipient") {
        alice.processAcknowledgmentWithRelayRoute(
            aliceSnapshot.toList(),
            sessionKey,
            acknowledgment,
            wrongAcknowledgmentRecipientRoute,
        )
    }
    val changedAcknowledgmentVersionRoute = RelayRoute(
        2u,
        RelayRouteKind.ESTABLISHED,
        aliceIdentity.ed25519VerifyingKey,
        null,
    )
    expectAuthenticationFailed("acknowledgment with a changed route version") {
        alice.processAcknowledgmentWithRelayRoute(
            aliceSnapshot.toList(),
            sessionKey,
            acknowledgment,
            changedAcknowledgmentVersionRoute,
        )
    }
    val acknowledgmentOutcome = alice.processAcknowledgmentWithRelayRoute(
        aliceSnapshot.toList(),
        sessionKey,
        acknowledgment,
        acknowledgmentRoute,
    )
    requireRoute(
        acknowledgmentOutcome.kind == AcknowledgmentOutcomeKind.CLEARED,
        "route-bound acknowledgment clearing",
    )

    println("Kotlin Relay Route binding coverage passed")
}

private fun exerciseRouteEncodingBoundaries() {
    val route = RelayRoute(
        UShort.MAX_VALUE,
        RelayRouteKind.INITIAL,
        ByteArray(32) { 0x44 },
        RelayPreKeyReference(ULong.MAX_VALUE, ULong.MAX_VALUE),
    )
    val associatedData = encodeRelayRouteAssociatedData(route)
    requireRoute(associatedData.size == 68, "maximum route encoded length")
    requireRoute(
        associatedData.copyOfRange(51, 59).all { it == 0xff.toByte() },
        "maximum signed prekey identifier",
    )
    requireRoute(
        associatedData.copyOfRange(60, 68).all { it == 0xff.toByte() },
        "maximum one-time prekey identifier",
    )
    verifyRelayRouteAssociatedData(route, associatedData)

    val tampered = associatedData.copyOf()
    tampered[0] = (tampered[0].toInt() xor 1).toByte()
    try {
        verifyRelayRouteAssociatedData(route, tampered)
        failRoute("tampered associated data should reject")
    } catch (_: AetherException.RelayRouteRejected) {
    }

    val malformed = RelayRoute(
        1u,
        RelayRouteKind.ESTABLISHED,
        ByteArray(32) { 0x44 },
        RelayPreKeyReference(0uL, null),
    )
    try {
        encodeRelayRouteAssociatedData(malformed)
        failRoute("malformed established route should reject")
    } catch (_: AetherException.InvalidData) {
    }
}

private fun expectRejectedRoute(store: KeyStore, message: Message, route: RelayRoute) {
    val reference = route.prekeyReference
        ?: failRoute("initial route should include a prekey reference")
    val oneTimeIdentifier = reference.oneTimePrekeyIdentifier
        ?: failRoute("initial route should include a one-time-prekey identifier")
    val mismatched = RelayRoute(
        route.protocolVersion,
        route.kind,
        route.recipientSigningKey,
        RelayPreKeyReference(reference.signedPrekeyIdentifier, oneTimeIdentifier + 1uL),
    )
    try {
        store.initiatorIdentityHintWithRelayRoute(message, mismatched)
        failRoute("mismatched one-time-prekey identifier should reject")
    } catch (_: AetherException.RelayRouteRejected) {
    }
}

private fun expectRelayRouteRejected(message: String, operation: () -> Unit) {
    try {
        operation()
        failRoute("$message should reject")
    } catch (_: AetherException.RelayRouteRejected) {
    }
}

private fun expectAuthenticationFailed(message: String, operation: () -> Unit) {
    try {
        operation()
        failRoute("$message should reject")
    } catch (_: AetherException.AuthenticationFailed) {
    }
}

private fun generateRouteIdentity(store: KeyStore): Identity {
    val prepared = store.prepareGenerateIdentity()
    completeRouteOperation(store, prepared.operation)
    return prepared.identity
}

private fun rotateRouteSignedPrekey(store: KeyStore) {
    val prepared = store.prepareRotateSignedPrekeyNow()
    completeRouteOperation(store, prepared.operation)
}

private fun replenishRouteOneTimePrekeys(store: KeyStore): List<OneTimePreKeyBundle> {
    val prepared = store.prepareReplenishOneTimePrekeys()
    completeRouteOperation(store, prepared.operation)
    return prepared.oneTimePrekeys
}

private fun completeRouteOperation(store: KeyStore, operation: KeyStoreOperation) {
    store.commitOperation(operation.identifier)
    store.finalizeOperation(operation.identifier)
}

private fun routeIdentityKey(identity: Identity) = IdentityKey(
    identity.x25519PublicKey,
    identity.ed25519VerifyingKey,
)

private fun routeContactIdentity(identity: Identity, publication: PublicationBundle) = ContactIdentity(
    routeIdentityKey(identity),
    ContactDiscoveryKey(
        publication.discoveryKey.publicKey,
        publication.discoveryKey.verifyingKey,
        publication.discoveryKey.epoch,
        publication.discoveryKey.createdAt,
        publication.discoveryKey.signature,
    ),
)

private fun applyRouteUpdates(
    snapshot: MutableList<ProtocolStateEntry>,
    updates: List<ProtocolStateUpdate>,
) {
    for (update in updates) {
        snapshot.removeAll { it.kind == update.kind && it.key.contentEquals(update.key) }
        update.blob?.let { snapshot.add(ProtocolStateEntry(update.kind, update.key, it)) }
    }
}

private fun requireRoute(condition: Boolean, message: String) {
    if (!condition) {
        failRoute(message)
    }
}

private fun failRoute(message: String): Nothing {
    throw IllegalStateException("Relay Route binding coverage failed: $message")
}
