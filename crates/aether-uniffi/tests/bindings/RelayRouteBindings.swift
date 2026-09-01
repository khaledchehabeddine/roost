import Foundation

private final class RelayRouteMemoryStorage: SecureStorage, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: Data] = [:]

    func store(key: String, value: Data) throws {
        lock.lock()
        values[key] = value
        lock.unlock()
    }

    func load(key: String) throws -> Data? {
        lock.lock()
        let value = values[key]
        lock.unlock()
        return value
    }

    func delete(key: String) throws {
        lock.lock()
        values.removeValue(forKey: key)
        lock.unlock()
    }
}

@main
struct RelayRouteBindings {
    static func main() throws {
        try exerciseRouteEncodingBoundaries()

        let alice = KeyStore(storage: RelayRouteMemoryStorage())
        let bob = KeyStore(storage: RelayRouteMemoryStorage())
        let aliceIdentity = try generateIdentity(alice)
        let bobIdentity = try generateIdentity(bob)
        try rotateSignedPrekey(alice)
        try rotateSignedPrekey(bob)
        let bobPublication = try bob.currentPublicationBundle()
        let bobOneTimePrekey = try replenishOneTimePrekeys(bob)[0]
        let initialRoute = RelayRoute(
            protocolVersion: 1,
            kind: .initial,
            recipientSigningKey: bobPublication.discoveryKey.verifyingKey,
            prekeyReference: RelayPreKeyReference(
                signedPrekeyIdentifier: bobPublication.signedPrekey.identifier,
                oneTimePrekeyIdentifier: bobOneTimePrekey.identifier
            )
        )
        let sessionKey = Data(repeating: 0x58, count: 16)
        let initiation = try alice.initiateSessionWithRelayRoute(
            sessionKey: sessionKey,
            responderIdentity: bobIdentity,
            responderPublication: bobPublication,
            responderOneTimePrekey: bobOneTimePrekey,
            senderCertificate: Data("alice certificate".utf8),
            senderSignature: Data("alice signature".utf8),
            plaintext: Data("route-bound hello".utf8),
            route: initialRoute
        )
        let hint = try bob.initiatorIdentityHintWithRelayRoute(
            message: initiation.message,
            route: initialRoute
        )
        require(
            hint.ed25519VerifyingKey == aliceIdentity.ed25519VerifyingKey,
            "route-bound initiator identity hint"
        )

        expectRejectedRoute(bob, message: initiation.message, route: initialRoute)

        let prepared = try bob.prepareAcceptSessionWithRelayRoute(
            sessionKey: sessionKey,
            initiatorIdentity: nil,
            message: initiation.message,
            route: initialRoute
        )
        _ = try bob.commitOperation(identifier: prepared.operation.identifier)
        _ = try bob.finalizeOperation(identifier: prepared.operation.identifier)
        require(prepared.acceptance.plaintext == Data("route-bound hello".utf8), "route-bound Session acceptance")

        var aliceSnapshot: [ProtocolStateEntry] = []
        apply(&aliceSnapshot, updates: initiation.stateUpdates)
        var bobSnapshot: [ProtocolStateEntry] = []
        apply(&bobSnapshot, updates: prepared.acceptance.stateUpdates)
        let engine = ProtocolStateEngine()
        let recorded = try engine.recordContact(
            snapshot: aliceSnapshot,
            contactIdentity: contactIdentity(identity: bobIdentity, publication: bobPublication)
        )
        apply(&aliceSnapshot, updates: recorded.stateUpdates)
        let acceptedContact = try engine.acceptContact(
            snapshot: aliceSnapshot,
            identityKey: identityKey(bobIdentity)
        )
        apply(&aliceSnapshot, updates: acceptedContact.stateUpdates)

        let authority = try DevelopmentCertificateAuthority(
            signingKeyIdentifier: Data("route-bindings".utf8),
            relayDomain: Data("relay.test".utf8)
        )
        let aliceCertificate = try authority.issue(identity: aliceIdentity, expiresAtSecs: 1_800_000_000)
        let bobCertificate = try authority.issue(identity: bobIdentity, expiresAtSecs: 1_800_000_000)
        let validation = authority.senderCertificateValidation(
            referenceTimestampSecs: 1_700_000_000,
            graceWindowSecs: 0
        )
        let messageRoute = RelayRoute(
            protocolVersion: 1,
            kind: .established,
            recipientSigningKey: bobIdentity.ed25519VerifyingKey,
            prekeyReference: nil
        )
        let acknowledgmentRoute = RelayRoute(
            protocolVersion: 1,
            kind: .established,
            recipientSigningKey: aliceIdentity.ed25519VerifyingKey,
            prekeyReference: nil
        )
        let wrongMessageRecipientRoute = RelayRoute(
            protocolVersion: 1,
            kind: .established,
            recipientSigningKey: Data(repeating: 0x60, count: 32),
            prekeyReference: nil
        )
        expectRelayRouteRejected("established encryption with the wrong recipient") {
            _ = try alice.encryptMessageWithRelayRoute(
                snapshot: aliceSnapshot,
                sessionKey: sessionKey,
                messageId: Data(repeating: 0x61, count: 16),
                contactIdentityKey: identityKey(bobIdentity),
                recipientPublicKey: bobPublication.discoveryKey.publicKey,
                timestampMillis: 1_700_000_000_099,
                senderCertificate: aliceCertificate.certificate,
                senderSignature: aliceCertificate.signature,
                plaintext: Data("wrong route".utf8),
                route: wrongMessageRecipientRoute
            )
        }
        let outbound = try alice.encryptMessageWithRelayRoute(
            snapshot: aliceSnapshot,
            sessionKey: sessionKey,
            messageId: Data(repeating: 0x59, count: 16),
            contactIdentityKey: identityKey(bobIdentity),
            recipientPublicKey: bobPublication.discoveryKey.publicKey,
            timestampMillis: 1_700_000_000_100,
            senderCertificate: aliceCertificate.certificate,
            senderSignature: aliceCertificate.signature,
            plaintext: Data("route-bound follow-up".utf8),
            route: messageRoute
        )
        apply(&aliceSnapshot, updates: outbound.stateUpdates)
        let deduplicationKey = Data("route-dedup".utf8)
        apply(
            &bobSnapshot,
            updates: [try engine.initializeDeduplicationSet(key: deduplicationKey)]
        )
        let changedMessageVersionRoute = RelayRoute(
            protocolVersion: 2,
            kind: .established,
            recipientSigningKey: bobIdentity.ed25519VerifyingKey,
            prekeyReference: nil
        )
        expectAuthenticationFailed("established decryption with a changed route version") {
            _ = try bob.decryptMessageWithRelayRoutes(
                snapshot: bobSnapshot,
                sessionKey: sessionKey,
                deduplicationKey: deduplicationKey,
                message: outbound.message,
                acknowledgmentId: Data(repeating: 0x5a, count: 16),
                acknowledgmentRecipientPublicKey: (try alice.currentPublicationBundle()).discoveryKey.publicKey,
                acknowledgmentTimestampMillis: 1_700_000_000_101,
                acknowledgmentSenderCertificate: bobCertificate.certificate,
                acknowledgmentSenderSignature: bobCertificate.signature,
                senderCertificateValidation: validation,
                messageRoute: changedMessageVersionRoute,
                acknowledgmentRoute: acknowledgmentRoute
            )
        }
        let inbound = try bob.decryptMessageWithRelayRoutes(
            snapshot: bobSnapshot,
            sessionKey: sessionKey,
            deduplicationKey: deduplicationKey,
            message: outbound.message,
            acknowledgmentId: Data(repeating: 0x5a, count: 16),
            acknowledgmentRecipientPublicKey: (try alice.currentPublicationBundle()).discoveryKey.publicKey,
            acknowledgmentTimestampMillis: 1_700_000_000_101,
            acknowledgmentSenderCertificate: bobCertificate.certificate,
            acknowledgmentSenderSignature: bobCertificate.signature,
            senderCertificateValidation: validation,
            messageRoute: messageRoute,
            acknowledgmentRoute: acknowledgmentRoute
        )
        require(inbound.kind == .accepted, "route-bound Message acceptance")
        require(inbound.plaintext == Data("route-bound follow-up".utf8), "route-bound Message plaintext")
        guard let acknowledgment = inbound.acknowledgment else {
            fail("accepted Message should return an acknowledgment")
        }
        let wrongAcknowledgmentRecipientRoute = RelayRoute(
            protocolVersion: 1,
            kind: .established,
            recipientSigningKey: Data(repeating: 0x62, count: 32),
            prekeyReference: nil
        )
        expectRelayRouteRejected("acknowledgment with the wrong recipient") {
            _ = try alice.processAcknowledgmentWithRelayRoute(
                snapshot: aliceSnapshot,
                sessionKey: sessionKey,
                message: acknowledgment,
                route: wrongAcknowledgmentRecipientRoute
            )
        }
        let changedAcknowledgmentVersionRoute = RelayRoute(
            protocolVersion: 2,
            kind: .established,
            recipientSigningKey: aliceIdentity.ed25519VerifyingKey,
            prekeyReference: nil
        )
        expectAuthenticationFailed("acknowledgment with a changed route version") {
            _ = try alice.processAcknowledgmentWithRelayRoute(
                snapshot: aliceSnapshot,
                sessionKey: sessionKey,
                message: acknowledgment,
                route: changedAcknowledgmentVersionRoute
            )
        }
        let acknowledgmentOutcome = try alice.processAcknowledgmentWithRelayRoute(
            snapshot: aliceSnapshot,
            sessionKey: sessionKey,
            message: acknowledgment,
            route: acknowledgmentRoute
        )
        require(acknowledgmentOutcome.kind == .cleared, "route-bound acknowledgment clearing")

        print("Swift Relay Route binding coverage passed")
    }

    private static func exerciseRouteEncodingBoundaries() throws {
        let route = RelayRoute(
            protocolVersion: UInt16.max,
            kind: .initial,
            recipientSigningKey: Data(repeating: 0x44, count: 32),
            prekeyReference: RelayPreKeyReference(
                signedPrekeyIdentifier: UInt64.max,
                oneTimePrekeyIdentifier: UInt64.max
            )
        )
        let associatedData = try encodeRelayRouteAssociatedData(route: route)
        require(associatedData.count == 68, "maximum route encoded length")
        require(associatedData[51..<59] == Data(repeating: 0xff, count: 8), "maximum signed prekey identifier")
        require(associatedData[60..<68] == Data(repeating: 0xff, count: 8), "maximum one-time prekey identifier")
        try verifyRelayRouteAssociatedData(route: route, associatedData: associatedData)

        var tampered = associatedData
        tampered[tampered.startIndex] ^= 0x01
        do {
            try verifyRelayRouteAssociatedData(route: route, associatedData: tampered)
            fail("tampered associated data should reject")
        } catch let error as AetherError {
            guard case .RelayRouteRejected(_) = error else {
                fail("unexpected tampered-route error \(error)")
            }
        }

        let malformed = RelayRoute(
            protocolVersion: 1,
            kind: .established,
            recipientSigningKey: Data(repeating: 0x44, count: 32),
            prekeyReference: RelayPreKeyReference(
                signedPrekeyIdentifier: 0,
                oneTimePrekeyIdentifier: nil
            )
        )
        do {
            _ = try encodeRelayRouteAssociatedData(route: malformed)
            fail("malformed established route should reject")
        } catch let error as AetherError {
            guard case .InvalidData(_) = error else {
                fail("unexpected malformed-route error \(error)")
            }
        }
    }

    private static func expectRejectedRoute(
        _ store: KeyStore,
        message: Message,
        route: RelayRoute
    ) {
        let mismatched = RelayRoute(
            protocolVersion: route.protocolVersion,
            kind: route.kind,
            recipientSigningKey: route.recipientSigningKey,
            prekeyReference: RelayPreKeyReference(
                signedPrekeyIdentifier: route.prekeyReference!.signedPrekeyIdentifier,
                oneTimePrekeyIdentifier: route.prekeyReference!.oneTimePrekeyIdentifier! + 1
            )
        )
        do {
            _ = try store.initiatorIdentityHintWithRelayRoute(message: message, route: mismatched)
            fail("mismatched one-time-prekey identifier should reject")
        } catch let error as AetherError {
            guard case .RelayRouteRejected(_) = error else {
                fail("unexpected mismatched-route error \(error)")
            }
        } catch {
            fail("unexpected mismatched-route error \(error)")
        }
    }

    private static func expectRelayRouteRejected(
        _ message: String,
        operation: () throws -> Void
    ) {
        do {
            try operation()
            fail("\(message) should reject")
        } catch let error as AetherError {
            guard case .RelayRouteRejected(_) = error else {
                fail("unexpected \(message) error \(error)")
            }
        } catch {
            fail("unexpected \(message) error \(error)")
        }
    }

    private static func expectAuthenticationFailed(
        _ message: String,
        operation: () throws -> Void
    ) {
        do {
            try operation()
            fail("\(message) should reject")
        } catch let error as AetherError {
            guard case .AuthenticationFailed(_) = error else {
                fail("unexpected \(message) error \(error)")
            }
        } catch {
            fail("unexpected \(message) error \(error)")
        }
    }

    private static func generateIdentity(_ store: KeyStore) throws -> Identity {
        let prepared = try store.prepareGenerateIdentity()
        try complete(store, operation: prepared.operation)
        return prepared.identity
    }

    private static func rotateSignedPrekey(_ store: KeyStore) throws {
        let prepared = try store.prepareRotateSignedPrekeyNow()
        try complete(store, operation: prepared.operation)
    }

    private static func replenishOneTimePrekeys(_ store: KeyStore) throws -> [OneTimePreKeyBundle] {
        let prepared = try store.prepareReplenishOneTimePrekeys()
        try complete(store, operation: prepared.operation)
        return prepared.oneTimePrekeys
    }

    private static func complete(_ store: KeyStore, operation: KeyStoreOperation) throws {
        _ = try store.commitOperation(identifier: operation.identifier)
        _ = try store.finalizeOperation(identifier: operation.identifier)
    }

    private static func identityKey(_ identity: Identity) -> IdentityKey {
        IdentityKey(
            x25519PublicKey: identity.x25519PublicKey,
            ed25519VerifyingKey: identity.ed25519VerifyingKey
        )
    }

    private static func contactIdentity(
        identity: Identity,
        publication: PublicationBundle
    ) -> ContactIdentity {
        ContactIdentity(
            identityKey: identityKey(identity),
            discoveryKey: ContactDiscoveryKey(
                x25519PublicKey: publication.discoveryKey.publicKey,
                ed25519VerifyingKey: publication.discoveryKey.verifyingKey,
                epoch: publication.discoveryKey.epoch,
                createdAt: publication.discoveryKey.createdAt,
                identitySignature: publication.discoveryKey.signature
            )
        )
    }

    private static func apply(
        _ snapshot: inout [ProtocolStateEntry],
        updates: [ProtocolStateUpdate]
    ) {
        for update in updates {
            snapshot.removeAll { $0.kind == update.kind && $0.key == update.key }
            if let blob = update.blob {
                snapshot.append(ProtocolStateEntry(kind: update.kind, key: update.key, blob: blob))
            }
        }
    }

    private static func require(_ condition: @autoclosure () -> Bool, _ message: String) {
        if !condition() {
            fail(message)
        }
    }

    private static func fail(_ message: String) -> Never {
        fputs("Relay Route binding coverage failed: \(message)\n", stderr)
        exit(1)
    }
}
