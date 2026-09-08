import Foundation

private final class TransportBindingMemoryStorage: SecureStorage, @unchecked Sendable {
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
struct TransportBindingBindings {
    static func main() throws {
        let alice = Client(storage: TransportBindingMemoryStorage())
        let bob = Client(storage: TransportBindingMemoryStorage())
        let aliceIdentity = try generateIdentity(alice)
        let bobIdentity = try generateIdentity(bob)
        try rotateSignedPrekey(alice)
        try rotateSignedPrekey(bob)
        let bobPublication = try bob.identity().currentPublicationBundle()
        let bobOneTimePrekey = try replenishOneTimePrekeys(bob)[0]
        let initialBinding = TransportBinding(bytes: Data("consumer-owned initial metadata".utf8))
        let prekeySelection = PreKeySelection(
            signedPrekeyIdentifier: bobPublication.signedPrekey.identifier,
            oneTimePrekeyIdentifier: bobOneTimePrekey.identifier
        )
        let sessionKey = Data(repeating: 0x58, count: 16)
        expectInvalidData("empty Transport Binding") {
            _ = try alice.messaging().initiateSession(
                sessionKey: sessionKey,
                responderIdentity: bobIdentity,
                responderPublication: bobPublication,
                responderOneTimePrekey: bobOneTimePrekey,
                senderCertificate: Data("alice certificate".utf8),
                senderSignature: Data("alice signature".utf8),
                plaintext: Data("rejected".utf8),
                transportBinding: TransportBinding(bytes: Data())
            )
        }
        expectInvalidData("oversized Transport Binding") {
            _ = try alice.messaging().initiateSession(
                sessionKey: sessionKey,
                responderIdentity: bobIdentity,
                responderPublication: bobPublication,
                responderOneTimePrekey: bobOneTimePrekey,
                senderCertificate: Data("alice certificate".utf8),
                senderSignature: Data("alice signature".utf8),
                plaintext: Data("rejected".utf8),
                transportBinding: TransportBinding(bytes: Data(repeating: 0x41, count: 1_025))
            )
        }
        let initiation = try alice.messaging().initiateSession(
            sessionKey: sessionKey,
            responderIdentity: bobIdentity,
            responderPublication: bobPublication,
            responderOneTimePrekey: bobOneTimePrekey,
            senderCertificate: Data("alice certificate".utf8),
            senderSignature: Data("alice signature".utf8),
            plaintext: Data("transport-bound hello".utf8),
            transportBinding: initialBinding
        )
        let hint = try bob.messaging().initiatorIdentityHint(
            message: initiation.message,
            transportBinding: initialBinding,
            prekeySelection: prekeySelection
        )
        require(
            hint.ed25519VerifyingKey == aliceIdentity.ed25519VerifyingKey,
            "transport-bound initiator identity hint"
        )

        expectMismatchedPrekeySelection(
            bob,
            message: initiation.message,
            transportBinding: initialBinding,
            prekeySelection: prekeySelection
        )
        expectAuthenticationFailed("maximum unsigned prekey identifiers") {
            _ = try bob.messaging().initiatorIdentityHint(
                message: initiation.message,
                transportBinding: initialBinding,
                prekeySelection: PreKeySelection(
                    signedPrekeyIdentifier: UInt64.max,
                    oneTimePrekeyIdentifier: UInt64.max
                )
            )
        }

        let prepared = try bob.messaging().prepareAcceptSession(
            sessionKey: sessionKey,
            initiatorIdentity: nil,
            message: initiation.message,
            transportBinding: initialBinding,
            prekeySelection: prekeySelection
        )
        _ = try bob.commitOperation(identifier: prepared.operation.identifier)
        _ = try bob.finalizeOperation(identifier: prepared.operation.identifier)
        require(prepared.acceptance.plaintext == Data("transport-bound hello".utf8), "transport-bound Session acceptance")

        var aliceSnapshot: [ProtocolStateEntry] = []
        apply(&aliceSnapshot, updates: initiation.stateUpdates)
        var bobSnapshot: [ProtocolStateEntry] = []
        apply(&bobSnapshot, updates: prepared.acceptance.stateUpdates)
        let contacts = alice.contacts()
        let messaging = bob.messaging()
        let recorded = try contacts.recordContact(
            snapshot: aliceSnapshot,
            contactIdentity: contactIdentity(identity: bobIdentity, publication: bobPublication)
        )
        apply(&aliceSnapshot, updates: recorded.stateUpdates)
        let acceptedContact = try contacts.acceptContact(
            snapshot: aliceSnapshot,
            identityKey: identityKey(bobIdentity)
        )
        apply(&aliceSnapshot, updates: acceptedContact.stateUpdates)

        let authority = try DevelopmentCertificateAuthority(
            signingKeyIdentifier: Data("transport-bindings".utf8),
            relayDomain: Data("relay.test".utf8)
        )
        let aliceCertificate = try authority.issue(identity: aliceIdentity, expiresAtSecs: 1_800_000_000)
        let bobCertificate = try authority.issue(identity: bobIdentity, expiresAtSecs: 1_800_000_000)
        let validation = authority.senderCertificateValidation(
            referenceTimestampSecs: 1_700_000_000,
            graceWindowSecs: 0
        )
        let messageBinding = TransportBinding(bytes: Data("consumer-owned message metadata".utf8))
        let acknowledgmentBinding = TransportBinding(
            bytes: Data("consumer-owned acknowledgment metadata".utf8)
        )
        let outbound = try alice.messaging().encryptMessage(
            snapshot: aliceSnapshot,
            sessionKey: sessionKey,
            messageId: Data(repeating: 0x59, count: 16),
            contactIdentityKey: identityKey(bobIdentity),
            recipientPublicKey: bobPublication.discoveryKey.publicKey,
            timestampMillis: 1_700_000_000_100,
            senderCertificate: aliceCertificate.certificate,
            senderSignature: aliceCertificate.signature,
            plaintext: Data("transport-bound follow-up".utf8),
            transportBinding: messageBinding
        )
        apply(&aliceSnapshot, updates: outbound.stateUpdates)
        let deduplicationKey = Data("binding-dedup".utf8)
        apply(
            &bobSnapshot,
            updates: [try messaging.initializeDeduplicationSet(key: deduplicationKey)]
        )
        let changedMessageBinding = TransportBinding(
            bytes: Data("changed consumer-owned message metadata".utf8)
        )
        expectAuthenticationFailed("established decryption with changed binding bytes") {
            _ = try bob.messaging().decryptMessage(
                snapshot: bobSnapshot,
                sessionKey: sessionKey,
                deduplicationKey: deduplicationKey,
                message: outbound.message,
                acknowledgmentId: Data(repeating: 0x5a, count: 16),
                acknowledgmentRecipientPublicKey: (try alice.identity().currentPublicationBundle()).discoveryKey.publicKey,
                acknowledgmentTimestampMillis: 1_700_000_000_101,
                acknowledgmentSenderCertificate: bobCertificate.certificate,
                acknowledgmentSenderSignature: bobCertificate.signature,
                senderCertificateValidation: validation,
                messageTransportBinding: changedMessageBinding,
                acknowledgmentTransportBinding: acknowledgmentBinding
            )
        }
        let inbound = try bob.messaging().decryptMessage(
            snapshot: bobSnapshot,
            sessionKey: sessionKey,
            deduplicationKey: deduplicationKey,
            message: outbound.message,
            acknowledgmentId: Data(repeating: 0x5a, count: 16),
            acknowledgmentRecipientPublicKey: (try alice.identity().currentPublicationBundle()).discoveryKey.publicKey,
            acknowledgmentTimestampMillis: 1_700_000_000_101,
            acknowledgmentSenderCertificate: bobCertificate.certificate,
            acknowledgmentSenderSignature: bobCertificate.signature,
            senderCertificateValidation: validation,
            messageTransportBinding: messageBinding,
            acknowledgmentTransportBinding: acknowledgmentBinding
        )
        guard case .accepted(let inbound) = inbound else { fail("expected accepted Message") }
        require(inbound.plaintext == Data("transport-bound follow-up".utf8), "transport-bound Message plaintext")
        let acknowledgment = inbound.acknowledgment
        let changedAcknowledgmentBinding = TransportBinding(
            bytes: Data("changed consumer-owned acknowledgment metadata".utf8)
        )
        expectAuthenticationFailed("acknowledgment with changed binding bytes") {
            _ = try alice.messaging().processAcknowledgment(
                snapshot: aliceSnapshot,
                sessionKey: sessionKey,
                message: acknowledgment,
                transportBinding: changedAcknowledgmentBinding
            )
        }
        let acknowledgmentOutcome = try alice.messaging().processAcknowledgment(
            snapshot: aliceSnapshot,
            sessionKey: sessionKey,
            message: acknowledgment,
            transportBinding: acknowledgmentBinding
        )
        guard case .cleared = acknowledgmentOutcome else { fail("expected cleared acknowledgment") }

        print("Swift Transport Binding coverage passed")
    }

    private static func expectMismatchedPrekeySelection(
        _ store: Client,
        message: Message,
        transportBinding: TransportBinding,
        prekeySelection: PreKeySelection
    ) {
        let mismatched = PreKeySelection(
            signedPrekeyIdentifier: prekeySelection.signedPrekeyIdentifier,
            oneTimePrekeyIdentifier: prekeySelection.oneTimePrekeyIdentifier! + 1
        )
        do {
            _ = try store.messaging().initiatorIdentityHint(
                message: message,
                transportBinding: transportBinding,
                prekeySelection: mismatched
            )
            fail("mismatched one-time-prekey identifier should reject")
        } catch let error as ClientError {
            guard case .AuthenticationFailed(_) = error else {
                fail("unexpected prekey-selection error \(error)")
            }
        } catch {
            fail("unexpected prekey-selection error \(error)")
        }
    }

    private static func expectInvalidData(
        _ message: String,
        operation: () throws -> Void
    ) {
        do {
            try operation()
            fail("\(message) should reject")
        } catch let error as ClientError {
            guard case .InvalidData(_) = error else {
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
        } catch let error as ClientError {
            guard case .AuthenticationFailed(_) = error else {
                fail("unexpected \(message) error \(error)")
            }
        } catch {
            fail("unexpected \(message) error \(error)")
        }
    }

    private static func generateIdentity(_ store: Client) throws -> Identity {
        let prepared = try store.identity().prepareGenerateIdentity()
        try complete(store, operation: prepared.operation)
        return prepared.identity
    }

    private static func rotateSignedPrekey(_ store: Client) throws {
        let prepared = try store.identity().prepareRotateSignedPrekeyNow()
        try complete(store, operation: prepared.operation)
    }

    private static func replenishOneTimePrekeys(_ store: Client) throws -> [OneTimePreKeyBundle] {
        let prepared = try store.identity().prepareReplenishOneTimePrekeys()
        try complete(store, operation: prepared.operation)
        return prepared.oneTimePrekeys
    }

    private static func complete(_ store: Client, operation: KeyStoreOperation) throws {
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
        fputs("Transport Binding coverage failed: \(message)\n", stderr)
        exit(1)
    }
}
