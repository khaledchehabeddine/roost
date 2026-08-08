import Foundation

private final class MemorySecureStorage: SecureStorage, @unchecked Sendable {
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

private struct StateAddress: Hashable {
    let kind: ProtocolStateKind
    let key: Data
}

private final class MemoryProtocolStateStore: ProtocolStateStore, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [StateAddress: Data] = [:]

    func load(kind: ProtocolStateKind, key: Data) throws -> Data? {
        lock.lock()
        let value = values[StateAddress(kind: kind, key: key)]
        lock.unlock()
        return value
    }

    func commit(updates: [ProtocolStateUpdate]) throws {
        lock.lock()
        defer { lock.unlock() }
        for update in updates {
            let address = StateAddress(kind: update.kind, key: update.key)
            let current = values[address]
            switch update.commitCheck {
            case .absent:
                if current != nil {
                    throw AetherError.ProtocolStateFault(reason: "stale protocol-state commit")
                }
            case .digest:
                guard
                    let expected = update.expectedBlobDigest,
                    let current,
                    protocolStateBlobDigest(blob: current) == expected
                else {
                    throw AetherError.ProtocolStateFault(reason: "stale protocol-state commit")
                }
            case .unchecked:
                break
            }
            if let blob = update.blob {
                values[address] = blob
            } else {
                values.removeValue(forKey: address)
            }
        }
    }
}

@main
struct Issue122Coverage {
    static func main() throws {
        let engine = ProtocolStateEngine()
        let limits = engine.hardeningLimits()
        require(limits.maxEncodedMessageLen > 0, "hardening limits")

        let protocolStore = MemoryProtocolStateStore()
        let dedupKey = Data("dedup".utf8)
        try protocolStore.commit(updates: [try engine.initializeDeduplicationSet(key: dedupKey)])
        expectStaleProtocolStateCommit(protocolStore, update: try engine.initializeDeduplicationSet(key: dedupKey))
        let digestKey = Data("digest".utf8)
        let digestSeed = ProtocolStateUpdate(
            kind: .deduplicationSet,
            key: digestKey,
            commitCheck: .absent,
            expectedBlobDigest: nil,
            blob: Data([0x01])
        )
        try protocolStore.commit(updates: [digestSeed])
        expectStaleProtocolStateCommit(
            protocolStore,
            update: ProtocolStateUpdate(
                kind: .deduplicationSet,
                key: digestKey,
                commitCheck: .digest,
                expectedBlobDigest: protocolStateBlobDigest(blob: Data([0x02])),
                blob: Data([0x03])
            )
        )
        let loaded = try engine.loadSnapshot(
            store: protocolStore,
            addresses: [ProtocolStateAddress(kind: .deduplicationSet, key: dedupKey)]
        )
        require(loaded.count == 1, "protocol state store load")

        let alice = KeyStore(storage: MemorySecureStorage())
        let bob = KeyStore(storage: MemorySecureStorage())
        let aliceIdentity = try alice.generateIdentity()
        let bobIdentity = try bob.generateIdentity()
        _ = try alice.rotateSignedPrekeyNow()
        _ = try bob.rotateSignedPrekeyNow()
        let alicePublication = try alice.currentPublicationBundle()
        let bobPublication = try bob.currentPublicationBundle()
        let replenished = try bob.replenishOneTimePrekeys()
        require(replenished.count == 100, "prekey replenishment")
        let bobOneTimePrekey = replenished[0]

        let backup = try alice.exportEncryptedBackup(passphrase: "passphrase")
        let restored = KeyStore(storage: MemorySecureStorage())
        try restored.importEncryptedBackup(data: backup, passphrase: "passphrase")
        let restoredHasIdentity = try restored.hasIdentity()
        require(restoredHasIdentity, "backup import")
        expectBackupFailure(restored)

        let sessionKey = Data(repeating: 0x45, count: 16)
        let initiation = try alice.initiateSession(
            sessionKey: sessionKey,
            responderIdentity: bobIdentity,
            responderPublication: bobPublication,
            responderOneTimePrekey: bobOneTimePrekey,
            senderCertificate: Data("alice certificate".utf8),
            senderSignature: Data("alice signature".utf8),
            plaintext: Data("hello bob".utf8)
        )
        let decodedInitial = try decodeMessage(bytes: try encodeMessage(message: initiation.message))
        let acceptance = try bob.acceptSession(
            sessionKey: sessionKey,
            initiatorIdentity: aliceIdentity,
            message: decodedInitial
        )
        require(acceptance.plaintext == Data("hello bob".utf8), "session accept plaintext")

        var aliceSnapshot: [ProtocolStateEntry] = []
        apply(&aliceSnapshot, initiation.stateUpdates)
        let recorded = try engine.recordContact(
            snapshot: [],
            contactIdentity: contactIdentity(identity: bobIdentity, publication: bobPublication)
        )
        apply(&aliceSnapshot, recorded.stateUpdates)
        let acceptedContact = try engine.acceptContact(
            snapshot: aliceSnapshot,
            identityKey: identityKey(bobIdentity)
        )
        apply(&aliceSnapshot, acceptedContact.stateUpdates)

        let outbound = try alice.encryptMessage(
            snapshot: aliceSnapshot,
            sessionKey: sessionKey,
            messageId: Data(repeating: 0x46, count: 16),
            contactIdentityKey: identityKey(bobIdentity),
            recipientPublicKey: bobPublication.discoveryKey.publicKey,
            timestampMillis: 42,
            senderCertificate: Data("alice certificate".utf8),
            senderSignature: Data("alice signature".utf8),
            plaintext: Data("follow-up".utf8)
        )
        apply(&aliceSnapshot, outbound.stateUpdates)
        let pending = try engine.pendingAcknowledgments(snapshot: aliceSnapshot, key: sessionKey)
        require(pending.count == 1, "pending ack")
        let retry = try engine.retryInstructions(
            snapshot: aliceSnapshot,
            key: sessionKey,
            nowMillis: 43,
            retryWindowMillis: 0
        )
        require(retry.instructions.count == 1, "retry instruction")

        let blocked = try engine.blockContact(snapshot: aliceSnapshot, identityKey: identityKey(bobIdentity))
        var blockedSnapshot = aliceSnapshot
        apply(&blockedSnapshot, blocked.stateUpdates)
        expectBlockedSend(alice, snapshot: blockedSnapshot, sessionKey: sessionKey, bobIdentity: bobIdentity, bobPublication: bobPublication)

        var bobSnapshot: [ProtocolStateEntry] = []
        apply(&bobSnapshot, acceptance.stateUpdates)
        apply(&bobSnapshot, [try engine.initializeDeduplicationSet(key: dedupKey)])
        expectMissingCertificateValidation(
            bob,
            snapshot: bobSnapshot,
            sessionKey: sessionKey,
            dedupKey: dedupKey,
            message: outbound.message,
            alicePublication: alicePublication
        )

        try exerciseEvents(contact: acceptedContact.contact)
        try expectCertificateRejection()
        expectInvalidMessageKey()
        print("Swift issue 122 coverage passed")
    }

    private static func identityKey(_ identity: Identity) -> IdentityKey {
        IdentityKey(
            x25519PublicKey: identity.x25519PublicKey,
            ed25519VerifyingKey: identity.ed25519VerifyingKey
        )
    }

    private static func contactIdentity(identity: Identity, publication: PublicationBundle) -> ContactIdentity {
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

    private static func apply(_ snapshot: inout [ProtocolStateEntry], _ updates: [ProtocolStateUpdate]) {
        for update in updates {
            snapshot.removeAll { $0.kind == update.kind && $0.key == update.key }
            if let blob = update.blob {
                snapshot.append(ProtocolStateEntry(kind: update.kind, key: update.key, blob: blob))
            }
        }
    }

    private static func expectStaleProtocolStateCommit(
        _ store: MemoryProtocolStateStore,
        update: ProtocolStateUpdate
    ) {
        do {
            try store.commit(updates: [update])
            fail("stale protocol-state commit should reject")
        } catch let error as AetherError {
            guard case .ProtocolStateFault(_) = error else {
                fail("unexpected stale-commit error \(error)")
            }
        } catch {
            fail("unexpected stale-commit error \(error)")
        }
    }

    private static func exerciseEvents(contact: ContactState) throws {
        let stream = try ContactEventStream.withObserverCapacity(initialState: [contact], observerCapacity: 1)
        let observer = try stream.subscribe()
        let event = ContactEvent(kind: .changed, contact: contact)
        _ = try stream.emit(event: event, nextState: [contact])
        _ = try stream.emit(event: event, nextState: [contact])
        let item = try observer.pollNext()
        require(item?.kind == .lagged, "event lag")
        try observer.resumeAfter(snapshot: stream.currentState())
    }

    private static func expectBackupFailure(_ store: KeyStore) {
        do {
            try store.importEncryptedBackup(data: Data([0x01]), passphrase: "bad")
            fail("backup import should fail")
        } catch let error as AetherError {
            switch error {
            case .InvalidData(_), .UnsupportedVersion(_), .DecryptionFailed, .BackupImportFailed(_):
                return
            default:
                fail("unexpected backup error \(error)")
            }
        } catch {
            fail("unexpected backup error \(error)")
        }
    }

    private static func expectBlockedSend(
        _ alice: KeyStore,
        snapshot: [ProtocolStateEntry],
        sessionKey: Data,
        bobIdentity: Identity,
        bobPublication: PublicationBundle
    ) {
        do {
            _ = try alice.encryptMessage(
                snapshot: snapshot,
                sessionKey: sessionKey,
                messageId: Data(repeating: 0x47, count: 16),
                contactIdentityKey: identityKey(bobIdentity),
                recipientPublicKey: bobPublication.discoveryKey.publicKey,
                timestampMillis: 44,
                senderCertificate: Data("alice certificate".utf8),
                senderSignature: Data("alice signature".utf8),
                plaintext: Data("blocked".utf8)
            )
            fail("blocked contact should reject send")
        } catch let error as AetherError {
            guard case .BlockedContact(_) = error else {
                fail("unexpected blocked-contact error \(error)")
            }
            return
        } catch {
            fail("unexpected blocked-contact error \(error)")
        }
    }

    private static func expectMissingCertificateValidation(
        _ bob: KeyStore,
        snapshot: [ProtocolStateEntry],
        sessionKey: Data,
        dedupKey: Data,
        message: Message,
        alicePublication: PublicationBundle
    ) {
        do {
            _ = try bob.decryptMessage(
                snapshot: snapshot,
                sessionKey: sessionKey,
                deduplicationKey: dedupKey,
                message: message,
                acknowledgmentId: Data(repeating: 0x48, count: 16),
                acknowledgmentRecipientPublicKey: alicePublication.discoveryKey.publicKey,
                acknowledgmentTimestampMillis: 45,
                acknowledgmentSenderCertificate: Data("bob certificate".utf8),
                acknowledgmentSenderSignature: Data("bob signature".utf8),
                senderCertificateValidation: nil
            )
            fail("missing certificate validation should reject receive")
        } catch let error as AetherError {
            guard case .InvalidData(_) = error else {
                fail("unexpected receive error \(error)")
            }
            return
        } catch {
            fail("unexpected receive error \(error)")
        }
    }

    private static func expectCertificateRejection() throws {
        do {
            _ = try validateSenderCertificate(
                certificate: Data([0x01]),
                signature: Data(),
                domainSigningKeys: [],
                expectedRelayDomain: Data("relay.test".utf8),
                revocationState: RevocationState(available: true, revokedIdentityKeys: []),
                referenceTimestampSecs: 0,
                graceWindowSecs: 0
            )
            fail("malformed certificate should reject")
        } catch let error as AetherError {
            guard case .CertificateRejected(_) = error else {
                fail("unexpected certificate error \(error)")
            }
            return
        }
    }

    private static func expectInvalidMessageKey() {
        do {
            _ = try encodeMessage(message: Message(
                version: 1,
                recipientPublicKey: Data(repeating: 0x01, count: 31),
                prekeyReference: nil,
                ephemeralPublicKey: Data(repeating: 0x02, count: 32),
                ciphertext: Data()
            ))
            fail("invalid public key should reject")
        } catch let error as AetherError {
            guard case .InvalidData(_) = error else {
                fail("unexpected message error \(error)")
            }
            return
        } catch {
            fail("unexpected message error \(error)")
        }
    }

    private static func require(_ condition: @autoclosure () -> Bool, _ message: String) {
        if !condition() {
            fail(message)
        }
    }

    private static func fail(_ message: String) -> Never {
        fputs("issue 122 coverage failed: \(message)\n", stderr)
        exit(1)
    }
}
