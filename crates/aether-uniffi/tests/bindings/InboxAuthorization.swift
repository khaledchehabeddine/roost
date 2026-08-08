import Foundation

// Exercises the inbox-authorization distribution flow (AE-STA-12) end to end
// through the generated Swift surface. See the Kotlin counterpart for why this
// coverage exists: the operations below were reachable only from Rust, so
// post-rotation redistribution could not be written on either mobile platform.

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

@main
struct InboxAuthorization {
    static func main() throws {
        let engine = ProtocolStateEngine()
        let alice = KeyStore(storage: MemorySecureStorage())
        let bob = KeyStore(storage: MemorySecureStorage())
        _ = try alice.generateIdentity()
        let bobIdentity = try bob.generateIdentity()
        _ = try alice.rotateSignedPrekeyNow()
        _ = try bob.rotateSignedPrekeyNow()
        let bobPublication = try bob.currentPublicationBundle()

        var snapshot: [ProtocolStateEntry] = []
        apply(&snapshot, try engine.recordContact(
            snapshot: [],
            contactIdentity: contactIdentity(identity: bobIdentity, publication: bobPublication)
        ).stateUpdates)
        apply(&snapshot, try engine.acceptContact(
            snapshot: snapshot,
            identityKey: identityKey(bobIdentity)
        ).stateUpdates)

        // Alice rotates. Bob has never been given an authorization, so he owes one.
        let rotation = try alice.rotateInboxNow()
        let generation = rotation.publication.discoveryKey.epoch
        let owing = try engine.contactsNeedingInboxAuthorization(
            snapshot: snapshot,
            currentGeneration: generation,
            candidates: [identityKey(bobIdentity)]
        )
        require(owing.count == 1, "a contact with no authorization must be listed as owing one")

        // Recorded only after the update reaches transport, so an app killed
        // mid-re-key resumes instead of skipping the contact.
        apply(&snapshot, try engine.recordInboxAuthorizationDelivered(
            snapshot: snapshot,
            identityKey: identityKey(bobIdentity),
            generation: generation
        ))
        require(
            try engine.contactsNeedingInboxAuthorization(
                snapshot: snapshot,
                currentGeneration: generation,
                candidates: [identityKey(bobIdentity)]
            ).isEmpty,
            "a contact already given this generation must not be listed again"
        )

        // The receiving side: Bob persists what Alice sent and reads it back to
        // submit to the relay.
        var bobSnapshot: [ProtocolStateEntry] = []
        let aliceIdentity = try alice.loadIdentity()
        let aliceIdentityKey = identityKey(aliceIdentity)
        apply(&bobSnapshot, try engine.recordContact(
            snapshot: [],
            contactIdentity: contactIdentity(identity: aliceIdentity, publication: rotation.publication)
        ).stateUpdates)
        apply(&bobSnapshot, try engine.recordPeerInboxAuthorization(
            snapshot: bobSnapshot,
            identityKey: aliceIdentityKey,
            generation: generation,
            capability: rotation.capability
        ))

        guard let stored = try engine.peerInboxAuthorization(
            snapshot: bobSnapshot,
            identityKey: aliceIdentityKey
        ) else {
            fail("a recorded peer authorization must be readable")
        }
        require(stored.generation == generation, "the stored generation must match what was recorded")
        require(stored.capability == rotation.capability, "the stored capability must round-trip intact")

        // AE-BLK-08: replaying an older authorization must not restore a
        // capability the peer has rotated away from.
        let replay = try engine.recordPeerInboxAuthorization(
            snapshot: bobSnapshot,
            identityKey: aliceIdentityKey,
            generation: generation - 1,
            capability: Data(repeating: 0x11, count: 32)
        )
        require(replay.isEmpty, "an older generation must be refused")

        // Blocking must rotate, or the blocked contact keeps a working delivery
        // capability and the block bites only on this device. The engine's
        // blockContact is the local-only half; the keystore's is the one that
        // makes the block reach the relay.
        let blocked = try alice.blockContact(snapshot: snapshot, identityKey: identityKey(bobIdentity))
        guard let blockRotation = blocked.rotation else {
            fail("blocking must rotate the inbox")
        }
        apply(&snapshot, blocked.contact.stateUpdates)
        require(
            try engine.contactsNeedingInboxAuthorization(
                snapshot: snapshot,
                currentGeneration: blockRotation.publication.discoveryKey.epoch,
                candidates: [identityKey(bobIdentity)]
            ).isEmpty,
            "a blocked contact must never be re-supplied the capability"
        )

        // Repeating the block must not churn every other contact's capability.
        require(
            try alice.blockContact(snapshot: snapshot, identityKey: identityKey(bobIdentity)).rotation == nil,
            "blocking an already-blocked contact must not rotate again"
        )

        print("Swift inbox authorization coverage passed")
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

    private static func require(_ condition: Bool, _ message: String) {
        if !condition {
            fail(message)
        }
    }

    private static func fail(_ message: String) -> Never {
        fputs("inbox authorization coverage failed: \(message)\n", stderr)
        exit(1)
    }
}
