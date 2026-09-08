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
        let alice = Client(storage: MemorySecureStorage())
        let bob = Client(storage: MemorySecureStorage())
        let contacts = alice.contacts()
        let aliceIdentityPreparation = try alice.identity().prepareGenerateIdentity()
        _ = try alice.commitOperation(identifier: aliceIdentityPreparation.operation.identifier)
        _ = try alice.finalizeOperation(identifier: aliceIdentityPreparation.operation.identifier)
        let bobIdentityPreparation = try bob.identity().prepareGenerateIdentity()
        _ = try bob.commitOperation(identifier: bobIdentityPreparation.operation.identifier)
        _ = try bob.finalizeOperation(identifier: bobIdentityPreparation.operation.identifier)
        let bobIdentity = bobIdentityPreparation.identity
        let aliceSignedPrekey = try alice.identity().prepareRotateSignedPrekeyNow()
        _ = try alice.commitOperation(identifier: aliceSignedPrekey.operation.identifier)
        _ = try alice.finalizeOperation(identifier: aliceSignedPrekey.operation.identifier)
        let bobSignedPrekey = try bob.identity().prepareRotateSignedPrekeyNow()
        _ = try bob.commitOperation(identifier: bobSignedPrekey.operation.identifier)
        _ = try bob.finalizeOperation(identifier: bobSignedPrekey.operation.identifier)
        let bobPublication = try bob.identity().currentPublicationBundle()

        var snapshot: [ProtocolStateEntry] = []
        apply(&snapshot, try contacts.recordContact(
            snapshot: [],
            contactIdentity: contactIdentity(identity: bobIdentity, publication: bobPublication)
        ).stateUpdates)
        apply(&snapshot, try contacts.acceptContact(
            snapshot: snapshot,
            identityKey: identityKey(bobIdentity)
        ).stateUpdates)

        // Alice rotates. Bob has never been given an authorization, so he owes one.
        let rotationPreparation = try alice.identity().prepareRotateInboxNow()
        _ = try alice.commitOperation(identifier: rotationPreparation.operation.identifier)
        _ = try alice.finalizeOperation(identifier: rotationPreparation.operation.identifier)
        let rotation = rotationPreparation.rotation
        let generation = rotation.publication.discoveryKey.epoch
        let owing = try contacts.contactsNeedingInboxAuthorization(
            snapshot: snapshot,
            currentGeneration: generation,
            candidates: [identityKey(bobIdentity)]
        )
        require(owing.count == 1, "a contact with no authorization must be listed as owing one")

        // Recorded only after the update reaches transport, so an app killed
        // mid-re-key resumes instead of skipping the contact.
        apply(&snapshot, try contacts.recordInboxAuthorizationDelivered(
            snapshot: snapshot,
            identityKey: identityKey(bobIdentity),
            generation: generation
        ))
        require(
            try contacts.contactsNeedingInboxAuthorization(
                snapshot: snapshot,
                currentGeneration: generation,
                candidates: [identityKey(bobIdentity)]
            ).isEmpty,
            "a contact already given this generation must not be listed again"
        )

        // The receiving side: Bob persists what Alice sent and reads it back to
        // submit to the relay.
        let bobContacts = bob.contacts()
        var bobSnapshot: [ProtocolStateEntry] = []
        let aliceIdentity = try alice.identity().loadIdentity()
        let aliceIdentityKey = identityKey(aliceIdentity)
        apply(&bobSnapshot, try bobContacts.recordContact(
            snapshot: [],
            contactIdentity: contactIdentity(identity: aliceIdentity, publication: rotation.publication)
        ).stateUpdates)
        apply(&bobSnapshot, try bobContacts.recordPeerInboxAuthorization(
            snapshot: bobSnapshot,
            identityKey: aliceIdentityKey,
            generation: generation,
            capability: rotation.capability
        ))

        guard let stored = try bobContacts.peerInboxAuthorization(
            snapshot: bobSnapshot,
            identityKey: aliceIdentityKey
        ) else {
            fail("a recorded peer authorization must be readable")
        }
        require(stored.generation == generation, "the stored generation must match what was recorded")
        require(stored.capability == rotation.capability, "the stored capability must round-trip intact")

        // AE-BLK-08: replaying an older authorization must not restore a
        // capability the peer has rotated away from.
        let replay = try bobContacts.recordPeerInboxAuthorization(
            snapshot: bobSnapshot,
            identityKey: aliceIdentityKey,
            generation: generation - 1,
            capability: Data(repeating: 0x11, count: 32)
        )
        require(replay.isEmpty, "an older generation must be refused")

        // Blocking must rotate, or the blocked contact keeps a working delivery
        // capability until the host publishes the prepared inbox rotation.
        let blockPreparation = try alice.contacts().prepareBlockContact(
            snapshot: snapshot,
            identityKey: identityKey(bobIdentity)
        )
        _ = try alice.commitOperation(identifier: blockPreparation.operation.identifier)
        apply(&snapshot, blockPreparation.block.contact.stateUpdates)
        _ = try alice.finalizeOperation(identifier: blockPreparation.operation.identifier)
        let blocked = blockPreparation.block
        guard let blockRotation = blocked.rotation else {
            fail("blocking must rotate the inbox")
        }
        require(
            try contacts.contactsNeedingInboxAuthorization(
                snapshot: snapshot,
                currentGeneration: blockRotation.publication.discoveryKey.epoch,
                candidates: [identityKey(bobIdentity)]
            ).isEmpty,
            "a blocked contact must never be re-supplied the capability"
        )

        // Repeating the block must not churn every other contact's capability.
        let repeatedBlock = try alice.contacts().prepareBlockContact(
            snapshot: snapshot,
            identityKey: identityKey(bobIdentity)
        )
        _ = try alice.commitOperation(identifier: repeatedBlock.operation.identifier)
        _ = try alice.finalizeOperation(identifier: repeatedBlock.operation.identifier)
        require(
            repeatedBlock.block.rotation == nil,
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
