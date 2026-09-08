package io.github.relaynet.roost

// Exercises the inbox-authorization distribution flow (AE-STA-12) end to end
// through the generated Kotlin surface.
//
// This file exists because the operations it calls were reachable only from
// Rust. A host could name ProtocolStateKind.PEER_INBOX_AUTHORIZATION but could
// not persist a capability a peer sent, read one back for relay submission, or
// work out which contacts still owe an authorization after a rotation — so
// post-rotation redistribution could not be written on either mobile platform.
// Rust tests cannot catch that: they exercise roost-core directly, where the
// operations have always existed.

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

private fun check(condition: Boolean, message: String) {
    if (!condition) {
        throw IllegalStateException("inbox authorization coverage failed: $message")
    }
}

fun main() {
    val alice = Client(MemorySecureStorage())
    val bob = Client(MemorySecureStorage())
    val contacts = alice.contacts()
    val aliceIdentityPreparation = alice.identity().prepareGenerateIdentity()
    alice.commitOperation(aliceIdentityPreparation.operation.identifier)
    alice.finalizeOperation(aliceIdentityPreparation.operation.identifier)
    val bobIdentityPreparation = bob.identity().prepareGenerateIdentity()
    bob.commitOperation(bobIdentityPreparation.operation.identifier)
    bob.finalizeOperation(bobIdentityPreparation.operation.identifier)
    val bobIdentity = bobIdentityPreparation.identity
    val aliceSignedPrekey = alice.identity().prepareRotateSignedPrekeyNow()
    alice.commitOperation(aliceSignedPrekey.operation.identifier)
    alice.finalizeOperation(aliceSignedPrekey.operation.identifier)
    val bobSignedPrekey = bob.identity().prepareRotateSignedPrekeyNow()
    bob.commitOperation(bobSignedPrekey.operation.identifier)
    bob.finalizeOperation(bobSignedPrekey.operation.identifier)
    val bobPublication = bob.identity().currentPublicationBundle()

    val snapshot = mutableListOf<ProtocolStateEntry>()
    applyUpdates(snapshot, contacts.recordContact(emptyList(), contactIdentity(bobIdentity, bobPublication)).stateUpdates)
    applyUpdates(snapshot, contacts.acceptContact(snapshot.toList(), identityKey(bobIdentity)).stateUpdates)

    // Alice rotates. Bob has never been given an authorization, so he owes one.
    val rotationPreparation = alice.identity().prepareRotateInboxNow()
    alice.commitOperation(rotationPreparation.operation.identifier)
    alice.finalizeOperation(rotationPreparation.operation.identifier)
    val rotation = rotationPreparation.rotation
    val generation = rotation.publication.discoveryKey.epoch
    val owing = contacts.contactsNeedingInboxAuthorization(
        snapshot.toList(),
        generation,
        listOf(identityKey(bobIdentity)),
    )
    check(owing.size == 1, "a contact with no authorization must be listed as owing one")

    // Recorded only after the update reaches transport, so an app killed
    // mid-re-key resumes instead of skipping the contact.
    applyUpdates(
        snapshot,
        contacts.recordInboxAuthorizationDelivered(snapshot.toList(), identityKey(bobIdentity), generation),
    )
    check(
        contacts.contactsNeedingInboxAuthorization(snapshot.toList(), generation, listOf(identityKey(bobIdentity))).isEmpty(),
        "a contact already given this generation must not be listed again",
    )

    // The receiving side: Bob persists what Alice sent and reads it back to
    // submit to the relay.
    val bobContacts = bob.contacts()
    val bobSnapshot = mutableListOf<ProtocolStateEntry>()
    val aliceIdentityKey = identityKey(alice.identity().loadIdentity())
    applyUpdates(bobSnapshot, bobContacts.recordContact(emptyList(), contactIdentity(alice.identity().loadIdentity(), rotation.publication)).stateUpdates)
    applyUpdates(
        bobSnapshot,
        bobContacts.recordPeerInboxAuthorization(
            bobSnapshot.toList(),
            aliceIdentityKey,
            generation,
            rotation.capability,
        ),
    )

    val stored = bobContacts.peerInboxAuthorization(bobSnapshot.toList(), aliceIdentityKey)
    check(stored != null, "a recorded peer authorization must be readable")
    check(stored!!.generation == generation, "the stored generation must match what was recorded")
    check(stored.capability.contentEquals(rotation.capability), "the stored capability must round-trip intact")

    // AE-BLK-08: replaying an older authorization must not restore a capability
    // the peer has rotated away from.
    val replay = bobContacts.recordPeerInboxAuthorization(
        bobSnapshot.toList(),
        aliceIdentityKey,
        generation - 1u,
        ByteArray(32) { 0x11 },
    )
    check(replay.isEmpty(), "an older generation must be refused")

    // Blocking must rotate, or the blocked contact keeps a working delivery
    // capability until the host publishes the prepared inbox rotation.
    val blockPreparation = alice.contacts().prepareBlockContact(snapshot.toList(), identityKey(bobIdentity))
    alice.commitOperation(blockPreparation.operation.identifier)
    applyUpdates(snapshot, blockPreparation.block.contact.stateUpdates)
    alice.finalizeOperation(blockPreparation.operation.identifier)
    val blocked = blockPreparation.block
    check(blocked.rotation != null, "blocking must rotate the inbox")
    val afterBlock = contacts.contactsNeedingInboxAuthorization(
        snapshot.toList(),
        blocked.rotation!!.publication.discoveryKey.epoch,
        listOf(identityKey(bobIdentity)),
    )
    check(afterBlock.isEmpty(), "a blocked contact must never be re-supplied the capability")

    // Repeating the block must not churn every other contact's capability.
    val repeatedBlock = alice.contacts().prepareBlockContact(snapshot.toList(), identityKey(bobIdentity))
    alice.commitOperation(repeatedBlock.operation.identifier)
    alice.finalizeOperation(repeatedBlock.operation.identifier)
    check(
        repeatedBlock.block.rotation == null,
        "blocking an already-blocked contact must not rotate again",
    )

    println("Kotlin inbox authorization coverage passed")
}
