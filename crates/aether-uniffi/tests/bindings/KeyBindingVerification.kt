package com.aurelion.aether

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

// Exercises verifyIdentityKeyBinding and verifyDiscoveryToIdentityBinding through
// the generated Kotlin surface.
//
// This file exists because both directions of the mutual binding (AE-KEY-04)
// were implemented and correct in aether-crypto while being unreachable from any
// binding. initiateSession needs a live publication bundle and a session;
// recordContact covers IK→DK only. A client adding a contact from a typed
// discovery key has neither and must decide before it records anything, so
// Android grew a second, hand-written Ed25519 implementation of the same two
// checks. No cargo test could report that: the Rust side was never missing
// anything.
//
// The counterparty below is the JDK's Ed25519, not Aether's. Aether must accept
// a discovery-to-identity signature this file produced with a key Aether never
// saw, and the JDK must accept the identity self-binding Aether produced. Doing
// it the other way round — checking Aether's signatures with Aether — would
// prove only that Aether agrees with itself, which is the trap this whole change
// exists to get out of.

private val IDENTITY_BINDING_CONTEXT = "AetherIKBinding-v1:".toByteArray(Charsets.US_ASCII)
private val DISCOVERY_TO_IDENTITY_CONTEXT = "AetherDKToIK-v1:".toByteArray(Charsets.US_ASCII)

// Raw Ed25519 public keys have to be wrapped in a SubjectPublicKeyInfo header
// before KeyFactory will take them: SEQUENCE { SEQUENCE { OID 1.3.101.112 },
// BIT STRING }.
private val ED25519_SPKI_PREFIX = byteArrayOf(
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
)

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

/** An Ed25519 key pair from the platform provider, standing in for a peer's key. */
private class PlatformKey(private val pair: KeyPair = generate()) {
    val verifyingKey: ByteArray =
        pair.public.encoded.let { it.copyOfRange(it.size - 32, it.size) }

    fun sign(message: ByteArray): ByteArray = Signature.getInstance("Ed25519").run {
        initSign(pair.private)
        update(message)
        sign()
    }

    companion object {
        fun generate(): KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
    }
}

private fun check(condition: Boolean, message: String) {
    if (!condition) {
        throw IllegalStateException("key binding verification coverage failed: $message")
    }
}

/** `context || ik_x25519 || ik_ed25519` — the 64-byte payload both contexts sign. */
private fun payload(context: ByteArray, identity: IdentityKey): ByteArray =
    context + identity.x25519PublicKey + identity.ed25519VerifyingKey

private fun platformVerifies(
    verifyingKey: ByteArray,
    message: ByteArray,
    signature: ByteArray,
): Boolean {
    val publicKey = KeyFactory.getInstance("Ed25519")
        .generatePublic(X509EncodedKeySpec(ED25519_SPKI_PREFIX + verifyingKey))
    return Signature.getInstance("Ed25519").run {
        initVerify(publicKey)
        update(message)
        verify(signature)
    }
}

private fun checkAuthenticationFailed(message: String, block: () -> Unit) {
    try {
        block()
        check(false, message)
    } catch (error: AetherException.AuthenticationFailed) {
        // Expected: the material is well formed and does not bind.
    }
}

private fun checkInvalidData(message: String, block: () -> Unit) {
    try {
        block()
        check(false, message)
    } catch (error: AetherException.InvalidData) {
        // Expected: the material is not well formed.
    }
}

fun main() {
    val store = KeyStore(MemorySecureStorage())
    val generated = store.generateIdentity()
    val identity = IdentityKey(generated.x25519PublicKey, generated.ed25519VerifyingKey)

    // ── The identity self-binding, both ways round ──────────────────────────

    verifyIdentityKeyBinding(identity, generated.identityBindingSignature)
    check(
        platformVerifies(
            verifyingKey = identity.ed25519VerifyingKey,
            message = payload(IDENTITY_BINDING_CONTEXT, identity),
            signature = generated.identityBindingSignature,
        ),
        "the JDK must accept the self-binding Aether produced, over the documented preimage",
    )

    // ── The discovery-to-identity direction, signed outside Aether ──────────

    val discovery = PlatformKey()
    val discoveryToIdentity = discovery.sign(payload(DISCOVERY_TO_IDENTITY_CONTEXT, identity))

    verifyDiscoveryToIdentityBinding(identity, discovery.verifyingKey, discoveryToIdentity)

    // ── The separation the two contexts exist for ───────────────────────────

    // The payloads are byte-identical (AE-KEY-05); only the context differs. A
    // caller-chosen context would have handed this separation to the caller.
    checkAuthenticationFailed("a DK→IK signature must not satisfy the identity self-binding") {
        verifyIdentityKeyBinding(
            // Checked under the key that actually signed, so only the context can reject it.
            IdentityKey(identity.x25519PublicKey, discovery.verifyingKey),
            discoveryToIdentity,
        )
    }
    checkAuthenticationFailed("a self-binding must not satisfy the DK→IK direction") {
        verifyDiscoveryToIdentityBinding(
            identity,
            identity.ed25519VerifyingKey,
            generated.identityBindingSignature,
        )
    }

    // ── The substitution add-by-discovery-key exists to catch ───────────────

    // A relay answers a discovery-key lookup with an identity of its own,
    // correctly self-bound, that the typed discovery key never vouched for. The
    // self-binding holds; only the DK→IK check refuses it.
    val impostor = PlatformKey()
    val impostorIdentity = IdentityKey(identity.x25519PublicKey, impostor.verifyingKey)
    verifyIdentityKeyBinding(
        impostorIdentity,
        impostor.sign(payload(IDENTITY_BINDING_CONTEXT, impostorIdentity)),
    )
    checkAuthenticationFailed("an identity the typed discovery key did not sign must be refused") {
        verifyDiscoveryToIdentityBinding(
            impostorIdentity,
            discovery.verifyingKey,
            impostor.sign(payload(DISCOVERY_TO_IDENTITY_CONTEXT, impostorIdentity)),
        )
    }

    // ── Malformed material is not the same answer as a failed binding ───────

    val tampered = discoveryToIdentity.copyOf()
    tampered[0] = (tampered[0].toInt() xor 0x01).toByte()
    checkAuthenticationFailed("a tampered signature must not verify") {
        verifyDiscoveryToIdentityBinding(identity, discovery.verifyingKey, tampered)
    }

    checkInvalidData("a 31-byte discovery key must be refused") {
        verifyDiscoveryToIdentityBinding(identity, ByteArray(31), discoveryToIdentity)
    }
    checkInvalidData("a 63-byte signature must be refused") {
        verifyDiscoveryToIdentityBinding(identity, discovery.verifyingKey, ByteArray(63))
    }
    // A small-order key is the case that is not merely malformed: signatures
    // under it verify for keys nobody controls, so accepting one would report a
    // binding that binds nothing.
    checkInvalidData("a weak discovery key must be refused") {
        verifyDiscoveryToIdentityBinding(identity, ByteArray(32), discoveryToIdentity)
    }
    checkInvalidData("a 16-byte identity agreement key must be refused") {
        verifyIdentityKeyBinding(
            IdentityKey(ByteArray(16), identity.ed25519VerifyingKey),
            generated.identityBindingSignature,
        )
    }

    println("Kotlin key binding verification coverage passed")
}
