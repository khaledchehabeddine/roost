package io.github.relaynet.roost

import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

// Exercises signAuthenticationTranscript through the generated Kotlin surface.
//
// This file exists because the identity key could sign nothing a caller
// defined. Every Client accessor returned public material and Identity
// carried a verifying key with no signing capability, so a relay authentication
// transcript (REL-RLY-16) — Relay's construction, not Aether's — could not be
// signed on either mobile platform. Rust tests could not catch that: roost-core
// has always had Identity::sign, and only the binding surface was missing it.
//
// Verification below is the JDK's Ed25519, not Aether's. A relay verifies with
// its own implementation over the transcript bytes alone, so checking with
// Aether would prove only that Aether agrees with itself.

private val HTTP_CONTEXT = "Relay-HTTP-Auth-v1".toByteArray(Charsets.US_ASCII)

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

private fun check(condition: Boolean, message: String) {
    if (!condition) {
        throw IllegalStateException("authentication transcript signing coverage failed: $message")
    }
}

private fun lengthPrefixed(field: ByteArray): ByteArray =
    byteArrayOf((field.size ushr 8).toByte(), (field.size and 0xff).toByte()) + field

// REL-RLY-16: the context, protocol version, challenge nonce and signing key are
// fixed width and unprefixed; the variable-length fields carry u16 big-endian
// lengths counting only the field that follows.
private fun httpTranscript(identitySigningKey: ByteArray): ByteArray =
    HTTP_CONTEXT +
        byteArrayOf(0x00, 0x01) +
        ByteArray(32) { 0x22 } +
        identitySigningKey +
        lengthPrefixed("relay.example".toByteArray(Charsets.UTF_8)) +
        lengthPrefixed("POST".toByteArray(Charsets.US_ASCII)) +
        lengthPrefixed("/v1/prekeys?count=10".toByteArray(Charsets.US_ASCII)) +
        MessageDigest.getInstance("SHA-256").digest("vector-body".toByteArray(Charsets.UTF_8))

private fun verifies(identitySigningKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
    val publicKey = KeyFactory.getInstance("Ed25519")
        .generatePublic(X509EncodedKeySpec(ED25519_SPKI_PREFIX + identitySigningKey))
    val verifier = Signature.getInstance("Ed25519")
    verifier.initVerify(publicKey)
    verifier.update(message)
    return verifier.verify(signature)
}

private fun checkInvalidData(store: Client, transcript: ByteArray, message: String) {
    try {
        store.identity().signAuthenticationTranscript(transcript)
        check(false, message)
    } catch (error: ClientException.InvalidData) {
        // Expected.
    }
}

fun main() {
    val store = Client(MemorySecureStorage())
    val prepared = store.identity().prepareGenerateIdentity()
    store.commitOperation(prepared.operation.identifier)
    store.finalizeOperation(prepared.operation.identifier)
    val identity = prepared.identity
    val transcript = httpTranscript(identity.ed25519VerifyingKey)

    val signature = store.identity().signAuthenticationTranscript(transcript)
    check(signature.size == 64, "an Ed25519 signature must cross as 64 bytes")

    check(
        verifies(identity.ed25519VerifyingKey, transcript, signature),
        "the signature must verify over the transcript bytes exactly as sent",
    )
    // The transcript already begins with its own context. Had the export
    // prepended a second one, this — and only this — would have verified, and
    // the relay would have rejected every request with no diagnosis.
    check(
        !verifies(identity.ed25519VerifyingKey, HTTP_CONTEXT + transcript, signature),
        "the signature must not cover a context-prefixed preimage",
    )

    // Ed25519 is deterministic; a retried challenge must resend the same proof.
    check(
        store.identity().signAuthenticationTranscript(transcript).contentEquals(signature),
        "signing the same transcript twice must produce the same bytes",
    )

    // The identity key is what signs Aether's own bindings and message
    // transcripts, so the export must refuse preimages that could pass for one
    // of them.
    for (context in listOf("AetherIKBinding-v1:", "AetherDKToIK-v1:", "AetherMessageTranscript-v1:")) {
        val reserved = context.toByteArray(Charsets.US_ASCII) +
            identity.x25519PublicKey +
            identity.ed25519VerifyingKey
        checkInvalidData(store, reserved, "a reserved Aether preimage must be refused: $context")
    }
    checkInvalidData(store, ByteArray(0), "an empty transcript must be refused")

    println("Kotlin authentication transcript signing coverage passed")
}
