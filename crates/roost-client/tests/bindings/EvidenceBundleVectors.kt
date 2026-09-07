package com.aurelion.aether

import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

private val VALID_EVIDENCE_BUNDLE = "01011009090909090909090909090909090909bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a50221000000004000800000000000000081fca7ffbc3100200000001b636f6e7465787420666f7220616e206162757365207265706f7274007b41657468657253656e64657243657274696669636174652d76323a020b746573742d646f6d61696e0a72656c61792e7465737457f24707f390532aa6598f61c43f3bc2dae984525359cb43fc13db947e93f63e65e8f9b0bc6eae124169f0576f97362d295a8cf5f770b45e14357ce647d33eec00000000655577a0409ed439e636de0aabb9ec5e6c0562d1c2892d1a1679897b3f4d1583bcc4abfc014821307b3bb6e35ec85fe66bca2c2e46ffd56f0bd533e43469659c01f985450640340624ac228577b9d3823baec5f873a09708c2e88d4f83ce4f2660911f7606b89a1b0b0f82399c1137947e6fc1c1bec30553cfdc435559c1d76007741143e40f".hexBytes()
private val EVIDENCE_DOMAIN_KEY = DomainSigningKey(
    "746573742d646f6d61696e".hexBytes(),
    "6556ea860463d074ae046736e1f20f6c78f7a26e31518d1fe7f645150aaa6ad1".hexBytes(),
    DomainSigningKeyStatus.TRUSTED,
)
private val EVIDENCE_RELAY_DOMAIN = "relay.test".encodeToByteArray()
private val ED25519_SUBJECT_PUBLIC_KEY_PREFIX = byteArrayOf(
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
)

private fun verifyEvidence(bundle: ByteArray): VerifiedEvidenceBundle = verifyEvidenceBundle(
    bundle,
    EvidenceProfile.MESSAGE_TRANSCRIPT_VERSION1,
    listOf(EVIDENCE_DOMAIN_KEY),
    EVIDENCE_RELAY_DOMAIN,
    1_700_000_000uL,
    0uL,
)

private fun requireEvidence(condition: Boolean, message: String) {
    if (!condition) throw IllegalStateException("evidence bundle vector coverage failed: $message")
}

private inline fun <reified T : Throwable> requireEvidenceError(message: String, block: () -> Unit) {
    try {
        block()
        requireEvidence(false, message)
    } catch (_: T) {
        // Expected error category.
    }
}

private fun platformVerifies(key: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
    val publicKey = KeyFactory.getInstance("Ed25519").generatePublic(
        X509EncodedKeySpec(ED25519_SUBJECT_PUBLIC_KEY_PREFIX + key),
    )
    return Signature.getInstance("Ed25519").run {
        initVerify(publicKey)
        update(message)
        verify(signature)
    }
}

private fun messageTranscript(): ByteArray {
    val paddedPayload =
        "0000001b636f6e7465787420666f7220616e206162757365207265706f727400".hexBytes()
    val senderCertificate =
        "41657468657253656e64657243657274696669636174652d76323a020b746573742d646f6d61696e0a72656c61792e7465737457f24707f390532aa6598f61c43f3bc2dae984525359cb43fc13db947e93f63e65e8f9b0bc6eae124169f0576f97362d295a8cf5f770b45e14357ce647d33eec00000000655577a0".hexBytes()
    return "AetherMessageTranscript-v1:".encodeToByteArray() +
        ByteBuffer.allocate(4).putInt(16).array() +
        ByteArray(16) { 0x09 } +
        "bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a5".hexBytes() +
        "02210000000040008000000000000000".hexBytes() +
        ByteBuffer.allocate(8).putLong(1_700_000_300_545L).array() +
        byteArrayOf(0) +
        ByteBuffer.allocate(4).putInt(paddedPayload.size).array() +
        paddedPayload +
        ByteBuffer.allocate(4).putInt(senderCertificate.size).array() +
        senderCertificate
}

fun main() {
    val verified = verifyEvidence(VALID_EVIDENCE_BUNDLE)
    requireEvidence(verified.profile == EvidenceProfile.MESSAGE_TRANSCRIPT_VERSION1, "profile")
    requireEvidence(verified.evidenceIdentity.contentEquals("a7af7974cb7c5c3c770baf1b946f8d7d69a295068d99b78425b1df538a6aa489".hexBytes()), "evidence identity")
    requireEvidence(verified.sessionKey.contentEquals(ByteArray(16) { 0x09 }), "session key")
    requireEvidence(verified.recipientIdentityVerifyingKey.contentEquals("bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a5".hexBytes()), "recipient Identity Key")
    requireEvidence(verified.messageId.contentEquals("02210000000040008000000000000000".hexBytes()), "message ID")
    requireEvidence(verified.timestampMillis == 1_700_000_300_545uL, "timestamp")
    requireEvidence(verified.payloadKind == PayloadKind.ENCRYPTED_TEXT, "payload kind")
    requireEvidence(verified.plaintext.contentEquals("context for an abuse report".encodeToByteArray()), "plaintext")
    requireEvidence(verified.senderIdentityKey.x25519PublicKey.contentEquals("57f24707f390532aa6598f61c43f3bc2dae984525359cb43fc13db947e93f63e".hexBytes()), "sender agreement key")
    requireEvidence(verified.senderIdentityKey.ed25519VerifyingKey.contentEquals("65e8f9b0bc6eae124169f0576f97362d295a8cf5f770b45e14357ce647d33eec".hexBytes()), "sender verifying key")
    requireEvidence(verified.relayDomain.contentEquals(EVIDENCE_RELAY_DOMAIN), "relay domain")
    requireEvidence(verified.certificateExpiresAtSecs == 1_700_100_000uL, "certificate expiry")

    val certificate = "41657468657253656e64657243657274696669636174652d76323a020b746573742d646f6d61696e0a72656c61792e7465737457f24707f390532aa6598f61c43f3bc2dae984525359cb43fc13db947e93f63e65e8f9b0bc6eae124169f0576f97362d295a8cf5f770b45e14357ce647d33eec00000000655577a0".hexBytes()
    val certificateSignature = "9ed439e636de0aabb9ec5e6c0562d1c2892d1a1679897b3f4d1583bcc4abfc014821307b3bb6e35ec85fe66bca2c2e46ffd56f0bd533e43469659c01f9854506".hexBytes()
    requireEvidence(
        platformVerifies(EVIDENCE_DOMAIN_KEY.verifyingKey, certificate, certificateSignature),
        "JDK certificate signature",
    )
    val messageSignature = "340624ac228577b9d3823baec5f873a09708c2e88d4f83ce4f2660911f7606b89a1b0b0f82399c1137947e6fc1c1bec30553cfdc435559c1d76007741143e40f".hexBytes()
    requireEvidence(
        platformVerifies(
            verified.senderIdentityKey.ed25519VerifyingKey,
            messageTranscript(),
            messageSignature,
        ),
        "JDK Message transcript signature",
    )

    requireEvidenceError<ClientException.InvalidData>("malformed bundle") {
        verifyEvidence(byteArrayOf(1, 1, -1))
    }
    requireEvidenceError<ClientException.InvalidData>("wrong profile") {
        verifyEvidence(VALID_EVIDENCE_BUNDLE.copyOf().also { it[1] = 2 })
    }
    requireEvidenceError<ClientException.UnsupportedVersion>("unsupported version") {
        verifyEvidence(VALID_EVIDENCE_BUNDLE.copyOf().also { it[0] = 2 })
    }
    requireEvidenceError<ClientException.AuthenticationFailed>("tampered Message signature") {
        verifyEvidence(VALID_EVIDENCE_BUNDLE.copyOf().also {
            it[it.lastIndex] = (it.last().toInt() xor 0x01).toByte()
        })
    }
    requireEvidenceError<ClientException.InvalidData>("noncanonical recipient Identity Key") {
        verifyEvidence(VALID_EVIDENCE_BUNDLE.copyOf().also {
            for (index in 19 until 51) it[index] = 0xff.toByte()
        })
    }
    requireEvidenceError<ClientException.InvalidData>("excessive certificate grace window") {
        verifyEvidenceBundle(
            VALID_EVIDENCE_BUNDLE,
            EvidenceProfile.MESSAGE_TRANSCRIPT_VERSION1,
            listOf(EVIDENCE_DOMAIN_KEY),
            EVIDENCE_RELAY_DOMAIN,
            1_700_000_000uL,
            301uL,
        )
    }
    requireEvidenceError<ClientException.CertificateRejected>("cross-relay replay") {
        verifyEvidenceBundle(
            VALID_EVIDENCE_BUNDLE,
            EvidenceProfile.MESSAGE_TRANSCRIPT_VERSION1,
            listOf(EVIDENCE_DOMAIN_KEY),
            "other-relay.test".encodeToByteArray(),
            1_700_000_000uL,
            0uL,
        )
    }

    println("Kotlin evidence bundle vectors passed")
}

private fun String.hexBytes(): ByteArray = chunked(2)
    .map { it.toInt(16).toByte() }
    .toByteArray()
