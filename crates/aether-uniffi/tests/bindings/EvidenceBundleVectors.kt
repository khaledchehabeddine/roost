package com.aurelion.aether

import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

private val VALID_EVIDENCE_BUNDLE = "01011009090909090909090909090909090909bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a50221000000000000000000000000000081fca7ffbc3100200000001b636f6e7465787420666f7220616e206162757365207265706f7274007b41657468657253656e64657243657274696669636174652d76323a020b746573742d646f6d61696e0a72656c61792e74657374c687135f1e118c6f85eaefea7e4a840fc1f73614d16a39b2b02674ab022cc131bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a500000000655577a040eb6b974d324f7726869849177eb00a939a133fde96b0c14bae3f17cf17b8ad5b0097aeda8fc0a9d6b9c23bbcb1eb315bbffd55e4969351b64dd21299f935ce0d40d1911d14ab80d76d99a057a8c0955a93fc6fdd723a2064bd391174dde7d228d0bebb9cf32dac16ec4fa4b99933fb6a59f1a5411eec2d5d7bc6969d90ed870e02".hexBytes()
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
    return "AetherMessageTranscript-v1:".encodeToByteArray() +
        ByteBuffer.allocate(4).putInt(16).array() +
        ByteArray(16) { 0x09 } +
        "bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a5".hexBytes() +
        "02210000000000000000000000000000".hexBytes() +
        ByteBuffer.allocate(8).putLong(1_700_000_300_545L).array() +
        byteArrayOf(0) +
        ByteBuffer.allocate(4).putInt(paddedPayload.size).array() +
        paddedPayload
}

fun main() {
    val verified = verifyEvidence(VALID_EVIDENCE_BUNDLE)
    requireEvidence(verified.profile == EvidenceProfile.MESSAGE_TRANSCRIPT_VERSION1, "profile")
    requireEvidence(verified.sessionKey.contentEquals(ByteArray(16) { 0x09 }), "session key")
    requireEvidence(verified.recipientIdentityVerifyingKey.contentEquals("bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a5".hexBytes()), "recipient Identity Key")
    requireEvidence(verified.messageId.contentEquals("02210000000000000000000000000000".hexBytes()), "message ID")
    requireEvidence(verified.timestampMillis == 1_700_000_300_545uL, "timestamp")
    requireEvidence(verified.payloadKind == PayloadKind.ENCRYPTED_TEXT, "payload kind")
    requireEvidence(verified.plaintext.contentEquals("context for an abuse report".encodeToByteArray()), "plaintext")
    requireEvidence(verified.senderIdentityKey.x25519PublicKey.contentEquals("c687135f1e118c6f85eaefea7e4a840fc1f73614d16a39b2b02674ab022cc131".hexBytes()), "sender agreement key")
    requireEvidence(verified.senderIdentityKey.ed25519VerifyingKey.contentEquals("bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a5".hexBytes()), "sender verifying key")
    requireEvidence(verified.relayDomain.contentEquals(EVIDENCE_RELAY_DOMAIN), "relay domain")
    requireEvidence(verified.certificateExpiresAtSecs == 1_700_100_000uL, "certificate expiry")

    val certificate = "41657468657253656e64657243657274696669636174652d76323a020b746573742d646f6d61696e0a72656c61792e74657374c687135f1e118c6f85eaefea7e4a840fc1f73614d16a39b2b02674ab022cc131bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a500000000655577a0".hexBytes()
    val certificateSignature = "eb6b974d324f7726869849177eb00a939a133fde96b0c14bae3f17cf17b8ad5b0097aeda8fc0a9d6b9c23bbcb1eb315bbffd55e4969351b64dd21299f935ce0d".hexBytes()
    requireEvidence(
        platformVerifies(EVIDENCE_DOMAIN_KEY.verifyingKey, certificate, certificateSignature),
        "JDK certificate signature",
    )
    val messageSignature = "d1911d14ab80d76d99a057a8c0955a93fc6fdd723a2064bd391174dde7d228d0bebb9cf32dac16ec4fa4b99933fb6a59f1a5411eec2d5d7bc6969d90ed870e02".hexBytes()
    requireEvidence(
        platformVerifies(
            verified.senderIdentityKey.ed25519VerifyingKey,
            messageTranscript(),
            messageSignature,
        ),
        "JDK Message transcript signature",
    )

    requireEvidenceError<AetherException.InvalidData>("malformed bundle") {
        verifyEvidence(byteArrayOf(1, 1, -1))
    }
    requireEvidenceError<AetherException.InvalidData>("wrong profile") {
        verifyEvidence(VALID_EVIDENCE_BUNDLE.copyOf().also { it[1] = 2 })
    }
    requireEvidenceError<AetherException.UnsupportedVersion>("unsupported version") {
        verifyEvidence(VALID_EVIDENCE_BUNDLE.copyOf().also { it[0] = 2 })
    }
    requireEvidenceError<AetherException.AuthenticationFailed>("tampered Message signature") {
        verifyEvidence(VALID_EVIDENCE_BUNDLE.copyOf().also {
            it[it.lastIndex] = (it.last().toInt() xor 0x01).toByte()
        })
    }
    requireEvidenceError<AetherException.CertificateRejected>("cross-relay replay") {
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
