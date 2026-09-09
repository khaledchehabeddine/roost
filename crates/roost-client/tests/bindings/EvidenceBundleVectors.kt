package io.github.relaynet.roost

import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

fun main() {
    val domainKey = DomainSigningKey(bytes("DOMAIN_ID"), bytes("DOMAIN_KEY"), DomainSigningKeyStatus.TRUSTED)
    val verified = verifyEvidenceBundle(
        bytes("BUNDLE"), EvidenceProfile.MESSAGE_TRANSCRIPT_VERSION1,
        listOf(domainKey), bytes("RELAY"), value("ACCEPTED").toULong(), value("GRACE").toULong(),
    )
    check(verified.evidenceIdentity.contentEquals(bytes("IDENTITY")))
    check(verified.payloadKind == PayloadKind.ENCRYPTED_TEXT)
    val certificate = bytes("CERTIFICATE")
    check(platformVerifies(domainKey.verifyingKey, certificate, bytes("CERTIFICATE_SIGNATURE")))

    // Rebuild the signed transcript from the fields returned across FFI.
    val payload = ByteBuffer.allocate(4).putInt(verified.plaintext.size).array() + verified.plaintext
    var bucket = 32
    while (bucket < payload.size) bucket *= 2
    val padded = payload.copyOf(bucket)
    val transcript = "AetherMessageTranscript-v1:".encodeToByteArray() +
        ByteBuffer.allocate(4).putInt(verified.sessionKey.size).array() + verified.sessionKey +
        verified.recipientIdentityVerifyingKey + verified.messageId +
        ByteBuffer.allocate(8).putLong(verified.timestampMillis.toLong()).array() + byteArrayOf(0) +
        ByteBuffer.allocate(4).putInt(padded.size).array() + padded +
        ByteBuffer.allocate(4).putInt(certificate.size).array() + certificate
    check(platformVerifies(verified.senderIdentityKey.ed25519VerifyingKey, transcript, bytes("MESSAGE_SIGNATURE")))
    transcript[transcript.lastIndex] = (transcript.last().toInt() xor 1).toByte()
    check(!platformVerifies(verified.senderIdentityKey.ed25519VerifyingKey, transcript, bytes("MESSAGE_SIGNATURE")))
    // Verify fresh signature bytes returned by the generated signer binding.
    val client = Client(InMemorySecureStorage())
    val prepared = client.identity().prepareGenerateIdentity()
    client.commitOperation(prepared.operation.identifier)
    client.finalizeOperation(prepared.operation.identifier)
    val authentication = byteArrayOf(0x00, 0x7f, 0x80.toByte(), 0xff.toByte())
    val signature = client.identity().signAuthenticationTranscript(authentication)
    check(platformVerifies(prepared.identity.ed25519VerifyingKey, authentication, signature))
    println("Kotlin native Evidence Bundle and returned signature verification passed")
}

private fun platformVerifies(key: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
    val prefix = byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)
    val publicKey = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(prefix + key))
    return Signature.getInstance("Ed25519").run {
        initVerify(publicKey)
        update(message)
        verify(signature)
    }
}

private fun value(key: String): String = System.getenv("ROOST_EVIDENCE_$key")
private fun bytes(key: String): ByteArray = value(key).chunked(2).map { it.toInt(16).toByte() }.toByteArray()
