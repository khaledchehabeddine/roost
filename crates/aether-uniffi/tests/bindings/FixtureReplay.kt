package com.aurelion.aether

private fun requireReplay(condition: Boolean, message: String) {
    if (!condition) {
        throw IllegalStateException("fixture replay failed: $message")
    }
}

fun main() {
    val report = replayFixtureHarness()

    requireReplay(report.messageWireCases.size == 4, "message fixture count")
    requireReplay(report.sealedSenderSessionCases.size == 1, "sealed-sender session fixture count")
    requireReplay(report.initialHandshakeCases.size == 1, "initial handshake fixture count")
    requireReplay(report.protocolStateBlobCases.size == 16, "protocol-state blob fixture count")
    requireReplay(
        report.protocolStateBlobCases.any { it.name == "deduplication_set_identity_with_duplicate_message" },
        "duplicate message blob fixture",
    )
    requireReplay(
        report.protocolStateBlobCases.any { it.name == "pending_acknowledgments_session_with_duplicate_ack" },
        "duplicate acknowledgment blob fixture",
    )
    requireReplay(report.unsupportedMessageVersionRejected, "unsupported message version")
    requireReplay(report.malformedMessageRejected, "malformed message")
    requireReplay(report.oldSenderVisibleMessageRejected, "old sender-visible message")
    requireReplay(report.unsupportedInitialHandshakeVersionRejected, "unsupported initial handshake version")
    requireReplay(report.malformedInitialHandshakeRejected, "malformed initial handshake")
    requireReplay(report.unsupportedBlobMajorRejected, "unsupported blob major")
    requireReplay(report.malformedBlobRejected, "malformed blob")

    val sessionCase = report.sealedSenderSessionCases[0]
    requireReplay(sessionCase.name == "sealed_text", "sealed-sender fixture name")
    requireReplay(
        sessionCase.plaintextHex == "66697874757265207365616c65642073657373696f6e",
        "sealed-sender plaintext",
    )
    requireReplay(sessionCase.senderIdentityHiddenBeforeDecrypt, "sender identity hidden before decrypt")
    requireReplay(sessionCase.senderCertificateHiddenBeforeDecrypt, "sender certificate hidden before decrypt")
    requireReplay(sessionCase.senderSignatureHiddenBeforeDecrypt, "sender signature hidden before decrypt")
    requireReplay(sessionCase.tamperedCiphertextRejected, "tampered ciphertext rejection")
    requireReplay(
        !sessionCase.transportVisible.ciphertextHex.contains(sessionCase.postDecryption.senderIdentityKeyHex),
        "identity leaked into transport payload",
    )
    requireReplay(
        !sessionCase.transportVisible.ciphertextHex.contains(sessionCase.postDecryption.senderCertificateHex),
        "certificate leaked into transport payload",
    )
    requireReplay(
        !sessionCase.transportVisible.ciphertextHex.contains(sessionCase.postDecryption.senderSignatureHex),
        "signature leaked into transport payload",
    )

    val initialCase = report.initialHandshakeCases[0]
    requireReplay(initialCase.senderIdentityHiddenBeforeDecrypt, "initial handshake identity hidden before decrypt")
    requireReplay(initialCase.senderCertificateHiddenBeforeDecrypt, "initial handshake certificate hidden before decrypt")
    requireReplay(initialCase.senderSignatureHiddenBeforeDecrypt, "initial handshake signature hidden before decrypt")
    requireReplay(initialCase.tamperedCiphertextRejected, "initial handshake tampered ciphertext rejection")

    println("Kotlin fixture replay passed")
}
