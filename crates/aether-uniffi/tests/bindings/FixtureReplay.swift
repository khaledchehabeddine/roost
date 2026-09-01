import Foundation

@main
struct FixtureReplay {
    static func main() throws {
        let report = try replayFixtureHarness()

        require(report.messageWireCases.count == 4, "message fixture count")
        require(report.sealedSenderSessionCases.count == 1, "sealed-sender session fixture count")
        require(report.initialHandshakeCases.count == 1, "initial handshake fixture count")
        require(report.protocolStateBlobCases.count == 16, "protocol-state blob fixture count")
        require(report.protocolStateBlobCases.contains { $0.name == "deduplication_set_identity_with_duplicate_message" }, "duplicate message blob fixture")
        require(report.protocolStateBlobCases.contains { $0.name == "pending_acknowledgments_session_with_duplicate_ack" }, "duplicate acknowledgment blob fixture")
        require(report.unsupportedMessageVersionRejected, "unsupported message version")
        require(report.malformedMessageRejected, "malformed message")
        require(report.oldSenderVisibleMessageRejected, "old sender-visible message")
        require(report.unsupportedInitialHandshakeVersionRejected, "unsupported initial handshake version")
        require(report.malformedInitialHandshakeRejected, "malformed initial handshake")
        require(report.unsupportedBlobMajorRejected, "unsupported blob major")
        require(report.malformedBlobRejected, "malformed blob")

        let sessionCase = report.sealedSenderSessionCases[0]
        require(sessionCase.name == "sealed_text", "sealed-sender fixture name")
        require(sessionCase.plaintextHex == "66697874757265207365616c65642073657373696f6e", "sealed-sender plaintext")
        require(sessionCase.senderIdentityHiddenBeforeDecrypt, "sender identity hidden before decrypt")
        require(sessionCase.senderCertificateHiddenBeforeDecrypt, "sender certificate hidden before decrypt")
        require(sessionCase.senderSignatureHiddenBeforeDecrypt, "sender signature hidden before decrypt")
        require(!sessionCase.evidenceBundleHex.isEmpty, "accepted Message evidence bundle")
        require(sessionCase.tamperedCiphertextRejected, "tampered ciphertext rejection")
        require(!sessionCase.transportVisible.ciphertextHex.contains(sessionCase.postDecryption.senderIdentityKeyHex), "identity leaked into transport payload")
        require(!sessionCase.transportVisible.ciphertextHex.contains(sessionCase.postDecryption.senderCertificateHex), "certificate leaked into transport payload")
        require(!sessionCase.transportVisible.ciphertextHex.contains(sessionCase.postDecryption.senderSignatureHex), "signature leaked into transport payload")

        let initialCase = report.initialHandshakeCases[0]
        require(initialCase.transportVisible.prekeyReference?.oneTimePrekeyIdentifier == 7, "frame one-time prekey identifier")
        require(initialCase.senderIdentityHiddenBeforeDecrypt, "initial handshake identity hidden before decrypt")
        require(initialCase.senderCertificateHiddenBeforeDecrypt, "initial handshake certificate hidden before decrypt")
        require(initialCase.senderSignatureHiddenBeforeDecrypt, "initial handshake signature hidden before decrypt")
        require(initialCase.tamperedCiphertextRejected, "initial handshake tampered ciphertext rejection")

        print("Swift fixture replay passed")
    }

    private static func require(_ condition: @autoclosure () -> Bool, _ message: String) {
        if !condition() {
            fputs("fixture replay failed: \(message)\n", stderr)
            exit(1)
        }
    }
}
