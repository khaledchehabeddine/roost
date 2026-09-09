import CryptoKit
import Foundation

@main
struct EvidenceBundleVectors {
    static func main() throws {
        let domainKey = DomainSigningKey(
            identifier: bytes("DOMAIN_ID"),
            verifyingKey: bytes("DOMAIN_KEY"),
            status: .trusted
        )
        let verified = try verifyEvidenceBundle(
            evidenceBundle: bytes("BUNDLE"),
            expectedProfile: .messageTranscriptVersion1,
            domainSigningKeys: [domainKey],
            expectedRelayDomain: bytes("RELAY"),
            acceptedTimestampSecs: UInt64(value("ACCEPTED"))!,
            graceWindowSecs: UInt64(value("GRACE"))!
        )
        precondition(verified.evidenceIdentity == bytes("IDENTITY"))
        precondition(verified.payloadKind == .encryptedText)
        let certificate = bytes("CERTIFICATE")
        let domain = try Curve25519.Signing.PublicKey(rawRepresentation: domainKey.verifyingKey)
        precondition(domain.isValidSignature(bytes("CERTIFICATE_SIGNATURE"), for: certificate))

        // Rebuild the signed transcript from the fields returned across FFI.
        var padded = Data()
        padded.appendBigEndian(UInt32(verified.plaintext.count))
        padded.append(verified.plaintext)
        var bucket = 32
        while bucket < padded.count { bucket *= 2 }
        padded.append(Data(repeating: 0, count: bucket - padded.count))
        var transcript = Data("AetherMessageTranscript-v1:".utf8)
        transcript.appendBigEndian(UInt32(verified.sessionKey.count))
        transcript.append(verified.sessionKey)
        transcript.append(verified.recipientIdentityVerifyingKey)
        transcript.append(verified.messageId)
        transcript.appendBigEndian(verified.timestampMillis)
        transcript.append(0)
        transcript.appendBigEndian(UInt32(padded.count))
        transcript.append(padded)
        transcript.appendBigEndian(UInt32(certificate.count))
        transcript.append(certificate)
        let sender = try Curve25519.Signing.PublicKey(
            rawRepresentation: verified.senderIdentityKey.ed25519VerifyingKey
        )
        precondition(sender.isValidSignature(bytes("MESSAGE_SIGNATURE"), for: transcript))
        transcript[transcript.count - 1] ^= 1
        precondition(!sender.isValidSignature(bytes("MESSAGE_SIGNATURE"), for: transcript))
        // Verify fresh signature bytes returned by the generated signer binding.
        let client = Client(storage: InMemorySecureStorage())
        let prepared = try client.identity().prepareGenerateIdentity()
        _ = try client.commitOperation(identifier: prepared.operation.identifier)
        _ = try client.finalizeOperation(identifier: prepared.operation.identifier)
        let authentication = Data([0x00, 0x7f, 0x80, 0xff])
        let signature = try client.identity().signAuthenticationTranscript(transcript: authentication)
        let key = try Curve25519.Signing.PublicKey(
            rawRepresentation: prepared.identity.ed25519VerifyingKey
        )
        precondition(key.isValidSignature(signature, for: authentication))
        print("Swift native Evidence Bundle and returned signature verification passed")
    }

    private static func value(_ key: String) -> String {
        ProcessInfo.processInfo.environment["ROOST_EVIDENCE_" + key]!
    }

    private static func bytes(_ key: String) -> Data {
        let hex = value(key)
        return Data(stride(from: 0, to: hex.count, by: 2).map { index in
            let start = hex.index(hex.startIndex, offsetBy: index)
            let end = hex.index(start, offsetBy: 2)
            return UInt8(hex[start..<end], radix: 16)!
        })
    }
}

private extension Data {
    mutating func appendBigEndian<T: FixedWidthInteger>(_ value: T) {
        var encoded = value.bigEndian
        Swift.withUnsafeBytes(of: &encoded) { append(contentsOf: $0) }
    }
}
