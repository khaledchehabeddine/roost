import CryptoKit
import Foundation

@main
struct EvidenceBundleVectors {
    private static let validBundle = Data(hex: "01011009090909090909090909090909090909bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a50221000000004000800000000000000081fca7ffbc3100200000001b636f6e7465787420666f7220616e206162757365207265706f7274007b41657468657253656e64657243657274696669636174652d76323a020b746573742d646f6d61696e0a72656c61792e7465737457f24707f390532aa6598f61c43f3bc2dae984525359cb43fc13db947e93f63e65e8f9b0bc6eae124169f0576f97362d295a8cf5f770b45e14357ce647d33eec00000000655577a0409ed439e636de0aabb9ec5e6c0562d1c2892d1a1679897b3f4d1583bcc4abfc014821307b3bb6e35ec85fe66bca2c2e46ffd56f0bd533e43469659c01f985450640340624ac228577b9d3823baec5f873a09708c2e88d4f83ce4f2660911f7606b89a1b0b0f82399c1137947e6fc1c1bec30553cfdc435559c1d76007741143e40f")
    private static let domainKey = DomainSigningKey(
        identifier: Data(hex: "746573742d646f6d61696e"),
        verifyingKey: Data(hex: "6556ea860463d074ae046736e1f20f6c78f7a26e31518d1fe7f645150aaa6ad1"),
        status: .trusted
    )
    private static let relayDomain = Data("relay.test".utf8)

    static func main() throws {
        let verified = try verifyEvidenceBundle(
            evidenceBundle: validBundle,
            expectedProfile: .messageTranscriptVersion1,
            domainSigningKeys: [domainKey],
            expectedRelayDomain: relayDomain,
            acceptedTimestampSecs: 1_700_000_000,
            graceWindowSecs: 0
        )
        require(verified.profile == .messageTranscriptVersion1, "profile")
        require(verified.evidenceIdentity == Data(hex: "a7af7974cb7c5c3c770baf1b946f8d7d69a295068d99b78425b1df538a6aa489"), "evidence identity")
        require(verified.sessionKey == Data(repeating: 0x09, count: 16), "session key")
        require(verified.recipientIdentityVerifyingKey == Data(hex: "bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a5"), "recipient Identity Key")
        require(verified.messageId == Data(hex: "02210000000040008000000000000000"), "message ID")
        require(verified.timestampMillis == 1_700_000_300_545, "timestamp")
        require(verified.payloadKind == .encryptedText, "payload kind")
        require(verified.plaintext == Data("context for an abuse report".utf8), "plaintext")
        require(verified.senderIdentityKey.x25519PublicKey == Data(hex: "57f24707f390532aa6598f61c43f3bc2dae984525359cb43fc13db947e93f63e"), "sender agreement key")
        require(verified.senderIdentityKey.ed25519VerifyingKey == Data(hex: "65e8f9b0bc6eae124169f0576f97362d295a8cf5f770b45e14357ce647d33eec"), "sender verifying key")
        require(verified.relayDomain == relayDomain, "relay domain")
        require(verified.certificateExpiresAtSecs == 1_700_100_000, "certificate expiry")

        // Independent counterparties for the two signatures carried by the vector.
        let certificate = Data(hex: "41657468657253656e64657243657274696669636174652d76323a020b746573742d646f6d61696e0a72656c61792e7465737457f24707f390532aa6598f61c43f3bc2dae984525359cb43fc13db947e93f63e65e8f9b0bc6eae124169f0576f97362d295a8cf5f770b45e14357ce647d33eec00000000655577a0")
        let certificateSignature = Data(hex: "9ed439e636de0aabb9ec5e6c0562d1c2892d1a1679897b3f4d1583bcc4abfc014821307b3bb6e35ec85fe66bca2c2e46ffd56f0bd533e43469659c01f9854506")
        let domainPublicKey = try Curve25519.Signing.PublicKey(rawRepresentation: domainKey.verifyingKey)
        require(domainPublicKey.isValidSignature(certificateSignature, for: certificate), "CryptoKit certificate signature")
        let messageSignature = Data(hex: "340624ac228577b9d3823baec5f873a09708c2e88d4f83ce4f2660911f7606b89a1b0b0f82399c1137947e6fc1c1bec30553cfdc435559c1d76007741143e40f")
        let senderPublicKey = try Curve25519.Signing.PublicKey(rawRepresentation: verified.senderIdentityKey.ed25519VerifyingKey)
        require(senderPublicKey.isValidSignature(messageSignature, for: messageTranscript()), "CryptoKit Message transcript signature")

        var malformed = Data([1, 1, 0xff])
        requireInvalidData("malformed bundle") { try verify(malformed) }
        malformed = validBundle
        malformed[1] = 2
        requireInvalidData("wrong profile") { try verify(malformed) }
        malformed = validBundle
        malformed[0] = 2
        requireUnsupportedVersion("unsupported version") { try verify(malformed) }
        malformed = validBundle
        malformed[malformed.count - 1] ^= 0x01
        requireAuthenticationFailed("tampered Message signature") { try verify(malformed) }
        malformed = validBundle
        for index in 19..<51 { malformed[index] = 0xff }
        requireInvalidData("noncanonical recipient Identity Key") { try verify(malformed) }
        requireInvalidData("excessive certificate grace window") {
            _ = try verifyEvidenceBundle(
                evidenceBundle: validBundle,
                expectedProfile: .messageTranscriptVersion1,
                domainSigningKeys: [domainKey],
                expectedRelayDomain: relayDomain,
                acceptedTimestampSecs: 1_700_000_000,
                graceWindowSecs: 301
            )
        }
        requireCertificateRejected("cross-relay replay") {
            _ = try verifyEvidenceBundle(
                evidenceBundle: validBundle,
                expectedProfile: .messageTranscriptVersion1,
                domainSigningKeys: [domainKey],
                expectedRelayDomain: Data("other-relay.test".utf8),
                acceptedTimestampSecs: 1_700_000_000,
                graceWindowSecs: 0
            )
        }

        print("Swift evidence bundle vectors passed")
    }

    private static func verify(_ bundle: Data) throws {
        _ = try verifyEvidenceBundle(
            evidenceBundle: bundle,
            expectedProfile: .messageTranscriptVersion1,
            domainSigningKeys: [domainKey],
            expectedRelayDomain: relayDomain,
            acceptedTimestampSecs: 1_700_000_000,
            graceWindowSecs: 0
        )
    }

    private static func messageTranscript() -> Data {
        let paddedPayload = Data(hex: "0000001b636f6e7465787420666f7220616e206162757365207265706f727400")
        let senderCertificate = Data(hex: "41657468657253656e64657243657274696669636174652d76323a020b746573742d646f6d61696e0a72656c61792e7465737457f24707f390532aa6598f61c43f3bc2dae984525359cb43fc13db947e93f63e65e8f9b0bc6eae124169f0576f97362d295a8cf5f770b45e14357ce647d33eec00000000655577a0")
        var transcript = Data("AetherMessageTranscript-v1:".utf8)
        transcript.appendBigEndian(UInt32(16))
        transcript.append(Data(repeating: 0x09, count: 16))
        transcript.append(Data(hex: "bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a5"))
        transcript.append(Data(hex: "02210000000040008000000000000000"))
        transcript.appendBigEndian(UInt64(1_700_000_300_545))
        transcript.append(0)
        transcript.appendBigEndian(UInt32(paddedPayload.count))
        transcript.append(paddedPayload)
        transcript.appendBigEndian(UInt32(senderCertificate.count))
        transcript.append(senderCertificate)
        return transcript
    }

    private static func requireInvalidData(_ message: String, _ block: () throws -> Void) {
        requireError(message, block) { if case .InvalidData = $0 { true } else { false } }
    }

    private static func requireUnsupportedVersion(_ message: String, _ block: () throws -> Void) {
        requireError(message, block) { if case .UnsupportedVersion = $0 { true } else { false } }
    }

    private static func requireAuthenticationFailed(_ message: String, _ block: () throws -> Void) {
        requireError(message, block) { if case .AuthenticationFailed = $0 { true } else { false } }
    }

    private static func requireCertificateRejected(_ message: String, _ block: () throws -> Void) {
        requireError(message, block) { if case .CertificateRejected = $0 { true } else { false } }
    }

    private static func requireError(
        _ message: String,
        _ block: () throws -> Void,
        _ matches: (ClientError) -> Bool
    ) {
        do {
            try block()
            fail(message)
        } catch let error as ClientError {
            require(matches(error), "\(message): got \(error)")
        } catch {
            fail("\(message): got \(error)")
        }
    }

    private static func require(_ condition: @autoclosure () -> Bool, _ message: String) {
        if !condition() { fail(message) }
    }

    private static func fail(_ message: String) -> Never {
        fputs("evidence bundle vector coverage failed: \(message)\n", stderr)
        exit(1)
    }
}

private extension Data {
    init(hex: String) {
        precondition(hex.count.isMultiple(of: 2))
        self.init(stride(from: 0, to: hex.count, by: 2).map { index in
            let start = hex.index(hex.startIndex, offsetBy: index)
            let end = hex.index(start, offsetBy: 2)
            return UInt8(hex[start..<end], radix: 16)!
        })
    }

    mutating func appendBigEndian<T: FixedWidthInteger>(_ value: T) {
        var encoded = value.bigEndian
        Swift.withUnsafeBytes(of: &encoded) { append(contentsOf: $0) }
    }
}
