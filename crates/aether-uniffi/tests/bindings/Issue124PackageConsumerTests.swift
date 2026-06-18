import Aether
import CryptoKit
import Foundation
import XCTest

private final class MemorySecureStorage: SecureStorage, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: Data] = [:]

    func store(key: String, value: Data) throws {
        lock.lock()
        values[key] = value
        lock.unlock()
    }

    func load(key: String) throws -> Data? {
        lock.lock()
        let value = values[key]
        lock.unlock()
        return value
    }

    func delete(key: String) throws {
        lock.lock()
        values.removeValue(forKey: key)
        lock.unlock()
    }
}

final class Issue124PackageConsumerTests: XCTestCase {
    func testPackageConsumerExercisesIdentitySessionBackupAndMessagePath() throws {
        let engine = ProtocolStateEngine()
        let domainSigner = Curve25519.Signing.PrivateKey()
        let domainIdentifier = Data("issue-124-domain".utf8)
        let domainKey = DomainSigningKey(
            identifier: domainIdentifier,
            verifyingKey: domainSigner.publicKey.rawRepresentation,
            status: .trusted
        )
        let validation = SenderCertificateValidation(
            domainSigningKeys: [domainKey],
            revocationState: RevocationState(available: true, revokedIdentityKeys: []),
            referenceTimestampSecs: 1_700_000_000,
            graceWindowSecs: 0
        )

        let alice = KeyStore(storage: MemorySecureStorage())
        let bob = KeyStore(storage: MemorySecureStorage())
        let aliceIdentity = try alice.generateIdentity()
        let bobIdentity = try bob.generateIdentity()
        _ = try alice.rotateSignedPrekeyNow()
        _ = try bob.rotateSignedPrekeyNow()
        let alicePublication = try alice.currentPublicationBundle()
        let bobPublication = try bob.currentPublicationBundle()
        let bobOneTimePrekey = try XCTUnwrap(try bob.replenishOneTimePrekeys().first)

        let aliceCertificate = try signedCertificate(
            identity: aliceIdentity,
            publication: alicePublication,
            identifier: domainIdentifier,
            signer: domainSigner
        )
        let bobCertificate = try signedCertificate(
            identity: bobIdentity,
            publication: bobPublication,
            identifier: domainIdentifier,
            signer: domainSigner
        )
        let validated = try validateSenderCertificate(
            certificate: aliceCertificate.bytes,
            signature: aliceCertificate.signature,
            domainSigningKeys: [domainKey],
            revocationState: validation.revocationState,
            referenceTimestampSecs: validation.referenceTimestampSecs,
            graceWindowSecs: validation.graceWindowSecs
        )
        XCTAssertEqual(validated.identityKey, identityKey(aliceIdentity))

        let backup = try alice.exportEncryptedBackup(passphrase: "issue-124-passphrase")
        let restored = KeyStore(storage: MemorySecureStorage())
        try restored.importEncryptedBackup(data: backup, passphrase: "issue-124-passphrase")
        XCTAssertTrue(try restored.hasIdentity())

        let sessionKey = Data(repeating: 0x24, count: 16)
        let initiation = try alice.initiateSession(
            sessionKey: sessionKey,
            responderIdentity: bobIdentity,
            responderPublication: bobPublication,
            responderOneTimePrekey: bobOneTimePrekey,
            senderCertificate: aliceCertificate.bytes,
            senderSignature: aliceCertificate.signature,
            plaintext: Data("hello bob".utf8)
        )
        let acceptance = try bob.acceptSession(
            sessionKey: sessionKey,
            initiatorIdentity: aliceIdentity,
            message: initiation.message
        )
        XCTAssertEqual(acceptance.plaintext, Data("hello bob".utf8))

        var aliceSnapshot: [ProtocolStateEntry] = []
        apply(&aliceSnapshot, initiation.stateUpdates)
        let recorded = try engine.recordContact(
            snapshot: [],
            contactIdentity: contactIdentity(identity: bobIdentity, publication: bobPublication)
        )
        apply(&aliceSnapshot, recorded.stateUpdates)
        let acceptedContact = try engine.acceptContact(
            snapshot: aliceSnapshot,
            identityKey: identityKey(bobIdentity)
        )
        apply(&aliceSnapshot, acceptedContact.stateUpdates)

        let outbound = try alice.encryptMessage(
            snapshot: aliceSnapshot,
            sessionKey: sessionKey,
            messageId: Data(repeating: 0x25, count: 16),
            contactIdentityKey: identityKey(bobIdentity),
            recipientPublicKey: bobPublication.discoveryKey.publicKey,
            timestampMillis: 1_700_000_001_000,
            senderCertificate: aliceCertificate.bytes,
            senderSignature: aliceCertificate.signature,
            plaintext: Data("package message".utf8)
        )
        XCTAssertEqual(outbound.payloadKind, .encryptedText)
        apply(&aliceSnapshot, outbound.stateUpdates)
        XCTAssertEqual(try engine.pendingAcknowledgments(snapshot: aliceSnapshot, key: sessionKey).count, 1)
        XCTAssertEqual(
            try engine.retryInstructions(
                snapshot: aliceSnapshot,
                key: sessionKey,
                nowMillis: 1_700_000_001_001,
                retryWindowMillis: 0
            ).instructions.count,
            1
        )

        var bobSnapshot: [ProtocolStateEntry] = []
        apply(&bobSnapshot, acceptance.stateUpdates)
        let deduplicationKey = Data("bob-dedup".utf8)
        apply(&bobSnapshot, [try engine.initializeDeduplicationSet(key: deduplicationKey)])

        let inbound = try bob.decryptMessage(
            snapshot: bobSnapshot,
            sessionKey: sessionKey,
            deduplicationKey: deduplicationKey,
            message: outbound.message,
            acknowledgmentId: Data(repeating: 0x26, count: 16),
            acknowledgmentRecipientPublicKey: alicePublication.discoveryKey.publicKey,
            acknowledgmentTimestampMillis: 1_700_000_001_002,
            acknowledgmentSenderCertificate: bobCertificate.bytes,
            acknowledgmentSenderSignature: bobCertificate.signature,
            senderCertificateValidation: validation
        )
        XCTAssertEqual(inbound.kind, .accepted)
        XCTAssertEqual(inbound.payloadKind, .encryptedText)
        XCTAssertEqual(inbound.plaintext, Data("package message".utf8))
        XCTAssertNotNil(inbound.acknowledgment)
        XCTAssertTrue(inbound.stateUpdates.contains { $0.kind == .ratchetSession })
        XCTAssertTrue(inbound.stateUpdates.contains { $0.kind == .deduplicationSet })
        apply(&bobSnapshot, inbound.stateUpdates)

        let duplicate = try bob.decryptMessage(
            snapshot: bobSnapshot,
            sessionKey: sessionKey,
            deduplicationKey: deduplicationKey,
            message: outbound.message,
            acknowledgmentId: Data(repeating: 0x27, count: 16),
            acknowledgmentRecipientPublicKey: alicePublication.discoveryKey.publicKey,
            acknowledgmentTimestampMillis: 1_700_000_001_003,
            acknowledgmentSenderCertificate: bobCertificate.bytes,
            acknowledgmentSenderSignature: bobCertificate.signature,
            senderCertificateValidation: nil
        )
        XCTAssertEqual(duplicate.kind, .duplicate)
        XCTAssertNil(duplicate.plaintext)
        XCTAssertTrue(duplicate.stateUpdates.isEmpty)

        let stream = try ContactEventStream.withObserverCapacity(
            initialState: [acceptedContact.contact],
            observerCapacity: 1
        )
        let observer = try stream.subscribe()
        let event = ContactEvent(kind: .changed, contact: acceptedContact.contact)
        let envelope = try stream.emit(event: event, nextState: [acceptedContact.contact])
        XCTAssertEqual(envelope.id, 1)
        XCTAssertEqual(try XCTUnwrap(try observer.pollNext()).kind, .event)

        try exerciseCheckedInReceiveFixtures()
    }
}

private func exerciseCheckedInReceiveFixtures() throws {
    let sessionFile: SessionFixtureFile = try loadFixture("sealed_sender_session_messages_v1")
    let blobFile: BlobFixtureFile = try loadFixture("protocol_state_blobs_v1")
    let fixture = try XCTUnwrap(sessionFile.fixtures.first { $0.name == "sealed_text" })
    let duplicateBlob = try XCTUnwrap(
        blobFile.fixtures.first { $0.name == "deduplication_set_identity_with_duplicate_message" }
    )

    let encoded = try Data(hex: fixture.encodedHex)
    let message = try decodeMessage(bytes: encoded)
    XCTAssertEqual(message.version, fixture.transportVisible.version)
    XCTAssertEqual(message.recipientPublicKey, try Data(hex: fixture.transportVisible.recipientPublicKeyHex))
    XCTAssertNil(message.prekeyReference)
    XCTAssertEqual(message.ephemeralPublicKey, try Data(hex: fixture.transportVisible.ephemeralPublicKeyHex))
    XCTAssertEqual(message.ciphertext, try Data(hex: fixture.transportVisible.ciphertextHex))
    XCTAssertEqual(try encodeMessage(message: message), encoded)

    let validation = try senderCertificateValidation(sessionFile.senderCertificateValidation)
    let validated = try validateSenderCertificate(
        certificate: try Data(hex: fixture.postDecryption.senderCertificateHex),
        signature: try Data(hex: fixture.postDecryption.senderSignatureHex),
        domainSigningKeys: validation.domainSigningKeys,
        revocationState: validation.revocationState,
        referenceTimestampSecs: validation.referenceTimestampSecs,
        graceWindowSecs: validation.graceWindowSecs
    )
    XCTAssertEqual(validated.identityKey.x25519PublicKey, try Data(hex: fixture.postDecryption.senderIdentityKeyHex))
    XCTAssertEqual(
        validated.identityKey.ed25519VerifyingKey,
        try Data(hex: fixture.postDecryption.senderIdentityVerifyingKeyHex)
    )

    let store = KeyStore(storage: MemorySecureStorage())
    _ = try store.generateIdentity()
    let duplicate = try store.decryptMessage(
        snapshot: [
            ProtocolStateEntry(
                kind: try protocolStateKind(duplicateBlob.kind),
                key: try Data(hex: duplicateBlob.keyHex),
                blob: try Data(hex: duplicateBlob.currentEncodedHex)
            ),
        ],
        sessionKey: try Data(hex: sessionFile.sessionKeyHex),
        deduplicationKey: try Data(hex: duplicateBlob.keyHex),
        message: message,
        acknowledgmentId: Data(repeating: 0x31, count: 16),
        acknowledgmentRecipientPublicKey: message.recipientPublicKey,
        acknowledgmentTimestampMillis: 1_700_000_001_004,
        acknowledgmentSenderCertificate: Data("duplicate ack certificate".utf8),
        acknowledgmentSenderSignature: Data("duplicate ack signature".utf8),
        senderCertificateValidation: nil
    )
    XCTAssertEqual(duplicate.kind, .duplicate)
    XCTAssertNil(duplicate.acknowledgment)
    XCTAssertTrue(duplicate.stateUpdates.isEmpty)
}

private struct SignedCertificate {
    let bytes: Data
    let signature: Data
}

private func signedCertificate(
    identity: Identity,
    publication: PublicationBundle,
    identifier: Data,
    signer: Curve25519.Signing.PrivateKey
) throws -> SignedCertificate {
    var bytes = Data("AetherSenderCertificate-v1:".utf8)
    bytes.append(contentsOf: [1, UInt8(identifier.count)])
    bytes.append(identifier)
    bytes.append(identity.x25519PublicKey)
    bytes.append(identity.ed25519VerifyingKey)
    bytes.append(publication.discoveryKey.publicKey)
    bytes.append(publication.discoveryKey.verifyingKey)
    bytes.appendBigEndian(publication.discoveryKey.epoch)
    bytes.appendBigEndian(UInt64(1_700_100_000))
    return SignedCertificate(bytes: bytes, signature: try signer.signature(for: bytes))
}

private func identityKey(_ identity: Identity) -> IdentityKey {
    IdentityKey(
        x25519PublicKey: identity.x25519PublicKey,
        ed25519VerifyingKey: identity.ed25519VerifyingKey
    )
}

private func contactIdentity(identity: Identity, publication: PublicationBundle) -> ContactIdentity {
    ContactIdentity(
        identityKey: identityKey(identity),
        discoveryKey: ContactDiscoveryKey(
            x25519PublicKey: publication.discoveryKey.publicKey,
            ed25519VerifyingKey: publication.discoveryKey.verifyingKey,
            epoch: publication.discoveryKey.epoch,
            createdAt: publication.discoveryKey.createdAt,
            identitySignature: publication.discoveryKey.signature
        )
    )
}

private func apply(_ snapshot: inout [ProtocolStateEntry], _ updates: [ProtocolStateUpdate]) {
    for update in updates {
        snapshot.removeAll { $0.kind == update.kind && $0.key == update.key }
        if let blob = update.blob {
            snapshot.append(ProtocolStateEntry(kind: update.kind, key: update.key, blob: blob))
        }
    }
}

private struct SessionFixtureFile: Decodable {
    let sessionKeyHex: String
    let senderCertificateValidation: CertificateValidationFixture
    let fixtures: [SessionMessageFixture]
}

private struct CertificateValidationFixture: Decodable {
    let domainSigningKeys: [DomainSigningKeyFixture]
    let revokedIdentityKeys: [IdentityKeyFixture]
    let referenceTimestampSecs: UInt64
    let graceWindowSecs: UInt64
}

private struct DomainSigningKeyFixture: Decodable {
    let identifierHex: String
    let verifyingKeyHex: String
    let status: String
}

private struct IdentityKeyFixture: Decodable {
    let x25519PublicKeyHex: String
    let ed25519VerifyingKeyHex: String
}

private struct SessionMessageFixture: Decodable {
    let name: String
    let encodedHex: String
    let transportVisible: MessageTransportFixture
    let postDecryption: SenderIdentityFixture
}

private struct MessageTransportFixture: Decodable {
    let version: UInt8
    let recipientPublicKeyHex: String
    let ephemeralPublicKeyHex: String
    let ciphertextHex: String
}

private struct SenderIdentityFixture: Decodable {
    let senderIdentityKeyHex: String
    let senderIdentityVerifyingKeyHex: String
    let senderCertificateHex: String
    let senderSignatureHex: String
}

private struct BlobFixtureFile: Decodable {
    let fixtures: [BlobFixture]
}

private struct BlobFixture: Decodable {
    let name: String
    let kind: String
    let keyHex: String
    let currentEncodedHex: String
}

private enum FixtureError: Error {
    case invalidHex(String)
    case unknownDomainStatus(String)
    case unknownProtocolStateKind(String)
}

private func loadFixture<T: Decodable>(_ name: String) throws -> T {
    let url = try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Resources"))
    let decoder = JSONDecoder()
    decoder.keyDecodingStrategy = .convertFromSnakeCase
    return try decoder.decode(T.self, from: try Data(contentsOf: url))
}

private func senderCertificateValidation(_ fixture: CertificateValidationFixture) throws -> SenderCertificateValidation {
    SenderCertificateValidation(
        domainSigningKeys: try fixture.domainSigningKeys.map { key in
            DomainSigningKey(
                identifier: try Data(hex: key.identifierHex),
                verifyingKey: try Data(hex: key.verifyingKeyHex),
                status: try domainSigningKeyStatus(key.status)
            )
        },
        revocationState: RevocationState(
            available: true,
            revokedIdentityKeys: try fixture.revokedIdentityKeys.map { key in
                IdentityKey(
                    x25519PublicKey: try Data(hex: key.x25519PublicKeyHex),
                    ed25519VerifyingKey: try Data(hex: key.ed25519VerifyingKeyHex)
                )
            }
        ),
        referenceTimestampSecs: fixture.referenceTimestampSecs,
        graceWindowSecs: fixture.graceWindowSecs
    )
}

private func domainSigningKeyStatus(_ status: String) throws -> DomainSigningKeyStatus {
    switch status {
    case "trusted":
        return .trusted
    case "untrusted":
        return .untrusted
    default:
        throw FixtureError.unknownDomainStatus(status)
    }
}

private func protocolStateKind(_ kind: String) throws -> ProtocolStateKind {
    switch kind {
    case "deduplication_set":
        return .deduplicationSet
    default:
        throw FixtureError.unknownProtocolStateKind(kind)
    }
}

private extension Data {
    init(hex: String) throws {
        guard hex.count.isMultiple(of: 2) else {
            throw FixtureError.invalidHex(hex)
        }

        self.init()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else {
                throw FixtureError.invalidHex(hex)
            }
            append(contentsOf: [byte])
            index = next
        }
    }

    mutating func appendBigEndian(_ value: UInt32) {
        var value = value.bigEndian
        Swift.withUnsafeBytes(of: &value) { append(contentsOf: $0) }
    }

    mutating func appendBigEndian(_ value: UInt64) {
        var value = value.bigEndian
        Swift.withUnsafeBytes(of: &value) { append(contentsOf: $0) }
    }
}
