import CryptoKit
import Foundation

// Exercises signAuthenticationTranscript through the generated Swift surface.
// See the Kotlin counterpart for why this coverage exists: the identity key
// could sign nothing a caller defined, so a relay authentication transcript
// (REL-RLY-16) could not be signed on either mobile platform.
//
// The verification below is deliberately CryptoKit's, not Aether's. A relay
// verifies with its own Ed25519 implementation over the transcript bytes alone,
// so an Aether-side check would prove only that Aether agrees with itself.

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

@main
struct AuthenticationTranscriptSigning {
    private static let httpContext = Data("Relay-HTTP-Auth-v1".utf8)

    static func main() throws {
        let store = KeyStore(storage: MemorySecureStorage())
        let identity = try store.generateIdentity()
        let transcript = httpTranscript(identitySigningKey: identity.ed25519VerifyingKey)

        let signature = try store.signAuthenticationTranscript(transcript: transcript)
        require(signature.count == 64, "an Ed25519 signature must cross as 64 bytes")

        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: identity.ed25519VerifyingKey)
        require(
            publicKey.isValidSignature(signature, for: transcript),
            "the signature must verify over the transcript bytes exactly as sent"
        )
        // The transcript already begins with its own context. Had the export
        // prepended a second one, this — and only this — would have verified,
        // and the relay would have rejected every request with no diagnosis.
        require(
            !publicKey.isValidSignature(signature, for: httpContext + transcript),
            "the signature must not cover a context-prefixed preimage"
        )

        // Ed25519 is deterministic; a retried challenge must resend the same proof.
        let resigned = try store.signAuthenticationTranscript(transcript: transcript)
        require(resigned == signature, "signing the same transcript twice must produce the same bytes")

        // The identity key is what signs Aether's own bindings and message
        // transcripts, so the export must refuse preimages that could pass for
        // one of them.
        for context in ["AetherIKBinding-v1:", "AetherDKToIK-v1:", "AetherMessageTranscript-v1:"] {
            var reserved = Data(context.utf8)
            reserved.append(identity.x25519PublicKey)
            reserved.append(identity.ed25519VerifyingKey)
            requireInvalidData(store, reserved, "a reserved Aether preimage must be refused: \(context)")
        }
        requireInvalidData(store, Data(), "an empty transcript must be refused")

        print("Swift authentication transcript signing coverage passed")
    }

    // REL-RLY-16: the context, protocol version, challenge nonce and signing key
    // are fixed width and unprefixed; the variable-length fields carry u16
    // big-endian lengths counting only the field that follows.
    private static func httpTranscript(identitySigningKey: Data) -> Data {
        var transcript = httpContext
        transcript.append(contentsOf: [0x00, 0x01])
        transcript.append(Data(repeating: 0x22, count: 32))
        transcript.append(identitySigningKey)
        appendLengthPrefixed(&transcript, Data("relay.example".utf8))
        appendLengthPrefixed(&transcript, Data("POST".utf8))
        appendLengthPrefixed(&transcript, Data("/v1/prekeys?count=10".utf8))
        transcript.append(Data(SHA256.hash(data: Data("vector-body".utf8))))
        return transcript
    }

    private static func appendLengthPrefixed(_ transcript: inout Data, _ field: Data) {
        transcript.append(UInt8(field.count >> 8))
        transcript.append(UInt8(field.count & 0xff))
        transcript.append(field)
    }

    private static func requireInvalidData(_ store: KeyStore, _ transcript: Data, _ message: String) {
        do {
            _ = try store.signAuthenticationTranscript(transcript: transcript)
            fail(message)
        } catch let error as AetherError {
            guard case .InvalidData(_) = error else {
                fail("\(message): got \(error)")
            }
        } catch {
            fail("\(message): got \(error)")
        }
    }

    private static func require(_ condition: Bool, _ message: String) {
        if !condition {
            fail(message)
        }
    }

    private static func fail(_ message: String) -> Never {
        fputs("authentication transcript signing coverage failed: \(message)\n", stderr)
        exit(1)
    }
}
