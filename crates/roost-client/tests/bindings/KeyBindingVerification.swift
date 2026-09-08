import CryptoKit
import Foundation

// Exercises verifyIdentityKeyBinding and verifyDiscoveryToIdentityBinding through
// the generated Swift surface. See the Kotlin counterpart for why this coverage
// exists: both directions of the mutual binding were correct in roost-crypto and
// unreachable from any binding, so the check that decides whether a discovery key
// vouches for an identity had to be written a second time outside Aether.
//
// The counterparty here is CryptoKit's Ed25519, not Aether's. Aether must accept a
// discovery-to-identity signature this file produced with a key Aether never saw,
// and CryptoKit must accept the identity self-binding Aether produced.

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
struct KeyBindingVerification {
    private static let identityBindingContext = Data("AetherIKBinding-v1:".utf8)
    private static let discoveryToIdentityContext = Data("AetherDKToIK-v1:".utf8)

    static func main() throws {
        let store = Client(storage: MemorySecureStorage())
        let prepared = try store.identity().prepareGenerateIdentity()
        _ = try store.commitOperation(identifier: prepared.operation.identifier)
        _ = try store.finalizeOperation(identifier: prepared.operation.identifier)
        let generated = prepared.identity
        let identity = IdentityKey(
            x25519PublicKey: generated.x25519PublicKey,
            ed25519VerifyingKey: generated.ed25519VerifyingKey
        )

        // ── The identity self-binding, both ways round ──────────────────────

        try verifyIdentityKeyBinding(
            identity: identity,
            bindingSignature: generated.identityBindingSignature
        )
        let identityPublicKey = try Curve25519.Signing.PublicKey(
            rawRepresentation: identity.ed25519VerifyingKey
        )
        require(
            identityPublicKey.isValidSignature(
                generated.identityBindingSignature,
                for: payload(identityBindingContext, identity)
            ),
            "CryptoKit must accept the self-binding Aether produced, over the documented preimage"
        )

        // ── The discovery-to-identity direction, signed outside Aether ──────

        let discovery = Curve25519.Signing.PrivateKey()
        let discoveryVerifyingKey = discovery.publicKey.rawRepresentation
        let discoveryToIdentity = try discovery.signature(
            for: payload(discoveryToIdentityContext, identity)
        )

        try verifyDiscoveryToIdentityBinding(
            identity: identity,
            discoveryVerifyingKey: discoveryVerifyingKey,
            signature: discoveryToIdentity
        )

        // ── The separation the two contexts exist for ───────────────────────

        // The payloads are byte-identical (AE-KEY-05); only the context differs.
        requireAuthenticationFailed("a DK→IK signature must not satisfy the identity self-binding") {
            try verifyIdentityKeyBinding(
                // Checked under the key that actually signed, so only the context can reject it.
                identity: IdentityKey(
                    x25519PublicKey: identity.x25519PublicKey,
                    ed25519VerifyingKey: discoveryVerifyingKey
                ),
                bindingSignature: discoveryToIdentity
            )
        }
        requireAuthenticationFailed("a self-binding must not satisfy the DK→IK direction") {
            try verifyDiscoveryToIdentityBinding(
                identity: identity,
                discoveryVerifyingKey: identity.ed25519VerifyingKey,
                signature: generated.identityBindingSignature
            )
        }

        // ── The substitution add-by-discovery-key exists to catch ───────────

        // A relay answers with an identity of its own, correctly self-bound, that
        // the typed discovery key never vouched for. Only the DK→IK check refuses it.
        let impostor = Curve25519.Signing.PrivateKey()
        let impostorIdentity = IdentityKey(
            x25519PublicKey: identity.x25519PublicKey,
            ed25519VerifyingKey: impostor.publicKey.rawRepresentation
        )
        try verifyIdentityKeyBinding(
            identity: impostorIdentity,
            bindingSignature: impostor.signature(
                for: payload(identityBindingContext, impostorIdentity)
            )
        )
        let impostorBinding = try impostor.signature(
            for: payload(discoveryToIdentityContext, impostorIdentity)
        )
        requireAuthenticationFailed("an identity the typed discovery key did not sign must be refused") {
            try verifyDiscoveryToIdentityBinding(
                identity: impostorIdentity,
                discoveryVerifyingKey: discoveryVerifyingKey,
                signature: impostorBinding
            )
        }

        // ── Malformed material is not the same answer as a failed binding ───

        var tampered = discoveryToIdentity
        tampered[tampered.startIndex] ^= 0x01
        requireAuthenticationFailed("a tampered signature must not verify") {
            try verifyDiscoveryToIdentityBinding(
                identity: identity,
                discoveryVerifyingKey: discoveryVerifyingKey,
                signature: tampered
            )
        }

        requireInvalidData("a 31-byte discovery key must be refused") {
            try verifyDiscoveryToIdentityBinding(
                identity: identity,
                discoveryVerifyingKey: Data(repeating: 0, count: 31),
                signature: discoveryToIdentity
            )
        }
        requireInvalidData("a 63-byte signature must be refused") {
            try verifyDiscoveryToIdentityBinding(
                identity: identity,
                discoveryVerifyingKey: discoveryVerifyingKey,
                signature: Data(repeating: 0, count: 63)
            )
        }
        // A small-order key is the case that is not merely malformed: signatures
        // under it verify for keys nobody controls.
        requireInvalidData("a weak discovery key must be refused") {
            try verifyDiscoveryToIdentityBinding(
                identity: identity,
                discoveryVerifyingKey: Data(repeating: 0, count: 32),
                signature: discoveryToIdentity
            )
        }
        requireInvalidData("a 16-byte identity agreement key must be refused") {
            try verifyIdentityKeyBinding(
                identity: IdentityKey(
                    x25519PublicKey: Data(repeating: 0, count: 16),
                    ed25519VerifyingKey: identity.ed25519VerifyingKey
                ),
                bindingSignature: generated.identityBindingSignature
            )
        }

        print("Swift key binding verification coverage passed")
    }

    /// `context || ik_x25519 || ik_ed25519` — the 64-byte payload both contexts sign.
    private static func payload(_ context: Data, _ identity: IdentityKey) -> Data {
        var preimage = context
        preimage.append(identity.x25519PublicKey)
        preimage.append(identity.ed25519VerifyingKey)
        return preimage
    }

    private static func requireAuthenticationFailed(_ message: String, _ block: () throws -> Void) {
        do {
            try block()
            fail(message)
        } catch let error as ClientError {
            guard case .AuthenticationFailed(_) = error else {
                fail("\(message): got \(error)")
            }
        } catch {
            fail("\(message): got \(error)")
        }
    }

    private static func requireInvalidData(_ message: String, _ block: () throws -> Void) {
        do {
            try block()
            fail(message)
        } catch let error as ClientError {
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
        fputs("key binding verification coverage failed: \(message)\n", stderr)
        exit(1)
    }
}
