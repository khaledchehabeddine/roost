// Swift proof-of-concept: generate a Hermes identity and print the public key as hex.
//
// Build and run (from the repo root, after running scripts/build-xcframework.sh):
//
//   swiftc \
//     examples/swift-poc/main.swift \
//     target/xcframework/swift/hermes.swift \
//     -import-objc-header target/xcframework/swift/hermesFFI.h \
//     -L target/aarch64-apple-ios-sim/release \
//     -lhermes_uniffi \
//     -o /tmp/hermes-swift-poc && /tmp/hermes-swift-poc

let storage = InMemorySecureStorage()
let manager = IdentityManager(storage: storage)

do {
    let identity = try manager.generateIdentity()
    let hex = identity.publicKey.map { String(format: "%02x", $0) }.joined()
    print("Public key: \(hex)")
} catch {
    print("Error: \(error)")
    exit(1)
}
