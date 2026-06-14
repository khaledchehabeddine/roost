import Foundation

private let injectedReason = "injected foreign storage failure"

private struct InjectedStorageFailure: Error, CustomStringConvertible {
    var description: String { injectedReason }
}

private final class ThrowingSecureStorage: SecureStorage, @unchecked Sendable {
    private let lock = NSLock()
    private var throwOnNextLoad = true

    func store(key: String, value: Data) throws {}

    func load(key: String) throws -> Data? {
        lock.lock()
        let shouldThrow = throwOnNextLoad
        throwOnNextLoad = false
        lock.unlock()

        if shouldThrow {
            throw InjectedStorageFailure()
        }
        return nil
    }

    func delete(key: String) throws {}
}

@main
struct SecureStorageUnexpectedError {
    static func main() throws {
        let store = KeyStore(storage: ThrowingSecureStorage())

        do {
            _ = try store.hasIdentity()
            fail("expected unexpected foreign storage exception")
        } catch let error as AetherError {
            guard case let .Storage(reason) = error else {
                fail("expected Storage, got \(error)")
            }
            require(reason.contains("unexpected foreign callback failure"), "storage error reason")
        }

        let hasIdentity = try store.hasIdentity()
        require(!hasIdentity, "storage mutex remains usable")
        print("Swift SecureStorage unexpected-error regression passed")
    }

    private static func require(_ condition: @autoclosure () -> Bool, _ message: String) {
        if !condition() {
            fail(message)
        }
    }

    private static func fail(_ message: String) -> Never {
        fputs("secure storage unexpected-error regression failed: \(message)\n", stderr)
        exit(1)
    }
}
