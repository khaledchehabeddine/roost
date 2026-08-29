import Foundation

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
struct Issue219PreparedOperations {
    static func main() throws {
        let storage = MemorySecureStorage()
        var store: KeyStore? = KeyStore(storage: storage)

        let orphan = try store!.prepareGenerateIdentity()
        require(orphan.operation.identifier.count == 16, "operation identifier must be 16 bytes")
        require(
            !orphan.operation.secureStoragePreconditions.isEmpty,
            "preparation must expose SecureStorage preconditions"
        )
        try require(!store!.hasIdentity(), "prepared identity must remain provisional")

        store = nil
        let recovered = KeyStore(storage: storage)
        let unfinished = try recovered.unfinishedOperations()
        require(
            unfinished.count == 1
                && unfinished[0].operation.identifier == orphan.operation.identifier,
            "a new KeyStore instance must discover the orphaned stage"
        )
        _ = try recovered.abortOperation(identifier: orphan.operation.identifier)
        _ = try recovered.abortOperation(identifier: orphan.operation.identifier)
        try require(recovered.unfinishedOperations().isEmpty, "abort must clear recovery work")

        let winner = try recovered.prepareGenerateIdentity()
        let stale = try recovered.prepareGenerateIdentity()
        _ = try recovered.commitOperation(identifier: winner.operation.identifier)
        _ = try recovered.commitOperation(identifier: winner.operation.identifier)
        expectRecoveryRequired(recovered, identifier: winner.operation.identifier)
        _ = try recovered.finalizeOperation(identifier: winner.operation.identifier)
        _ = try recovered.finalizeOperation(identifier: winner.operation.identifier)
        try require(recovered.hasIdentity(), "finalization must make the identity authoritative")

        expectPreconditionChanged(recovered, identifier: stale.operation.identifier)
        _ = try recovered.abortOperation(identifier: stale.operation.identifier)

        let signedPreKey = try recovered.prepareRotateSignedPrekeyNow()
        _ = try recovered.commitOperation(identifier: signedPreKey.operation.identifier)
        _ = try recovered.finalizeOperation(identifier: signedPreKey.operation.identifier)
        let noOp = try recovered.prepareRotateSignedPrekeyIfStale()
        require(noOp.signedPrekey == nil, "fresh signed pre-key rotation must report no change")
        let noOpUnfinished = try recovered.unfinishedOperations()
        require(
            noOpUnfinished.contains { $0.operation.identifier == noOp.operation.identifier },
            "a no-op result must still own an unfinished operation"
        )
        _ = try recovered.commitOperation(identifier: noOp.operation.identifier)
        _ = try recovered.finalizeOperation(identifier: noOp.operation.identifier)

        var cappedIdentifiers: [Data] = []
        for _ in 0..<16 {
            let prepared = try recovered.prepareRotateSignedPrekeyIfStale()
            cappedIdentifiers.append(prepared.operation.identifier)
        }
        expectUnfinishedOperationLimit(recovered)
        for identifier in cappedIdentifiers {
            _ = try recovered.abortOperation(identifier: identifier)
        }

        print("Swift issue 219 prepared-operation coverage passed")
    }

    private static func expectRecoveryRequired(_ store: KeyStore, identifier: Data) {
        do {
            _ = try store.hasIdentity()
            fail("ordinary KeyStore work must stop until committed recovery finishes")
        } catch let error as AetherError {
            guard case let .OperationRecoveryRequired(operationIdentifier, _) = error else {
                fail("unexpected recovery error \(error)")
            }
            require(operationIdentifier == identifier, "recovery error must name the operation")
        } catch {
            fail("unexpected recovery error \(error)")
        }
    }

    private static func expectPreconditionChanged(_ store: KeyStore, identifier: Data) {
        do {
            _ = try store.commitOperation(identifier: identifier)
            fail("a stale prepared operation must not commit")
        } catch let error as AetherError {
            guard case .SecureStoragePreconditionChanged(_) = error else {
                fail("unexpected stale-precondition error \(error)")
            }
        } catch {
            fail("unexpected stale-precondition error \(error)")
        }
    }

    private static func expectUnfinishedOperationLimit(_ store: KeyStore) {
        do {
            _ = try store.prepareRotateSignedPrekeyIfStale()
            fail("the bounded unfinished-operation journal must reject a seventeenth operation")
        } catch let error as AetherError {
            guard case .TooManyUnfinishedOperations = error else {
                fail("unexpected unfinished-operation limit error \(error)")
            }
        } catch {
            fail("unexpected unfinished-operation limit error \(error)")
        }
    }

    private static func require(_ condition: @autoclosure () throws -> Bool, _ message: String) rethrows {
        if try !condition() {
            fail(message)
        }
    }

    private static func fail(_ message: String) -> Never {
        fputs("issue 219 prepared-operation coverage failed: \(message)\n", stderr)
        exit(1)
    }
}
