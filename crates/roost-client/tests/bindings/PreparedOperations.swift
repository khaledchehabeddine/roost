import Foundation

private struct LostStorageReply: Error { }

private final class MemorySecureStorage: SecureStorage, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: Data] = [:]
    var loseNextStoreReply = false

    func store(key: String, value: Data) throws {
        lock.lock()
        defer { lock.unlock() }
        values[key] = value
        if loseNextStoreReply {
            loseNextStoreReply = false
            throw LostStorageReply()
        }
    }

    func load(key: String) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return values[key]
    }

    func delete(key: String) throws {
        lock.lock()
        defer { lock.unlock() }
        values.removeValue(forKey: key)
    }
}

@main
struct PreparedOperations {
    static func main() throws {
        let storage = MemorySecureStorage()
        let orphan = try Client(storage: storage).identity().prepareGenerateIdentity()
        let client = Client(storage: storage)
        let unfinished = try client.unfinishedOperations()
        precondition(unfinished.count == 1)
        precondition(unfinished[0].operation.identifier == orphan.operation.identifier)
        let provisional = try client.identity().hasIdentity()
        precondition(!provisional)
        _ = try client.abortOperation(identifier: orphan.operation.identifier)
        _ = try client.abortOperation(identifier: orphan.operation.identifier)

        let winner = try client.identity().prepareGenerateIdentity()
        let stale = try client.identity().prepareGenerateIdentity()
        precondition(!winner.operation.secureStoragePreconditions.isEmpty)
        // The foreign store persists the reservation, then loses its reply.
        storage.loseNextStoreReply = true
        do {
            _ = try client.commitOperation(identifier: winner.operation.identifier)
            fatalError("expected lost storage reply")
        } catch ClientError.Storage { }

        let recovered = Client(storage: storage)
        let reserved = try recovered.unfinishedOperations()
        precondition(reserved.contains { $0.operation.identifier == winner.operation.identifier })
        do {
            _ = try recovered.identity().hasIdentity()
            fatalError("reserved operation did not gate ordinary work")
        } catch let ClientError.OperationRecoveryRequired(identifier, _) {
            precondition(identifier == winner.operation.identifier)
        }
        // The host has confirmed its durable transaction committed before finalizing.
        _ = try recovered.commitOperation(identifier: winner.operation.identifier)
        storage.loseNextStoreReply = true
        do {
            _ = try recovered.finalizeOperation(identifier: winner.operation.identifier)
            fatalError("expected lost finalization reply")
        } catch ClientError.Storage { }
        let restarted = Client(storage: storage)
        _ = try restarted.finalizeOperation(identifier: winner.operation.identifier)
        _ = try restarted.finalizeOperation(identifier: winner.operation.identifier)
        let identity = try restarted.identity().loadIdentity()
        precondition(identity.ed25519VerifyingKey == winner.identity.ed25519VerifyingKey)
        do {
            _ = try restarted.commitOperation(identifier: stale.operation.identifier)
            fatalError("stale SecureStorage precondition committed")
        } catch ClientError.SecureStoragePreconditionChanged { }
        _ = try restarted.abortOperation(identifier: stale.operation.identifier)
        let remaining = try restarted.unfinishedOperations()
        precondition(remaining.isEmpty)
        print("Swift prepared-operation recovery passed")
    }
}
