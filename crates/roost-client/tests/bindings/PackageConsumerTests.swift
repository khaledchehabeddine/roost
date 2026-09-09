import Roost
import XCTest

final class PackageConsumerTests: XCTestCase {
    func testPackageLoadsNativeLibraryAndCallsBindings() throws {
        let client = Client(storage: InMemorySecureStorage())
        XCTAssertFalse(try client.identity().hasIdentity())
        let prepared = try client.identity().prepareGenerateIdentity()
        _ = try client.commitOperation(identifier: prepared.operation.identifier)
        _ = try client.finalizeOperation(identifier: prepared.operation.identifier)
        XCTAssertEqual(
            try client.identity().loadIdentity().ed25519VerifyingKey,
            prepared.identity.ed25519VerifyingKey
        )
    }
}
