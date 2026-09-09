package io.github.relaynet.roost

import android.test.InstrumentationTestCase

class AndroidAarConsumerTest : InstrumentationTestCase() {
    fun testPackageLoadsNativeLibraryAndCallsBindings() {
        val client = Client(InMemorySecureStorage())
        assertFalse(client.identity().hasIdentity())
        val prepared = client.identity().prepareGenerateIdentity()
        client.commitOperation(prepared.operation.identifier)
        client.finalizeOperation(prepared.operation.identifier)
        assertTrue(client.identity().loadIdentity().ed25519VerifyingKey
            .contentEquals(prepared.identity.ed25519VerifyingKey))
    }
}
