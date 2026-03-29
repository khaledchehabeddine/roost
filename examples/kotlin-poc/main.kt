// Kotlin proof-of-concept: generate a Hermes identity and print the public key as hex.
//
// Build and run (from the repo root, after running scripts/build-android.sh):
//
//   kotlinc \
//     examples/kotlin-poc/main.kt \
//     target/android/kotlin/uniffi/hermes/hermes.kt \
//     -include-runtime \
//     -classpath jna.jar \
//     -d /tmp/hermes-kotlin-poc.jar
//
//   java -cp /tmp/hermes-kotlin-poc.jar:jna.jar \
//     -Djna.library.path=target/aarch64-linux-android/release \
//     MainKt

import uniffi.hermes.InMemorySecureStorage
import uniffi.hermes.IdentityManager

fun main() {
    val storage = InMemorySecureStorage()
    val manager = IdentityManager(storage)
    try {
        val identity = manager.generateIdentity()
        val hex = identity.publicKey.joinToString("") { "%02x".format(it) }
        println("Public key: $hex")
    } catch (e: Exception) {
        println("Error: $e")
        System.exit(1)
    }
}
