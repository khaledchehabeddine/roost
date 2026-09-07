# Secure Storage Platform Abstraction

**Status:** Accepted

Platform secret storage (iOS Keychain, Android Keystore) is exposed through a Rust trait owned by the identity-layer crate and consumed by identity-layer code as a trait object, with the host app providing the platform implementation at compile time. The trait lives in the identity layer rather than at the FFI boundary because identity-key persistence is an identity-layer concern, and defining the contract where the concern lives keeps the FFI boundary clean and stable. The trait-object pattern lets multiple identity-layer consumers share a single storage instance without their internal types leaking into the FFI signature, so the FFI surface stays stable as those consumers evolve, and a self-contained in-memory implementation ships in the same crate so the test suite exercises the storage contract without any OS dependency.
