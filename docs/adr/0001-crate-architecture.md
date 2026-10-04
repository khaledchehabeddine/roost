# Crate Architecture

Roost is written in Rust and reaches mobile apps through UniFFI, and only its Client and Server crates are meant to be used directly. Underneath them, Core handles Message processing and protocol state, Crypto handles the cryptography, and Protocol holds what apps and the Backend share, such as certificates and Evidence Bundles. Protocol depends on no other crate, so Server can verify Evidence Bundles without device state, and Client and Server share one copy of each validation rule.

## Alternatives

- Let Server depend on Core: Server only verifies, so it needs no device state, storage, or Sessions.
- Merge Core and Crypto: separate crates keep storage code out of the cryptography, and the compiler enforces that split.
