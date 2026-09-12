# Roost crate architecture

**Status:** Accepted

Rust owns the shared messaging implementation and UniFFI exposes the mobile contract. The v0.16.0
cutover establishes two consumer entry crates and three implementation crates. The direct graph is
Client to Core and Protocol, Server to Protocol, Core to Crypto and Protocol, and Crypto to Protocol.
Protocol depends on no other Roost crate. Cargo enforces this acyclic graph without a custom checker.

Protocol owns the encodings, certificates, canonical key validation, signature framing, Message
transcript and padding pieces, and Evidence Bundle codec and verifier shared by mobile and backend
consumers. Core retains Message processing, identity and contact lifecycle, protocol-state
transitions, and SecureStorage recovery. Crypto retains local keys, X3DH, Double Ratchet, and
encryption. The whole Message module does not move merely because evidence shares some fields.

## Considered options

- Let Server depend on Core. Rejected because a stateless verifier needs neither device state nor
  storage, ratchets, or session management.
- Duplicate verification in the two consumer crates. Rejected because certificate, transcript, and
  key-validation rules would have two owners.
- Merge Core and Crypto. Rejected because their existing dependency direction separates storage
  coordination from cryptographic operations and already has compiler enforcement.

## Consequences

- Only Client and Server are supported consumer entry crates. The implementation crates are neither
  independent SDK commitments nor separate release products or crates.io publications.
- All crates share the workspace version and source revision. The approved coordinated pre-MVP
  break uses v0.16.0, with no aliases, forwarding crates, or migration layer. v0.15.0 remains immutable.
- Server exposes only the stateless verifier and its required public types. Certificate trust and
  the acceptance timestamp come from the backend; report deduplication remains backend policy.
- Existing cryptographic context bytes and current-format vectors are unchanged by this Rust
  package and ownership refactor. Their fixed domain separators remain protocol inputs.

The approved boundary is recorded in [the architecture resolution](https://github.com/RelayNet/roost/issues/259#issuecomment-5558392822)
and implemented by [ticket 266](https://github.com/RelayNet/roost/issues/266).
