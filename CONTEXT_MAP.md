# Context map

## Contexts

- [Client](crates/roost-client/CONTEXT.md), mobile bindings and platform integration
- [Server](crates/roost-server/CONTEXT.md), backend evidence verification
- [Core](crates/roost-core/CONTEXT.md), identity lifecycle, messaging, contacts, state transitions, and storage recovery
- [Crypto](crates/roost-crypto/CONTEXT.md), keys, X3DH, Double Ratchet, and encryption
- [Protocol](crates/roost-protocol/CONTEXT.md), shared encodings and authenticity evidence

## Relationships

- Client consumes Core operations and Protocol's stateless verification through one mobile binding contract.
- Server exposes Protocol's stateless evidence verdict to backends.
- Core coordinates Crypto operations and Protocol encodings with caller-owned storage.
- Crypto uses Protocol's canonical key validation and signature framing.
- Protocol depends on no other Roost context and owns no device, session, or storage lifecycle.
