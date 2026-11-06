# Crate Architecture

Roost is written in Rust and reaches mobile apps through UniFFI, and only its Client crate is meant to be used directly. Underneath it, Core handles message processing and protocol state, Crypto handles keys, signatures, X3DH, and the Double Ratchet, and Protocol holds the encodings and validation rules the others share, such as certificates and message transcripts. Protocol depends on no other Roost crate, so Crypto can use it and each rule has one copy.

## Alternatives

- Merge Core and Crypto: separate crates keep storage code out of the cryptography, and the compiler enforces that split.
