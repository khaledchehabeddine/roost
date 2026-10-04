# Crate Architecture

Roost is written in Rust and reaches mobile apps through UniFFI, and only its Client crate is meant to be used directly. Underneath it, Core handles Message processing and protocol state, Crypto handles the cryptography, and Protocol holds the encodings and validation rules the others share, such as certificates and Message transcripts. Protocol depends on no other crate, so Crypto can use it and each rule has one copy.

## Alternatives

- Merge Core and Crypto: separate crates keep storage code out of the cryptography, and the compiler enforces that split.
