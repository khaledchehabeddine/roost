//! Cryptographic primitives for Hermes.
//!
//! Provides [`KeyPair`] (X25519 Diffie-Hellman) and [`SigningKeyPair`] (Ed25519
//! digital signatures). Secret keys are private fields to ensure zeroize-on-drop
//! fires at the correct memory location. Callers serialize via `to_secret_bytes()` /
//! `to_signing_bytes()` (returning `Zeroizing<[u8; 32]>`) and deserialize via
//! `from_secret_bytes()` / `from_signing_bytes()`.

pub mod keys;

pub use keys::{
    KeyPair, PublicKey, SharedSecret, Signature, SigningKeyPair, VerifyingKey, generate_key_pair,
    generate_signing_key_pair,
};
