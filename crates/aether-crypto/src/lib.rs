//! Cryptographic primitives for private peer-to-peer messaging.
//!
//! This crate provides the key, signature, handshake, and Double Ratchet building blocks used by
//! integrating crates. Integrating crates handles identity persistence, replay tracking, and
//! transport framing.
//!
//! # Overview
//!
//! Callers publish an Ed25519-signed X25519 pre-key bundle, use the X3DH-lite handshake to agree
//! on an initial ratchet root key, then exchange encrypted messages through [`RatchetState`].
//! Public APIs return domain-specific [`CryptoError`] values for cryptographic failures and
//! protocol-limit violations.
//!
//! # Examples
//!
//! ```
//! use aether_crypto::{generate_signed_prekey, generate_signing_key_pair, verify_bundle};
//!
//! let signing = generate_signing_key_pair();
//! let signed_prekey = generate_signed_prekey(&signing, 1_700_000_000);
//! let bundle = signed_prekey.bundle();
//!
//! verify_bundle(&bundle, &signing.verifying)?;
//! # Ok::<(), aether_crypto::CryptoError>(())
//! ```
//!
//! # Key Concepts
//!
//! X3DH-lite bootstraps a Double Ratchet session before peers exchange ratcheted messages. Unlike
//! Signal's X3DH, this variant has no one-time pre-key. It uses three Diffie-Hellman outputs
//! instead of four, which keeps pre-key storage simpler but gives the first message slightly less
//! forward secrecy.
//!
//! The three Diffie-Hellman outputs provide contributory binding: each party's long-term and
//! ephemeral material participates in the derived root key. See [`initiate`] and [`accept`] for
//! the per-side handshake flows.
//!
//! # Known Constraints
//!
//! - Handshake envelopes carry no replay marker. Replay detection belongs above this crate.
//! - Re-handshake policy is undefined. Rotating the handshake root key requires starting a new
//!   session.
//! - Signed pre-key archival is not implemented. An envelope that references a just-rotated
//!   signed pre-key fails with [`CryptoError::HandshakeSignedPreKeyMismatch`].

mod double_ratchet;
mod error;
mod handshake;
mod keys;
mod ratchet;
mod signed_prekey;

pub use double_ratchet::{Header, RatchetState};
pub use error::CryptoError;
pub use handshake::{HandshakeEnvelope, accept, initial_associated_data, initiate};
pub use keys::{
    KeyPair, PublicKey, SharedSecret, Signature, SigningKeyPair, VerifyingKey, generate_key_pair,
    generate_signing_key_pair,
};
pub use signed_prekey::{SignedPreKey, SignedPreKeyBundle, generate_signed_prekey, verify_bundle};
