//! Cryptographic primitives for private end-to-end encrypted messaging.
//!
//! This crate provides key generation, signing, X3DH-lite handshakes, and Double Ratchet message
//! encryption for Rust crates that need protocol-level crypto. Higher layers handle persistence,
//! replay tracking, and transport framing.
//!
//! # Overview
//!
//! The identity key signs the discovery-key bundle. The discovery key signs the signed-pre-key
//! bundle. Peers verify both signatures, use [`initiate`] and [`accept`] to create the first
//! [`RatchetState`], then use the ratchet to encrypt messages. X3DH-lite uses three
//! Diffie-Hellman outputs and no one-time pre-key.
//!
//! # Examples
//!
//! ```
//! use aether_crypto::{
//!     generate_discovery_key, generate_signed_prekey_for_discovery_key,
//!     generate_signing_key_pair, verify_signed_prekey_bundle, verify_discovery_key_bundle,
//! };
//! use rand::rngs::OsRng;
//!
//! let mut rng = OsRng;
//! let identity = generate_signing_key_pair(&mut rng);
//! let discovery_key = generate_discovery_key(&mut rng, &identity, 0, 1_700_000_000);
//! let discovery_bundle = discovery_key.bundle();
//! verify_discovery_key_bundle(&discovery_bundle, &identity.verifying)?;
//!
//! let signed_prekey =
//!     generate_signed_prekey_for_discovery_key(&mut rng, &discovery_key, 1_700_000_000);
//! verify_signed_prekey_bundle(&signed_prekey.bundle(), &discovery_bundle.verifying_key)?;
//! # Ok::<(), aether_crypto::CryptoError>(())
//! ```
//!
//! # Limitations
//!
//! - Handshake envelopes carry no replay marker. Replay detection belongs above this crate.
//! - Re-handshake policy belongs above this crate. A new handshake starts a new session.
//! - This crate has no signed-pre-key storage. Delayed handshake envelopes require the caller to
//!   retain and pass the matching key to [`accept`].

mod discovery_key;
mod double_ratchet;
mod error;
mod handshake;
mod keys;
mod ratchet;
mod signed_prekey;

pub use discovery_key::{
    DiscoveryKey, DiscoveryKeyBundle, generate_discovery_key,
    generate_signed_prekey_for_discovery_key, verify_discovery_key_bundle,
};
pub use double_ratchet::{Header, RatchetState};
pub use error::CryptoError;
pub use handshake::{HandshakeEnvelope, accept, initial_associated_data, initiate};
pub use keys::{
    KeyPair, PublicKey, SharedSecret, Signature, SigningKeyPair, VerifyingKey, generate_key_pair,
    generate_signing_key_pair,
};
pub use signed_prekey::{
    SignedPreKey, SignedPreKeyBundle, generate_signed_prekey, verify_signed_prekey_bundle,
};
