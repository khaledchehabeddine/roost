//! Cryptographic primitives for private end-to-end encrypted messaging.
//!
//! This crate provides the key, signature, handshake, and Double Ratchet building blocks used by
//! integrating crates. Integrating crates handles identity persistence, replay tracking, and
//! transport framing.
//!
//! # Overview
//!
//! Callers publish their identity key, a discovery-key bundle the identity key signs, and a signed
//! pre-key bundle the discovery key signs. Peers use the X3DH-lite handshake to agree on an initial
//! ratchet root key, then exchange encrypted messages through [`RatchetState`]. Public APIs return
//! domain-specific [`CryptoError`] values for cryptographic failures and protocol-limit violations.
//!
//! # Examples
//!
//! ```
//! use aether_crypto::{
//!     generate_discovery_key, generate_signed_prekey_for_discovery_key,
//!     generate_signing_key_pair, verify_bundle, verify_discovery_key_bundle,
//! };
//! use rand::rngs::OsRng;
//!
//! let mut rng = OsRng;
//! // The permanent identity key signs a rotatable discovery key (epoch 0).
//! let identity = generate_signing_key_pair(&mut rng);
//! let discovery_key = generate_discovery_key(&mut rng, &identity, 0, 1_700_000_000);
//! let discovery_bundle = discovery_key.bundle();
//! verify_discovery_key_bundle(&discovery_bundle, &identity.verifying)?;
//!
//! // The discovery key signs the published signed pre-key.
//! let signed_prekey =
//!     generate_signed_prekey_for_discovery_key(&mut rng, &discovery_key, 1_700_000_000);
//! verify_bundle(&signed_prekey.bundle(), &discovery_bundle.verifying_key)?;
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
pub use signed_prekey::{SignedPreKey, SignedPreKeyBundle, generate_signed_prekey, verify_bundle};
