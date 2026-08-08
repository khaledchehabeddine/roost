//! Cryptographic primitives for private end-to-end encrypted messaging.
//!
//! This crate provides key generation, signing, X3DH handshakes, and Double Ratchet message
//! encryption for Rust crates that need protocol-level crypto. Higher layers handle persistence,
//! replay tracking, and transport framing.
//!
//! # Overview
//!
//! The identity key signs the discovery-key bundle. The discovery key signs the signed-pre-key
//! bundle. Initiators verify both responder signatures, use [`initiate`] and [`accept`] to create
//! the first [`RatchetState`], then use the ratchet to encrypt messages. X3DH includes a one-time
//! pre-key when one is available. Sender identity material is revealed only after the sealed first
//! message decrypts successfully.
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
//! # Secret handling
//!
//! Secret-owning public types do not implement `Debug`.
//!
//! ```compile_fail
//! use aether_crypto::KeyPair;
//!
//! fn assert_debug<T: std::fmt::Debug>() {}
//!
//! assert_debug::<KeyPair>();
//! ```
//!
//! Secret-owning public key types do not implement caller-visible `Clone`.
//!
//! ```compile_fail
//! use aether_crypto::SigningKeyPair;
//!
//! fn assert_clone<T: Clone>() {}
//!
//! assert_clone::<SigningKeyPair>();
//! ```
//!
//! Ratchet state does not implement caller-visible `Clone`.
//!
//! ```compile_fail
//! use aether_crypto::RatchetState;
//!
//! fn assert_clone<T: Clone>() {}
//!
//! assert_clone::<RatchetState>();
//! ```
//!
//! Decrypted initial-message results do not implement caller-visible `Clone`.
//!
//! ```compile_fail
//! use aether_crypto::AcceptedInitialMessage;
//!
//! fn assert_clone<T: Clone>() {}
//!
//! assert_clone::<AcceptedInitialMessage>();
//! ```
//!
//! # Limitations
//!
//! - Handshake envelopes carry no replay marker. Replay detection belongs above this crate.
//! - Re-handshake policy belongs above this crate. A new handshake starts a new session.
//! - This crate has no signed-pre-key storage. Delayed handshake envelopes require the caller to
//!   retain and pass the matching key to [`accept`].

mod delivery_capability;
mod discovery_key;
mod double_ratchet;
mod error;
mod handshake;
mod keys;
mod one_time_prekey;
mod ratchet;
mod sealed_frame;
mod signed_prekey;

pub use delivery_capability::{
    RecipientDeliveryCapability, RecipientDeliveryVerifier, generate_recipient_delivery_capability,
};
pub use discovery_key::{
    DiscoveryKey, DiscoveryKeyBundle, generate_discovery_key,
    generate_signed_prekey_for_discovery_key, verify_discovery_key_bundle,
    verify_discovery_to_identity_binding,
};
pub use double_ratchet::{Header, RatchetState};
pub use error::CryptoError;
pub use handshake::{
    AcceptedInitialMessage, HandshakeEnvelope, InitialPlaintext,
    PREKEY_BUNDLE_ADDITIVE_PUBLIC_KEY_HEADROOM, PREKEY_BUNDLE_VERSION, PreKeyBundle,
    SenderIdentityMaterial, X3DH_ADDITIVE_SHARED_SECRET_HEADROOM, accept, initial_associated_data,
    initiate,
};
pub use keys::{
    IdentityKeyBundle, KeyPair, PublicKey, SharedSecret, Signature, SigningKeyPair, VerifyingKey,
    generate_key_pair, generate_signing_key_pair, sign_identity_key_binding,
    verify_identity_key_bundle, verify_with_context,
};
pub use one_time_prekey::{OneTimePreKey, OneTimePreKeyBundle, generate_one_time_prekey};
pub use sealed_frame::{
    SealedFrame, SealedFramePreKeyReference, open_frame, open_frame_for_discovery_key, seal_frame,
};
pub use signed_prekey::{
    SignedPreKey, SignedPreKeyBundle, generate_signed_prekey, verify_signed_prekey_bundle,
};
