//! Cryptographic primitives for private end-to-end encrypted messaging.
//!
//! Handles key generation, identity key and discovery key binding signatures, signed and one-time
//! prekeys, delivery capabilities, X3DH handshakes and sender proofs, Double Ratchet encryption,
//! and sealed sender frames. Higher layers handle persistence, replay tracking, and transport.
//!
//! The identity key signs the public discovery key. The discovery key signs the public signed
//! prekey. Initiators verify both responder signatures, use [`initiate_handshake`] to create the
//! first [`RatchetState`] and the [`SessionId`](roost_protocol::SessionId) both peers derive, then
//! use the ratchet to encrypt messages. Responders run [`accept_handshake`] and check the
//! initiator's [`prove_sender`] proof with [`verify_sender_proof`]. X3DH includes a one-time
//! prekey when one is available.
//!
//! # Secret handling
//!
//! Secret-owning public types do not implement `Debug`.
//!
//! ```compile_fail
//! use roost_crypto::KeyPair;
//!
//! fn assert_debug<T: std::fmt::Debug>() {}
//!
//! assert_debug::<KeyPair>();
//! ```
//!
//! Secret-owning public key types do not implement caller-visible `Clone`.
//!
//! ```compile_fail
//! use roost_crypto::SigningKeyPair;
//!
//! fn assert_clone<T: Clone>() {}
//!
//! assert_clone::<SigningKeyPair>();
//! ```
//!
//! Ratchet state does not implement caller-visible `Clone`.
//!
//! ```compile_fail
//! use roost_crypto::RatchetState;
//!
//! fn assert_clone<T: Clone>() {}
//!
//! assert_clone::<RatchetState>();
//! ```
//!
//! # Limitations
//!
//! - Handshakes carry no replay marker. Replay detection belongs above this crate.
//! - Re-handshake policy belongs above this crate. A new handshake starts a new session.
//! - This crate has no signed prekey storage. Delayed handshakes require the caller to retain and
//!   pass the matching key to [`accept_handshake`].

mod delivery_capability;
mod discovery_key;
mod double_ratchet;
mod handshake;
mod keys;
mod one_time_prekey;
mod sealed_frame;
mod signed_prekey;

pub use delivery_capability::{
    RecipientDeliveryCapability, RecipientDeliveryVerifier, generate_recipient_delivery_capability,
};
pub use discovery_key::{
    DiscoveryKey, PublicDiscoveryKey, generate_discovery_key,
    generate_signed_prekey_for_discovery_key, verify_discovery_to_identity_binding,
    verify_public_discovery_key,
};
pub use double_ratchet::{Header, RatchetError, RatchetState, RatchetStateError};
pub use handshake::{
    Handshake, HandshakeError, PREKEY_BUNDLE_VERSION, PreKeyBundle, SENDER_PROOF_LEN,
    SenderProofTranscript, accept_handshake, initiate_handshake, prove_sender, verify_sender_proof,
};
pub use keys::{
    KeyPair, PublicIdentityKey, PublicKey, PublicKeyError, Signature, SigningKeyPair, VerifyingKey,
    generate_key_pair, generate_signing_key_pair, sign_identity_key_binding,
    verify_public_identity_key,
};
pub use one_time_prekey::{OneTimePreKey, PublicOneTimePreKey, generate_one_time_prekey};
pub use sealed_frame::{
    OneTimePreKeyReference, SealedFrame, SealedFrameError, SealedFramePreKeyReference,
    open_frame_for_discovery_key_with_associated_data, seal_frame_with_associated_data,
};
pub use signed_prekey::{PublicSignedPreKey, SignedPreKey, verify_public_signed_prekey};
