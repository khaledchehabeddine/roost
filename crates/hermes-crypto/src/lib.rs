//! Cryptographic primitives for Hermes: identity keys, signed prekeys, the X3DH-lite handshake,
//! and the Double Ratchet.
//!
//! # X3DH-lite handshake
//!
//! Bootstraps a Double Ratchet session over an asynchronous channel. Unlike Signal's X3DH, there
//! is no one-time prekey — three DHs rather than four. The tradeoff is a simpler prekey store (no
//! pool to sync or mark consumed) at the cost of slightly reduced forward secrecy for the very
//! first message in a new session.
//!
//! Three DHs are required to achieve *contributory binding*: each party's long-term and ephemeral
//! material participates in at least two of the three shared secrets, so neither side alone can
//! predict SK. See [`handshake`] for the initiator and responder flows.
//!
//! # Known gaps (future work)
//!
//! * Handshake envelopes carry no replay marker. A captured envelope can be re-delivered; the
//!   ratchet will accept it as a fresh conversation. Replay detection belongs at a layer above the
//!   crypto primitive.
//! * Re-handshake policy is undefined. After a session is established, there is no protocol for
//!   either side to rotate the underlying SK without tearing down the ratchet.
//! * Signed prekey archival is not implemented. The responder stores only the current SPK, so an
//!   envelope that references a just-rotated SPK fails with [`CryptoError::HandshakeSpkMismatch`]
//!   rather than falling back to an archived one.

pub mod double_ratchet;
pub mod error;
pub mod handshake;
pub mod keys;
pub mod ratchet;
pub mod signed_prekey;

pub use double_ratchet::{Header, RatchetState};
pub use error::CryptoError;
pub use handshake::{
    HandshakeEnvelope, accept, derive_sk_initiator, derive_sk_responder, initial_ad, initiate,
};
pub use keys::{
    KeyPair, PublicKey, SharedSecret, Signature, SigningKeyPair, VerifyingKey, generate_key_pair,
    generate_signing_key_pair,
};
pub use ratchet::{ChainKey, MessageKey, RootKey, kdf_ck, kdf_rk};
pub use signed_prekey::{PreKeyBundle, SignedPreKey, generate_signed_prekey, verify_bundle};
