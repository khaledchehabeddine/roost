//! Application-layer key management for private messaging clients.
//!
//! This crate wraps [`roost_crypto`] primitives with persistence, identity lifecycle management,
//! and signed-pre-key rotation for Rust callers wiring the core into apps. Platform adapters
//! provide a [`SecureStorage`] implementation backed by secure storage.
//!
//! # Overview
//!
//! [`KeyStore`] is the entry point for identity setup, encrypted backup import and export, and
//! signed-pre-key publication. It serializes access to the underlying storage so callers can share
//! a cloned handle across application components.
//!
//! # Examples
//!
//! ```
//! use roost_core::{InMemorySecureStorage, KeyStore};
//!
//! # fn publish_identity_bundle(
//! #     _identity: &roost_core::Identity,
//! #     _discovery_key: &roost_crypto::DiscoveryKeyBundle,
//! #     _signed_prekey: &roost_crypto::SignedPreKeyBundle,
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! #     Ok(())
//! # }
//! let store = KeyStore::new(Box::new(InMemorySecureStorage::new()));
//! let identity = store.prepare_generate_identity()?;
//! store.commit_operation(identity.operation.identifier)?;
//! // Commit any host-owned output atomically here, then finalize SecureStorage.
//! store.finalize_operation(identity.operation.identifier)?;
//! // Publish the identity with a matching discovery-key + signed-pre-key pair.
//! let signed_prekey = store.prepare_rotate_signed_prekey_now()?;
//! store.commit_operation(signed_prekey.operation.identifier)?;
//! store.finalize_operation(signed_prekey.operation.identifier)?;
//! let publication = store.current_publication_bundle()?;
//! publish_identity_bundle(
//!     &identity.output,
//!     &publication.discovery_key,
//!     &publication.signed_prekey,
//! )?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Secret handling
//!
//! Identity does not implement `Debug`.
//!
//! ```compile_fail
//! use roost_core::Identity;
//!
//! fn assert_debug<T: std::fmt::Debug>() {}
//!
//! assert_debug::<Identity>();
//! ```
//!
//! Protocol-state blobs do not implement `Debug`.
//!
//! ```compile_fail
//! use roost_core::ProtocolStateBlob;
//!
//! fn assert_debug<T: std::fmt::Debug>() {}
//!
//! assert_debug::<ProtocolStateBlob>();
//! ```
//!
//! Secret-owning public result types do not implement caller-visible `Clone`.
//!
//! ```compile_fail
//! use roost_core::InboundMessageResult;
//!
//! fn assert_clone<T: Clone>() {}
//!
//! assert_clone::<InboundMessageResult>();
//! ```

mod clock;
mod contact;
#[cfg(feature = "development-certificates")]
mod development_certificate;
mod discovery_key;
mod events;
mod hardening;
mod identity;
mod key_store;
mod message;
mod one_time_prekey;
mod prekey_state;
mod protocol_state;
mod safety_number;
mod signed_prekey;
mod storage;
mod transport_binding;

use roost_protocol::{MessageId, PayloadKind};

pub use contact::{
    ContactDiscoveryKey, ContactEvent, ContactEventStream, ContactIdentity, ContactIdentityKey,
    ContactSafetyNumberConfirmation, ContactState, ContactStateChange, ContactTrustState,
    PeerInboxAuthorization,
};
#[cfg(feature = "development-certificates")]
pub use development_certificate::{
    DevelopmentCertificateAuthority, DevelopmentCertificateError, DevelopmentSenderCertificate,
};
pub use discovery_key::DiscoveryKeyError;
pub use events::{
    DEFAULT_OBSERVER_CAPACITY, EventEnvelope, EventId, EventObserver, EventStream,
    EventStreamError, EventStreamItem, EventStreamSnapshot, MAX_OBSERVER_CAPACITY,
};
pub use hardening::{
    DEFAULT_DEDUPLICATION_CAPACITY, MAX_DEDUPLICATION_CAPACITY, MIN_DEDUPLICATION_CAPACITY,
    ProtocolHardeningLimits,
};
pub use identity::{Identity, IdentityError};
pub use key_store::{
    AcknowledgmentProcessing, ContactBlock, InboxRotation, KeyStore, KeyStoreError,
    KeyStoreOperation, KeyStoreOperationError, KeyStoreOperationIdentifier,
    KeyStoreOperationStatus, MessageDecryption, MessageEncryption, MessageOperationError,
    PreparedKeyStoreOperation, PublicationBundle, SecureStorageExpectedValue,
    SecureStoragePrecondition, SessionAcceptance, SessionAcceptanceResult,
    SessionEstablishmentError, SessionInitiation, SessionInitiationResult,
    UnfinishedKeyStoreOperation,
};
pub use message::{Message, MessageError};
pub use one_time_prekey::OneTimePreKeyError;
pub use protocol_state::{
    AcknowledgmentOutcome, BlockedContactAcknowledgmentPolicy, BlockedInboundMessageResult,
    ClearedAcknowledgment, InboundAcknowledgmentMessage, InboundEncryptedMessage,
    InboundMessageOutcome, InboundMessageResult, InboundSenderCertificateValidation,
    OutboundAcknowledgment, OutboundMessageResult, OutboundPlaintext, PendingAcknowledgment,
    ProtocolStateAddress, ProtocolStateBlob, ProtocolStateEngine, ProtocolStateError,
    ProtocolStateKey, ProtocolStateKind, ProtocolStateSnapshot, ProtocolStateUpdate,
    RetryInstruction, RetryInstructionResult, SessionEvent, SessionId, SessionUnrecoverableReason,
    SessionUnrecoverableResult,
};
pub use roost_crypto::{
    CryptoError, DiscoveryKeyBundle, IdentityKeyBundle, OneTimePreKeyBundle, PreKeyBundle,
    PublicKey, RecipientDeliveryCapability, SealedFramePreKeyReference, SenderIdentityMaterial,
    Signature, SignedPreKeyBundle, verify_discovery_to_identity_binding,
    verify_identity_key_bundle,
};
pub use safety_number::{IdentityKey, SafetyNumber, SafetyNumberError, derive_safety_number};
pub use signed_prekey::SignedPreKeyError;
pub use storage::{InMemorySecureStorage, SecureStorage, StorageError};
pub use transport_binding::{PreKeySelection, TransportBinding, TransportBindingError};

#[cfg(fuzzing)]
#[doc(hidden)]
pub mod fuzzing {
    pub use crate::discovery_key::fuzz_decode_discovery_key_blob;
    pub use crate::one_time_prekey::fuzz_decode_one_time_prekey_pool;
    pub use crate::protocol_state::{
        fuzz_decode_protocol_state_blob, fuzz_decode_sealed_sender_envelope,
        fuzz_deduplication_digest, fuzz_unpad_sealed_payload,
    };
    pub use crate::signed_prekey::fuzz_decode_signed_prekey_blob;
}

/// Deterministic inputs used by the generated-binding checks.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod test_support {
    pub use roost_crypto::{
        DiscoveryKey, DiscoveryKeyBundle, HandshakeEnvelope, IdentityKeyBundle, InitialPlaintext,
        KeyPair, OneTimePreKey, PREKEY_BUNDLE_VERSION, PreKeyBundle, PublicKey, RatchetState,
        RecipientDeliveryCapability, SealedFramePreKeyReference, Signature, SignedPreKey,
        SignedPreKeyBundle, SigningKeyPair, VerifyingKey, accept, generate_discovery_key,
        generate_key_pair, generate_one_time_prekey, generate_signed_prekey_for_discovery_key,
        generate_signing_key_pair, initiate, sign_identity_key_binding,
        verify_discovery_key_bundle, verify_discovery_to_identity_binding,
        verify_identity_key_bundle, verify_signed_prekey_bundle,
    };
}
