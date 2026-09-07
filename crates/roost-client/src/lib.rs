//! UniFFI bindings for the cryptographic core.
//!
//! This crate exposes the storage-backed [`KeyStore`] API and FFI-safe record types used by SDKs.
//! Apps provide a platform [`SecureStorage`] implementation, then use one [`KeyStore`] for the app
//! lifetime to manage the local identity and publication keys.
//!
//! # Feature flags
//!
//! - `development-certificates` exposes an in-memory certificate authority for local peer
//!   simulations. Normal artifacts omit the API.
//! - `fixture-replay` exposes checked-in fixture replay support for tests and tooling.
//!
//! # Examples
//!
//! ```
//! use roost_client::{
//!     ClientError, InMemorySecureStorage, KeyStore, PublicationBundle, SecureStorage,
//! };
//! use std::sync::Arc;
//!
//! # fn publish(_bundle: &PublicationBundle) -> Result<(), ClientError> {
//! #     Ok(())
//! # }
//! let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
//! let store = KeyStore::new(storage);
//!
//! if !store.has_identity()? {
//!     let identity = store.prepare_generate_identity()?;
//!     store.commit_operation(identity.operation.identifier.clone())?;
//!     store.finalize_operation(identity.operation.identifier)?;
//! }
//!
//! let signed_prekey = store.prepare_rotate_signed_prekey_now()?;
//! store.commit_operation(signed_prekey.operation.identifier.clone())?;
//! store.finalize_operation(signed_prekey.operation.identifier)?;
//! let publication = store.current_publication_bundle()?;
//! publish(&publication)?;
//! # Ok::<(), ClientError>(())
//! ```

uniffi::setup_scaffolding!("roost_client");

#[cfg(all(feature = "fixture-replay", not(debug_assertions)))]
compile_error!("fixture-replay is test-only and must not be enabled for release builds");

mod binding;
mod certificate;
#[cfg(feature = "development-certificates")]
mod development_certificate;
mod error;
mod events;
mod evidence;
#[cfg(feature = "fixture-replay")]
mod fixture_replay;
mod key_store;
mod key_store_operation;
mod message;
mod protocol;
mod records;
mod storage;
mod transport_binding;

pub use binding::{verify_discovery_to_identity_binding, verify_identity_key_binding};
pub use certificate::{
    DomainSigningKey, DomainSigningKeyStatus, RevocationState, SenderCertificateValidation,
    ValidatedSenderCertificate, validate_sender_certificate,
};
#[cfg(feature = "development-certificates")]
pub use development_certificate::{DevelopmentCertificateAuthority, DevelopmentSenderCertificate};
pub use error::ClientError;
pub use events::{
    ContactEventEnvelope, ContactEventObserver, ContactEventSnapshot, ContactEventStream,
    ContactEventStreamItem, ContactEventStreamItemKind,
};
pub use evidence::{EvidenceProfile, VerifiedEvidenceBundle, verify_evidence_bundle};
pub use key_store::{KeyStore, SessionAcceptanceResult, SessionInitiationResult};
pub use key_store_operation::{
    KeyStoreOperation, KeyStoreOperationStatus, PreparedContactBlock, PreparedIdentityGeneration,
    PreparedInboxRotation, PreparedOneTimePreKeys, PreparedSessionAcceptance,
    PreparedSignedPreKeyRotation, SecureStoragePrecondition, UnfinishedKeyStoreOperation,
};
pub use message::{FramePreKeyReference, Message, PayloadKind, SenderIdentityMaterial};
pub use protocol::{
    AcknowledgmentOutcome, AcknowledgmentOutcomeKind, BlockedContactAcknowledgmentPolicy,
    ContactDiscoveryKey, ContactEvent, ContactEventKind, ContactIdentity,
    ContactSafetyNumberConfirmation, ContactSafetyNumberConfirmationKind, ContactState,
    ContactStateChange, ContactTrustState, IdentityKey, InboundMessageOutcome,
    InboundMessageOutcomeKind, OutboundMessageResult, PendingAcknowledgment,
    ProtocolHardeningLimits, ProtocolStateAddress, ProtocolStateCommitCheck, ProtocolStateEngine,
    ProtocolStateEntry, ProtocolStateKind, ProtocolStateStore, ProtocolStateUpdate,
    RetryInstruction, RetryInstructionResult, SafetyNumber, SessionEvent,
    SessionUnrecoverableReason, derive_safety_number, protocol_state_blob_digest,
};
pub use records::{
    DiscoveryKeyBundle, Identity, InboxRotation, OneTimePreKeyBundle, PublicationBundle,
    SignedPreKeyBundle,
};
pub use storage::{InMemorySecureStorage, SecureStorage};
pub use transport_binding::{PreKeySelection, TransportBinding};
