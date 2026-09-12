//! UniFFI bindings for the cryptographic core.
//!
//! This crate exposes the storage-backed [`Client`] API and FFI-safe record types used by SDKs.
//! Apps provide a platform [`SecureStorage`] implementation, then keep one [`Client`] per identity
//! namespace. Identity, messaging and contacts interfaces share its configuration. The host owns
//! protocol-state transactions and observation of committed stores; see [`Client`] for serialization
//! and recovery requirements.
//!
//! # Feature flags
//!
//! - `development-certificates` exposes an in-memory certificate authority for local peer
//!   simulations. Normal artifacts omit the API.
//!
//! # Examples
//!
//! ```
//! use roost_client::{
//!     ClientError, InMemorySecureStorage, Client, PublicationBundle, SecureStorage,
//! };
//! use std::sync::Arc;
//!
//! # fn publish(_bundle: &PublicationBundle) -> Result<(), ClientError> {
//! #     Ok(())
//! # }
//! let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
//! let store = Client::new(storage);
//!
//! if !store.identity().has_identity()? {
//!     let identity = store.identity().prepare_generate_identity()?;
//!     store.commit_operation(identity.operation.identifier.clone())?;
//!     // Commit the host's identity record and operation identifier before finalizing.
//!     store.finalize_operation(identity.operation.identifier)?;
//! }
//!
//! let signed_prekey = store.identity().prepare_rotate_signed_prekey_now()?;
//! store.commit_operation(signed_prekey.operation.identifier.clone())?;
//! // Commit publication work and the operation identifier in the host transaction.
//! store.finalize_operation(signed_prekey.operation.identifier)?;
//! let publication = store.identity().current_publication_bundle()?;
//! publish(&publication)?;
//! # Ok::<(), ClientError>(())
//! ```

uniffi::setup_scaffolding!("roost_client");

mod binding;
mod certificate;
mod client;
#[cfg(feature = "development-certificates")]
mod development_certificate;
mod error;
mod evidence;
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
pub use client::{
    Client, ClientConfiguration, Contacts, IdentityOperations, Messaging, SessionAcceptanceResult,
    SessionInitiationResult,
};
#[cfg(feature = "development-certificates")]
pub use development_certificate::{DevelopmentCertificateAuthority, DevelopmentSenderCertificate};
pub use error::ClientError;
pub use evidence::{EvidenceProfile, VerifiedEvidenceBundle, verify_evidence_bundle};
pub use key_store_operation::{
    KeyStoreOperation, KeyStoreOperationStatus, PreparedContactBlock, PreparedIdentityGeneration,
    PreparedInboxRotation, PreparedOneTimePreKeys, PreparedSessionAcceptance,
    PreparedSignedPreKeyRotation, SecureStoragePrecondition, UnfinishedKeyStoreOperation,
};
pub use message::{FramePreKeyReference, Message, PayloadKind, SenderIdentityMaterial};
pub use protocol::{
    AcknowledgmentOutcome, AcknowledgmentResult, BlockedContactAcknowledgmentPolicy,
    BlockedInboundMessageResult, ContactDiscoveryKey, ContactEvent, ContactEventKind,
    ContactIdentity, ContactSafetyNumberConfirmation, ContactSafetyNumberConfirmationKind,
    ContactState, ContactStateChange, ContactTrustState, IdentityKey, InboundMessageOutcome,
    InboundMessageResult, OutboundMessageResult, PendingAcknowledgment, ProtocolHardeningLimits,
    ProtocolStateAddress, ProtocolStateCommitCheck, ProtocolStateEntry, ProtocolStateKind,
    ProtocolStateUpdate, RetryInstruction, RetryInstructionResult, SafetyNumber, SessionEvent,
    SessionUnrecoverableReason, SessionUnrecoverableResult, derive_safety_number,
    protocol_state_blob_digest,
};
pub use records::{
    DiscoveryKeyBundle, Identity, InboxRotation, OneTimePreKeyBundle, PublicationBundle,
    SignedPreKeyBundle,
};
pub use storage::{InMemorySecureStorage, SecureStorage};
pub use transport_binding::{PreKeySelection, TransportBinding};
