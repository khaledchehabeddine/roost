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

uniffi::setup_scaffolding!("roost_client");

mod binding;
mod certificate;
mod client;
#[cfg(feature = "development-certificates")]
mod development_certificate;
mod error;
mod key_store_operation;
mod message;
mod protocol;
mod records;
mod storage;
mod time;
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
pub use key_store_operation::{
    KeyStoreOperation, KeyStoreOperationStatus, PreparedContactBlock, PreparedIdentityGeneration,
    PreparedInboxRotation, PreparedOneTimePreKeys, PreparedSessionAcceptance,
    PreparedSignedPreKeyRotation, SecureStoragePrecondition, UnfinishedKeyStoreOperation,
};
pub use message::{
    FramePreKeyReference, Message, PayloadKind, SenderIdentityMaterial, decode_message,
    encode_message,
};
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
