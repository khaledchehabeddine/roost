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
//! use aether::{
//!     AetherError, InMemorySecureStorage, KeyStore, PublicationBundle, SecureStorage,
//! };
//! use std::sync::Arc;
//!
//! # fn publish(_bundle: &PublicationBundle) -> Result<(), AetherError> {
//! #     Ok(())
//! # }
//! let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
//! let store = KeyStore::new(storage);
//!
//! if !store.has_identity()? {
//!     store.generate_identity()?;
//! }
//!
//! store.rotate_signed_prekey_now()?;
//! let publication = store.current_publication_bundle()?;
//! publish(&publication)?;
//! # Ok::<(), AetherError>(())
//! ```

uniffi::setup_scaffolding!("aether");

#[cfg(all(feature = "fixture-replay", not(debug_assertions)))]
compile_error!("fixture-replay is test-only and must not be enabled for release builds");

mod binding;
mod certificate;
#[cfg(feature = "development-certificates")]
mod development_certificate;
mod error;
mod events;
#[cfg(feature = "fixture-replay")]
mod fixture_replay;
mod key_store;
mod message;
mod protocol;
mod records;
mod storage;

pub use binding::{verify_discovery_to_identity_binding, verify_identity_key_binding};
pub use certificate::{
    DomainSigningKey, DomainSigningKeyStatus, RevocationState, SenderCertificateValidation,
    ValidatedSenderCertificate, validate_sender_certificate,
};
#[cfg(feature = "development-certificates")]
pub use development_certificate::{DevelopmentCertificateAuthority, DevelopmentSenderCertificate};
pub use error::AetherError;
pub use events::{
    ContactEventEnvelope, ContactEventObserver, ContactEventSnapshot, ContactEventStream,
    ContactEventStreamItem, ContactEventStreamItemKind,
};
pub use key_store::{KeyStore, SessionAcceptanceResult, SessionInitiationResult};
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
