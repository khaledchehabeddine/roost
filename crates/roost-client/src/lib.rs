//! The Swift and Kotlin API, exported through UniFFI.
//!
//! Hosts create one [`IdentityContext`] per identity namespace over their own [`SecureStorage`].
//! Its documentation says what Roost and the host each own.
//!
//! # Feature flags
//!
//! - `development-certificates` exposes an in-memory certificate authority for local peer
//!   simulations. Normal artifacts omit the API.

uniffi::setup_scaffolding!("roost_client");

mod binding;
mod certificate;
mod context;
#[cfg(feature = "development-certificates")]
mod development_certificate;
mod error;
mod message;
mod operation;
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
pub use context::{
    ContactBlock, Contacts, ContextConfiguration, IdentityContext, Messaging,
    SessionAcceptanceResult, SessionInitiationResult,
};
#[cfg(feature = "development-certificates")]
pub use development_certificate::{DevelopmentCertificateAuthority, DevelopmentSenderCertificate};
pub use error::RoostError;
pub use message::{
    FramePreKeyReference, Message, PayloadKind, SenderIdentityMaterial, decode_message,
    encode_message,
};
pub use operation::{
    OperationId, OperationStatus, PreparedContactBlock, PreparedIdentity, PreparedInboxRotation,
    PreparedOneTimePreKeys, PreparedSessionAcceptance, PreparedSignedPreKeyRotation,
    UnfinishedOperation,
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
    Identity, InboxRotation, PublicDiscoveryKey, PublicOneTimePreKey, PublicSignedPreKey,
    PublicationBundle,
};
pub use storage::SecureStorage;
pub use transport_binding::{PreKeySelection, TransportBinding};
