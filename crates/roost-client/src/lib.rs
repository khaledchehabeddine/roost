//! The Swift and Kotlin API, exported through UniFFI.
//!
//! It handles identities and their backups, prekeys and inbox rotation, contacts, blocking and
//! Safety Numbers, Message Operations, delivery checks and recovery, sender certificate and
//! binding checks, and the one error type every call shares. Hosts create one [`IdentityContext`]
//! per identity namespace over their own [`SecureStorage`]. Its documentation says what Roost and
//! the host each own.

uniffi::setup_scaffolding!("roost_client");

mod binding;
mod certificate;
mod contact;
mod context;
mod encoding;
mod error;
mod hardening;
mod identity;
mod message;
mod message_operation;
mod operation;
mod publication;
mod recovery;
mod state;
mod storage;
mod time;
mod transport_binding;

pub use binding::{verify_discovery_to_identity_binding, verify_identity_key_binding};
pub use certificate::{
    DomainSigningKey, DomainSigningKeyStatus, RevocationState, SenderCertificateValidation,
    ValidatedSenderCertificate,
};
pub use contact::{
    ContactBlock, ContactSafetyNumberConfirmation, ContactState, ContactTrustState, SafetyNumber,
    derive_safety_number,
};
pub use context::{Contacts, IdentityContext, Messaging};
pub use error::RoostError;
pub use hardening::{ProtocolHardeningLimits, protocol_hardening_limits};
pub use identity::{Identity, IdentityKey};
pub use message::{
    FrameOneTimePreKeyReference, FramePreKeyReference, Message, MessageId, PayloadKind,
    SenderIdentityMaterial, SessionId, decode_message, encode_message,
};
pub use message_operation::{
    AcknowledgmentResult, AdmissionRequest, BlockedContactAcknowledgmentPolicy,
    BlockedInboundMessageResult, GrantUpdateResult, InboundMessageOutcome, InboundMessageResult,
    IncomingMessage, MessageDecryption, MessageDecryptionStep, MessageDestination,
    MessageEncryption, MessageEncryptionStep, OutboundMessageResult, OutgoingGrantUpdate,
    OutgoingMessage, ReceiveSettings, SignedSenderCertificate, WithheldInboundMessageResult,
};
pub use operation::{
    OperationId, OperationStatus, PreparedIdentity, PreparedInboxRotation, PreparedOneTimePreKeys,
    PreparedSignedPreKeyRotation, UnfinishedOperation,
};
pub use publication::{
    PreKeyBundle, PublicDiscoveryKey, PublicOneTimePreKey, PublicSignedPreKey, PublicationBundle,
};
pub use recovery::{
    DeliveryCheck, DeliveryCheckResult, DeliveryCheckStep, MessageRecovery, MessageRecoveryStep,
    OutgoingRecovery, RetryInstruction,
};
pub use state::{
    CommitCondition, ProtocolStateKind, StateChanges, StateEntry, StateKey, StateUpdate,
};
pub use storage::SecureStorage;
pub use transport_binding::TransportBinding;
