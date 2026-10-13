//! The Swift and Kotlin API, exported through UniFFI.
//!
//! Hosts create one [`IdentityContext`] per identity namespace over their own [`SecureStorage`].
//! Its documentation says what Roost and the host each own.

uniffi::setup_scaffolding!("roost_client");

mod binding;
mod certificate;
mod context;
mod error;
mod message;
mod message_operation;
mod operation;
mod protocol;
mod records;
mod storage;
mod time;
mod transport_binding;

pub use binding::{verify_discovery_to_identity_binding, verify_identity_key_binding};
pub use certificate::{
    DomainSigningKey, DomainSigningKeyStatus, RevocationState, SenderCertificateValidation,
    ValidatedSenderCertificate,
};
pub use context::{
    ContactBlock, Contacts, IdentityContext, Messaging, SessionAcceptanceOutcome,
    SessionAcceptanceResult, SessionInitiationResult,
};
pub use error::RoostError;
pub use message::{
    FramePreKeyReference, Message, MessageId, PayloadKind, SenderIdentityMaterial, decode_message,
    encode_message,
};
pub use message_operation::{
    IncomingMessage, MessageDecryption, MessageDecryptionStep, MessageDestination,
    MessageEncryption, MessageEncryptionStep, OutgoingMessage, SignedSenderCertificate,
};
pub use operation::{
    OperationId, OperationStatus, PreparedContactBlock, PreparedIdentity, PreparedInboxRotation,
    PreparedOneTimePreKeys, PreparedSessionAcceptance, PreparedSignedPreKeyRotation,
    UnfinishedOperation,
};
pub use protocol::{
    AcknowledgmentResult, BlockedContactAcknowledgmentPolicy, BlockedInboundMessageResult,
    CommitCondition, ContactDiscoveryKey, ContactEvent, ContactEventKind, ContactIdentity,
    ContactSafetyNumberConfirmation, ContactSafetyNumberConfirmationKind, ContactState,
    ContactStateChange, ContactTrustState, IdentityKey, InboundMessageOutcome,
    InboundMessageResult, OutboundMessageResult, PendingAcknowledgment, ProtocolHardeningLimits,
    ProtocolStateKind, ReceiveSettings, RetryInstruction, RetryInstructionResult, SafetyNumber,
    SessionEvent, SessionUnrecoverableReason, SessionUnrecoverableResult, StateChanges, StateEntry,
    StateKey, StateUpdate, derive_safety_number, protocol_hardening_limits,
};
pub use records::{
    Identity, InboxRotation, PublicDiscoveryKey, PublicOneTimePreKey, PublicSignedPreKey,
    PublicationBundle, SessionId,
};
pub use storage::SecureStorage;
pub use transport_binding::{PreKeySelection, TransportBinding};
