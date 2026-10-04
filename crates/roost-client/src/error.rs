//! Error mapping for failures crossing the UniFFI boundary.

use roost_core::{
    DiscoveryKeyError, HandshakeError, IdentityError, KeyBundleError, KeyStoreError,
    KeyStoreOperationError, MessageError, MessageOperationError, OneTimePreKeyError,
    ProtocolStateError, RatchetError, RatchetStateError, SafetyNumberError, SealedFrameError,
    SessionEstablishmentError, SignedPreKeyError, StorageError, TransportBindingError,
};
use roost_protocol::{EvidenceVerificationError, SenderCertificateValidationError, SignatureError};

/// Errors surfaced across the UniFFI boundary.
///
/// Variants group storage, identity, backup, and internal failures returned through generated
/// bindings. `reason` fields are diagnostic strings for logs and must not drive application
/// logic.
#[derive(Debug, uniffi::Error)]
pub enum ClientError {
    /// An identity already exists in storage.
    AlreadyExists,
    /// Cryptographic authentication or decryption failed.
    AuthenticationFailed {
        /// Diagnostic context for logging only.
        reason: String,
    },
    /// Encrypted backup creation failed during randomness, key derivation, or encryption.
    BackupFailed {
        /// Diagnostic failure context for logs only.
        reason: String,
    },
    /// Backup import failed before an identity was restored.
    BackupImportFailed {
        /// Diagnostic failure context for logs only.
        reason: String,
    },
    /// A contact is locally blocked.
    BlockedContact {
        /// Diagnostic context for logging only.
        reason: String,
    },
    /// Sender certificate validation rejected caller input.
    CertificateRejected {
        /// Diagnostic context for logging only.
        reason: String,
    },
    /// A contact must be accepted before sending.
    ContactNotAccepted,
    /// Stored identity, discovery key, or signed pre-key material is corrupt or incomplete.
    Corrupt,
    /// Backup decryption failed because the passphrase or backup bytes did not authenticate.
    DecryptionFailed,
    /// Internal failure that does not expose a more specific failure category.
    InternalError {
        /// Diagnostic context for logging only.
        reason: String,
    },
    /// Input bytes are malformed or the wrong length.
    InvalidData {
        /// Description of what was invalid for logging only.
        reason: String,
    },
    /// A restored identity must rotate its inbox before using prekeys.
    InboxRotationRequired,
    /// Requested identity, discovery-key, or signed-pre-key material is not stored.
    NotFound,
    /// The requested prepared-operation transition conflicts with its durable state.
    OperationConflict {
        /// Diagnostic context for logging only.
        reason: String,
    },
    /// A committed or finalizing KeyStore operation must be recovered before ordinary work.
    OperationRecoveryRequired {
        /// Opaque 16-byte identifier of the operation to recover.
        operation_id: Vec<u8>,
        /// Diagnostic context for logging only.
        reason: String,
    },
    /// Protocol-state load, decode, encode, binding, or missing-state fault.
    ProtocolStateFault {
        /// Diagnostic context for logging only.
        reason: String,
    },
    /// Underlying [`SecureStorage`](crate::SecureStorage) returned a platform error.
    Storage {
        /// Platform-specific error message from the underlying
        /// [`SecureStorage`](crate::SecureStorage) implementation.
        reason: String,
    },
    /// A SecureStorage input changed after a KeyStore operation was prepared.
    SecureStoragePreconditionChanged {
        /// Stable SecureStorage entry name that changed.
        key: String,
    },
    /// A Session is terminal and must be replaced through a fresh handshake.
    TerminalSessionRecovery {
        /// Diagnostic context for logging only.
        reason: String,
    },
    /// The bounded prepared-operation journal has no free unfinished-operation slot.
    TooManyUnfinishedOperations,
    /// A message, blob, backup, or prekey major version is unsupported.
    UnsupportedVersion {
        /// Diagnostic context for logging only.
        reason: String,
    },
}

impl std::error::Error for ClientError {}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::AlreadyExists => write!(f, "identity already exists"),
            ClientError::AuthenticationFailed { reason } => {
                write!(f, "authentication failed: {reason}")
            }
            ClientError::BackupFailed { reason } => write!(f, "backup failed: {reason}"),
            ClientError::BackupImportFailed { reason } => {
                write!(f, "backup import failed: {reason}")
            }
            ClientError::BlockedContact { reason } => write!(f, "blocked contact: {reason}"),
            ClientError::CertificateRejected { reason } => {
                write!(f, "certificate rejected: {reason}")
            }
            ClientError::ContactNotAccepted => write!(f, "contact is not accepted"),
            ClientError::Corrupt => write!(f, "stored key material is corrupt"),
            ClientError::DecryptionFailed => write!(f, "decryption failed"),
            ClientError::InternalError { reason } => write!(f, "internal error: {reason}"),
            ClientError::InvalidData { reason } => write!(f, "invalid data: {reason}"),
            ClientError::InboxRotationRequired => {
                write!(f, "inbox rotation required after backup restore")
            }
            ClientError::NotFound => write!(f, "key material not found"),
            ClientError::OperationConflict { reason } => {
                write!(f, "prepared-operation conflict: {reason}")
            }
            ClientError::OperationRecoveryRequired { reason, .. } => {
                write!(f, "prepared-operation recovery required: {reason}")
            }
            ClientError::ProtocolStateFault { reason } => {
                write!(f, "protocol-state fault: {reason}")
            }
            ClientError::Storage { reason } => write!(f, "storage error: {reason}"),
            ClientError::SecureStoragePreconditionChanged { key } => {
                write!(f, "secure-storage precondition changed for {key}")
            }
            ClientError::TerminalSessionRecovery { reason } => {
                write!(f, "terminal session recovery required: {reason}")
            }
            ClientError::TooManyUnfinishedOperations => {
                write!(f, "too many unfinished prepared operations")
            }
            ClientError::UnsupportedVersion { reason } => {
                write!(f, "unsupported version: {reason}")
            }
        }
    }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for ClientError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        ClientError::InternalError {
            reason: "unexpected foreign callback failure".into(),
        }
    }
}

impl From<IdentityError> for ClientError {
    fn from(e: IdentityError) -> Self {
        match e {
            IdentityError::AlreadyExists => ClientError::AlreadyExists,
            IdentityError::BackupFailed(reason) => ClientError::BackupFailed { reason },
            IdentityError::UnsupportedVersion(version) => ClientError::UnsupportedVersion {
                reason: format!("unsupported stored format version: {version}"),
            },
            IdentityError::Corrupt => ClientError::Corrupt,
            IdentityError::DecryptionFailed => ClientError::DecryptionFailed,
            IdentityError::InvalidData(reason) => ClientError::InvalidData { reason },
            IdentityError::LockPoisoned => ClientError::InternalError {
                reason: "internal lock poisoned".into(),
            },
            IdentityError::NotFound => ClientError::NotFound,
            IdentityError::Storage(e) => ClientError::Storage {
                reason: e.to_string(),
            },
        }
    }
}

impl From<SignedPreKeyError> for ClientError {
    fn from(e: SignedPreKeyError) -> Self {
        match e {
            SignedPreKeyError::Clock => ClientError::InternalError {
                reason: "system clock is before Unix epoch".into(),
            },
            SignedPreKeyError::Corrupt => ClientError::Corrupt,
            SignedPreKeyError::Discovery(e) => e.into(),
            SignedPreKeyError::InboxRotationRequired => ClientError::InboxRotationRequired,
            SignedPreKeyError::UnsupportedVersion(version) => ClientError::UnsupportedVersion {
                reason: format!("unsupported stored format version: {version}"),
            },
            SignedPreKeyError::InvalidData(reason) => ClientError::InvalidData { reason },
            SignedPreKeyError::LockPoisoned => ClientError::InternalError {
                reason: "internal lock poisoned".into(),
            },
            SignedPreKeyError::NotFound => ClientError::NotFound,
            SignedPreKeyError::Storage(e) => e.into(),
        }
    }
}

impl From<OneTimePreKeyError> for ClientError {
    fn from(e: OneTimePreKeyError) -> Self {
        match e {
            OneTimePreKeyError::Clock => ClientError::InternalError {
                reason: "system clock is before Unix epoch".into(),
            },
            OneTimePreKeyError::Discovery(e) => e.into(),
            OneTimePreKeyError::InboxRotationRequired => ClientError::InboxRotationRequired,
            OneTimePreKeyError::UnsupportedVersion(version) => ClientError::UnsupportedVersion {
                reason: format!("unsupported stored format version: {version}"),
            },
            OneTimePreKeyError::InvalidData(reason) => ClientError::InvalidData { reason },
            OneTimePreKeyError::LockPoisoned => ClientError::InternalError {
                reason: "internal lock poisoned".into(),
            },
            OneTimePreKeyError::NotFound => ClientError::NotFound,
            OneTimePreKeyError::StaleEpoch => ClientError::InvalidData {
                reason: "one-time pre-key belongs to a superseded discovery-key epoch".into(),
            },
            OneTimePreKeyError::Storage(e) => e.into(),
        }
    }
}

impl From<DiscoveryKeyError> for ClientError {
    fn from(e: DiscoveryKeyError) -> Self {
        match e {
            DiscoveryKeyError::Clock => ClientError::InternalError {
                reason: "system clock is before Unix epoch".into(),
            },
            DiscoveryKeyError::Corrupt => ClientError::Corrupt,
            DiscoveryKeyError::Identity(e) => e.into(),
            DiscoveryKeyError::UnsupportedVersion(version) => ClientError::UnsupportedVersion {
                reason: format!("unsupported stored format version: {version}"),
            },
            DiscoveryKeyError::InvalidData(reason) => ClientError::InvalidData { reason },
            DiscoveryKeyError::LockPoisoned => ClientError::InternalError {
                reason: "internal lock poisoned".into(),
            },
            DiscoveryKeyError::NotFound => ClientError::NotFound,
            DiscoveryKeyError::Storage(e) => e.into(),
        }
    }
}

impl From<StorageError> for ClientError {
    fn from(e: StorageError) -> Self {
        ClientError::Storage {
            reason: e.to_string(),
        }
    }
}

impl From<KeyStoreOperationError> for ClientError {
    fn from(e: KeyStoreOperationError) -> Self {
        match e {
            KeyStoreOperationError::Corrupt(_) => ClientError::Corrupt,
            KeyStoreOperationError::InvalidTransition { status, action } => {
                ClientError::OperationConflict {
                    reason: format!("cannot {action} operation in {status:?} state"),
                }
            }
            KeyStoreOperationError::LockPoisoned => ClientError::InternalError {
                reason: "prepared-operation lock poisoned".into(),
            },
            KeyStoreOperationError::NotFound => ClientError::NotFound,
            KeyStoreOperationError::PreconditionChanged { key } => {
                ClientError::SecureStoragePreconditionChanged { key }
            }
            KeyStoreOperationError::Randomness => ClientError::InternalError {
                reason: "operation identifier generation failed".into(),
            },
            KeyStoreOperationError::RecoveryRequired { id } => {
                ClientError::OperationRecoveryRequired {
                    operation_id: id.as_bytes().to_vec(),
                    reason: "recover the identified operation before continuing".into(),
                }
            }
            KeyStoreOperationError::Storage(e) => e.into(),
            KeyStoreOperationError::TooManyUnfinishedOperations => {
                ClientError::TooManyUnfinishedOperations
            }
        }
    }
}

impl From<KeyStoreError> for ClientError {
    fn from(e: KeyStoreError) -> Self {
        match e {
            KeyStoreError::Discovery(e) => e.into(),
            KeyStoreError::Identity(e) => e.into(),
            KeyStoreError::OneTimePreKey(e) => e.into(),
            KeyStoreError::Operation(e) => e.into(),
            KeyStoreError::ProtocolState(e) => e.into(),
            KeyStoreError::SignedPreKey(e) => e.into(),
        }
    }
}

impl From<HandshakeError> for ClientError {
    fn from(e: HandshakeError) -> Self {
        match e {
            HandshakeError::KeyBundle(source) => source.into(),
            HandshakeError::Ratchet(source) => source.into(),
            HandshakeError::SealedFrame(source) => source.into(),
            HandshakeError::NonContributorySharedSecret
            | HandshakeError::OneTimePreKeyMismatch
            | HandshakeError::SenderIdentityMismatch
            | HandshakeError::SenderProofInvalid
            | HandshakeError::SignedPreKeyMismatch => ClientError::AuthenticationFailed {
                reason: e.to_string(),
            },
            HandshakeError::UnsupportedPreKeyBundleVersion(_) => ClientError::UnsupportedVersion {
                reason: e.to_string(),
            },
            HandshakeError::EnvelopeEncode | HandshakeError::HkdfExpand => {
                ClientError::InternalError {
                    reason: e.to_string(),
                }
            }
            HandshakeError::EnvelopeDecode
            | HandshakeError::MissingOneTimePreKey
            | HandshakeError::StalePreKey => ClientError::InvalidData {
                reason: e.to_string(),
            },
        }
    }
}

impl From<KeyBundleError> for ClientError {
    fn from(e: KeyBundleError) -> Self {
        match e {
            KeyBundleError::Signature(source) => source.into(),
            KeyBundleError::InvalidKeyEncoding => ClientError::InvalidData {
                reason: e.to_string(),
            },
        }
    }
}

impl From<RatchetError> for ClientError {
    fn from(e: RatchetError) -> Self {
        match e {
            RatchetError::Aead | RatchetError::NonContributorySharedSecret => {
                ClientError::AuthenticationFailed {
                    reason: e.to_string(),
                }
            }
            RatchetError::HkdfExpand | RatchetError::InvalidHmacKey => ClientError::InternalError {
                reason: e.to_string(),
            },
            RatchetError::InvalidState(_)
            | RatchetError::MaxSkipExceeded
            | RatchetError::MaxSkippedKeysExceeded => ClientError::InvalidData {
                reason: e.to_string(),
            },
        }
    }
}

impl From<RatchetStateError> for ClientError {
    fn from(e: RatchetStateError) -> Self {
        match e {
            RatchetStateError::UnsupportedVersion(_) => ClientError::UnsupportedVersion {
                reason: e.to_string(),
            },
            RatchetStateError::Encode => ClientError::InternalError {
                reason: e.to_string(),
            },
            RatchetStateError::Decode | RatchetStateError::MaxSkippedKeysExceeded => {
                ClientError::InvalidData {
                    reason: e.to_string(),
                }
            }
        }
    }
}

impl From<SealedFrameError> for ClientError {
    fn from(e: SealedFrameError) -> Self {
        match e {
            SealedFrameError::Aead | SealedFrameError::NonContributorySharedSecret => {
                ClientError::AuthenticationFailed {
                    reason: e.to_string(),
                }
            }
            SealedFrameError::Encode | SealedFrameError::HkdfExpand => ClientError::InternalError {
                reason: e.to_string(),
            },
            SealedFrameError::Decode => ClientError::InvalidData {
                reason: e.to_string(),
            },
        }
    }
}

impl From<SignatureError> for ClientError {
    fn from(e: SignatureError) -> Self {
        match e {
            SignatureError::SignatureInvalid => ClientError::AuthenticationFailed {
                reason: e.to_string(),
            },
            SignatureError::InvalidSignatureContext => ClientError::InvalidData {
                reason: e.to_string(),
            },
        }
    }
}

impl From<MessageError> for ClientError {
    fn from(e: MessageError) -> Self {
        match e {
            MessageError::UnsupportedPayloadKind(_) | MessageError::UnsupportedVersion(_) => {
                ClientError::UnsupportedVersion {
                    reason: e.to_string(),
                }
            }
            // Encoding also validates caller-supplied public keys.
            MessageError::Encode
            | MessageError::Decode
            | MessageError::EncodedTooLarge
            | MessageError::InvalidPublicKey
            | MessageError::PayloadTooLarge => ClientError::InvalidData {
                reason: e.to_string(),
            },
        }
    }
}

impl From<ProtocolStateError> for ClientError {
    fn from(e: ProtocolStateError) -> Self {
        match e {
            ProtocolStateError::SenderCertificateValidation(source) => {
                ClientError::CertificateRejected {
                    reason: source.to_string(),
                }
            }
            ProtocolStateError::UnsupportedBlobVersion { .. } => ClientError::UnsupportedVersion {
                reason: e.to_string(),
            },
            ProtocolStateError::MissingSenderCertificateValidation
            | ProtocolStateError::InvalidDeduplicationCapacity { .. }
            | ProtocolStateError::InvalidHardeningLimit { .. }
            | ProtocolStateError::InvalidMessage { .. }
            | ProtocolStateError::InvalidStateKey { .. } => ClientError::InvalidData {
                reason: e.to_string(),
            },
            ProtocolStateError::BlockedContact => ClientError::BlockedContact {
                reason: e.to_string(),
            },
            ProtocolStateError::ContactNotAccepted => ClientError::ContactNotAccepted,
            ProtocolStateError::SessionUnrecoverable => ClientError::TerminalSessionRecovery {
                reason: e.to_string(),
            },
            ProtocolStateError::BlobEncode { .. } => ClientError::InternalError {
                reason: e.to_string(),
            },
            ProtocolStateError::MessageEncode(source) => source.into(),
            ProtocolStateError::SnapshotCapacityExceeded => ClientError::InvalidData {
                reason: e.to_string(),
            },
            ProtocolStateError::Ratchet(source) => source.into(),
            ProtocolStateError::RatchetState(source) => source.into(),
            ProtocolStateError::SealedFrame(source) => source.into(),
            ProtocolStateError::Signature(source) => source.into(),
            ProtocolStateError::BlobDecode { .. }
            | ProtocolStateError::InvalidStateBinding { .. }
            | ProtocolStateError::MissingRequiredState { .. } => ClientError::ProtocolStateFault {
                reason: e.to_string(),
            },
        }
    }
}

impl From<SenderCertificateValidationError> for ClientError {
    fn from(e: SenderCertificateValidationError) -> Self {
        ClientError::CertificateRejected {
            reason: e.to_string(),
        }
    }
}

impl From<EvidenceVerificationError> for ClientError {
    fn from(e: EvidenceVerificationError) -> Self {
        match e {
            EvidenceVerificationError::BundleTooLarge
            | EvidenceVerificationError::MalformedBundle
            | EvidenceVerificationError::WrongProfile { .. }
            | EvidenceVerificationError::TooManyDomainSigningKeys { .. }
            | EvidenceVerificationError::GraceWindowTooLarge { .. } => ClientError::InvalidData {
                reason: e.to_string(),
            },
            EvidenceVerificationError::UnsupportedVersion(_) => ClientError::UnsupportedVersion {
                reason: e.to_string(),
            },
            EvidenceVerificationError::SenderCertificate(e) => e.into(),
            EvidenceVerificationError::SignatureFailure => ClientError::AuthenticationFailed {
                reason: e.to_string(),
            },
        }
    }
}

impl From<SafetyNumberError> for ClientError {
    fn from(e: SafetyNumberError) -> Self {
        ClientError::InvalidData {
            reason: e.to_string(),
        }
    }
}

impl From<SessionEstablishmentError> for ClientError {
    fn from(e: SessionEstablishmentError) -> Self {
        match e {
            SessionEstablishmentError::Discovery(e) => e.into(),
            SessionEstablishmentError::Handshake(e) => e.into(),
            SessionEstablishmentError::Identity(e) => e.into(),
            SessionEstablishmentError::KeyBundle(e) => e.into(),
            SessionEstablishmentError::Message(e) => e.into(),
            SessionEstablishmentError::OneTimePreKey(e) => e.into(),
            SessionEstablishmentError::Operation(e) => e.into(),
            SessionEstablishmentError::ProtocolState(e) => e.into(),
            SessionEstablishmentError::SignedPreKey(e) => e.into(),
        }
    }
}

impl From<MessageOperationError> for ClientError {
    fn from(e: MessageOperationError) -> Self {
        match e {
            MessageOperationError::Discovery(e) => e.into(),
            MessageOperationError::Identity(e) => e.into(),
            MessageOperationError::Operation(e) => e.into(),
            MessageOperationError::ProtocolState(e) => e.into(),
        }
    }
}

impl From<TransportBindingError> for ClientError {
    fn from(e: TransportBindingError) -> Self {
        ClientError::InvalidData {
            reason: e.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_input_rejections_remain_invalid_data_across_protocol_error_boundary() {
        for error in [
            MessageError::PayloadTooLarge,
            MessageError::EncodedTooLarge,
            MessageError::Encode,
        ] {
            assert!(matches!(
                ClientError::from(ProtocolStateError::MessageEncode(error)),
                ClientError::InvalidData { .. }
            ));
        }
    }
}
