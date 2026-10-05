//! Error mapping for failures crossing the UniFFI boundary.

use roost_core::{
    DiscoveryKeyError, HandshakeError, IdentityError, KeyStoreError, KeyStoreOperationError,
    MessageError, MessageOperationError, OneTimePreKeyError, ProtocolStateError, PublicKeyError,
    RatchetError, RatchetStateError, SafetyNumberError, SealedFrameError,
    SessionEstablishmentError, SignedPreKeyError, StorageError, TransportBindingError,
};
use roost_protocol::{SenderCertificateValidationError, SignatureError};

/// Errors surfaced across the UniFFI boundary.
///
/// Variants group storage, identity, backup, and internal failures returned through generated
/// bindings. `reason` fields are diagnostic strings for logs and must not drive application
/// logic.
#[derive(Debug, uniffi::Error)]
pub enum RoostError {
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
    /// A reserved or finalizing operation must be finalized or aborted before other work.
    OperationRecoveryRequired {
        /// The operation to recover.
        operation_id: crate::OperationId,
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

impl std::error::Error for RoostError {}

impl std::fmt::Display for RoostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoostError::AlreadyExists => write!(f, "identity already exists"),
            RoostError::AuthenticationFailed { reason } => {
                write!(f, "authentication failed: {reason}")
            }
            RoostError::BackupFailed { reason } => write!(f, "backup failed: {reason}"),
            RoostError::BackupImportFailed { reason } => {
                write!(f, "backup import failed: {reason}")
            }
            RoostError::BlockedContact { reason } => write!(f, "blocked contact: {reason}"),
            RoostError::CertificateRejected { reason } => {
                write!(f, "certificate rejected: {reason}")
            }
            RoostError::ContactNotAccepted => write!(f, "contact is not accepted"),
            RoostError::Corrupt => write!(f, "stored key material is corrupt"),
            RoostError::DecryptionFailed => write!(f, "decryption failed"),
            RoostError::InternalError { reason } => write!(f, "internal error: {reason}"),
            RoostError::InvalidData { reason } => write!(f, "invalid data: {reason}"),
            RoostError::InboxRotationRequired => {
                write!(f, "inbox rotation required after backup restore")
            }
            RoostError::NotFound => write!(f, "key material not found"),
            RoostError::OperationConflict { reason } => {
                write!(f, "prepared-operation conflict: {reason}")
            }
            RoostError::OperationRecoveryRequired { reason, .. } => {
                write!(f, "prepared-operation recovery required: {reason}")
            }
            RoostError::ProtocolStateFault { reason } => {
                write!(f, "protocol-state fault: {reason}")
            }
            RoostError::Storage { reason } => write!(f, "storage error: {reason}"),
            RoostError::SecureStoragePreconditionChanged { key } => {
                write!(f, "secure-storage precondition changed for {key}")
            }
            RoostError::TerminalSessionRecovery { reason } => {
                write!(f, "terminal session recovery required: {reason}")
            }
            RoostError::TooManyUnfinishedOperations => {
                write!(f, "too many unfinished prepared operations")
            }
            RoostError::UnsupportedVersion { reason } => {
                write!(f, "unsupported version: {reason}")
            }
        }
    }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for RoostError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        RoostError::InternalError {
            reason: "unexpected foreign callback failure".into(),
        }
    }
}

impl From<IdentityError> for RoostError {
    fn from(e: IdentityError) -> Self {
        match e {
            IdentityError::AlreadyExists => RoostError::AlreadyExists,
            IdentityError::BackupFailed(reason) => RoostError::BackupFailed { reason },
            IdentityError::UnsupportedVersion(version) => RoostError::UnsupportedVersion {
                reason: format!("unsupported stored format version: {version}"),
            },
            IdentityError::Corrupt => RoostError::Corrupt,
            IdentityError::DecryptionFailed => RoostError::DecryptionFailed,
            IdentityError::InvalidData(reason) => RoostError::InvalidData { reason },
            IdentityError::LockPoisoned => RoostError::InternalError {
                reason: "internal lock poisoned".into(),
            },
            IdentityError::NotFound => RoostError::NotFound,
            IdentityError::Storage(e) => RoostError::Storage {
                reason: e.to_string(),
            },
        }
    }
}

impl From<SignedPreKeyError> for RoostError {
    fn from(e: SignedPreKeyError) -> Self {
        match e {
            SignedPreKeyError::Clock => RoostError::InternalError {
                reason: "system clock is before Unix epoch".into(),
            },
            SignedPreKeyError::Corrupt => RoostError::Corrupt,
            SignedPreKeyError::Discovery(e) => e.into(),
            SignedPreKeyError::InboxRotationRequired => RoostError::InboxRotationRequired,
            SignedPreKeyError::UnsupportedVersion(version) => RoostError::UnsupportedVersion {
                reason: format!("unsupported stored format version: {version}"),
            },
            SignedPreKeyError::InvalidData(reason) => RoostError::InvalidData { reason },
            SignedPreKeyError::LockPoisoned => RoostError::InternalError {
                reason: "internal lock poisoned".into(),
            },
            SignedPreKeyError::NotFound => RoostError::NotFound,
            SignedPreKeyError::Storage(e) => e.into(),
        }
    }
}

impl From<OneTimePreKeyError> for RoostError {
    fn from(e: OneTimePreKeyError) -> Self {
        match e {
            OneTimePreKeyError::Clock => RoostError::InternalError {
                reason: "system clock is before Unix epoch".into(),
            },
            OneTimePreKeyError::Discovery(e) => e.into(),
            OneTimePreKeyError::InboxRotationRequired => RoostError::InboxRotationRequired,
            OneTimePreKeyError::UnsupportedVersion(version) => RoostError::UnsupportedVersion {
                reason: format!("unsupported stored format version: {version}"),
            },
            OneTimePreKeyError::InvalidData(reason) => RoostError::InvalidData { reason },
            OneTimePreKeyError::LockPoisoned => RoostError::InternalError {
                reason: "internal lock poisoned".into(),
            },
            OneTimePreKeyError::NotFound => RoostError::NotFound,
            OneTimePreKeyError::StaleEpoch => RoostError::InvalidData {
                reason: "one-time pre-key belongs to a superseded discovery-key epoch".into(),
            },
            OneTimePreKeyError::Storage(e) => e.into(),
        }
    }
}

impl From<DiscoveryKeyError> for RoostError {
    fn from(e: DiscoveryKeyError) -> Self {
        match e {
            DiscoveryKeyError::Clock => RoostError::InternalError {
                reason: "system clock is before Unix epoch".into(),
            },
            DiscoveryKeyError::Corrupt => RoostError::Corrupt,
            DiscoveryKeyError::Identity(e) => e.into(),
            DiscoveryKeyError::UnsupportedVersion(version) => RoostError::UnsupportedVersion {
                reason: format!("unsupported stored format version: {version}"),
            },
            DiscoveryKeyError::InvalidData(reason) => RoostError::InvalidData { reason },
            DiscoveryKeyError::LockPoisoned => RoostError::InternalError {
                reason: "internal lock poisoned".into(),
            },
            DiscoveryKeyError::NotFound => RoostError::NotFound,
            DiscoveryKeyError::Storage(e) => e.into(),
        }
    }
}

impl From<StorageError> for RoostError {
    fn from(e: StorageError) -> Self {
        RoostError::Storage {
            reason: e.to_string(),
        }
    }
}

impl From<KeyStoreOperationError> for RoostError {
    fn from(e: KeyStoreOperationError) -> Self {
        match e {
            KeyStoreOperationError::Corrupt(_) => RoostError::Corrupt,
            KeyStoreOperationError::InvalidTransition { status, action } => {
                RoostError::OperationConflict {
                    reason: format!("cannot {action} operation in {status:?} state"),
                }
            }
            KeyStoreOperationError::LockPoisoned => RoostError::InternalError {
                reason: "prepared-operation lock poisoned".into(),
            },
            KeyStoreOperationError::NotFound => RoostError::NotFound,
            KeyStoreOperationError::PreconditionChanged { key } => {
                RoostError::SecureStoragePreconditionChanged { key }
            }
            KeyStoreOperationError::Randomness => RoostError::InternalError {
                reason: "operation identifier generation failed".into(),
            },
            KeyStoreOperationError::RecoveryRequired { id } => {
                RoostError::OperationRecoveryRequired {
                    operation_id: crate::OperationId::from_core(id),
                    reason: "recover the identified operation before continuing".into(),
                }
            }
            KeyStoreOperationError::Storage(e) => e.into(),
            KeyStoreOperationError::TooManyUnfinishedOperations => {
                RoostError::TooManyUnfinishedOperations
            }
        }
    }
}

impl From<KeyStoreError> for RoostError {
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

impl From<HandshakeError> for RoostError {
    fn from(e: HandshakeError) -> Self {
        match e {
            HandshakeError::PublicKey(source) => source.into(),
            HandshakeError::Ratchet(source) => source.into(),
            HandshakeError::SealedFrame(source) => source.into(),
            HandshakeError::NonContributorySharedSecret
            | HandshakeError::OneTimePreKeyMismatch
            | HandshakeError::SenderIdentityMismatch
            | HandshakeError::SenderProofInvalid
            | HandshakeError::SignedPreKeyMismatch => RoostError::AuthenticationFailed {
                reason: e.to_string(),
            },
            HandshakeError::UnsupportedPreKeyBundleVersion(_) => RoostError::UnsupportedVersion {
                reason: e.to_string(),
            },
            HandshakeError::EnvelopeEncode | HandshakeError::HkdfExpand => {
                RoostError::InternalError {
                    reason: e.to_string(),
                }
            }
            HandshakeError::EnvelopeDecode
            | HandshakeError::MissingOneTimePreKey
            | HandshakeError::StalePreKey => RoostError::InvalidData {
                reason: e.to_string(),
            },
        }
    }
}

impl From<PublicKeyError> for RoostError {
    fn from(e: PublicKeyError) -> Self {
        match e {
            PublicKeyError::Signature(source) => source.into(),
            PublicKeyError::InvalidKeyEncoding => RoostError::InvalidData {
                reason: e.to_string(),
            },
        }
    }
}

impl From<RatchetError> for RoostError {
    fn from(e: RatchetError) -> Self {
        match e {
            RatchetError::Aead | RatchetError::NonContributorySharedSecret => {
                RoostError::AuthenticationFailed {
                    reason: e.to_string(),
                }
            }
            RatchetError::HkdfExpand | RatchetError::InvalidHmacKey => RoostError::InternalError {
                reason: e.to_string(),
            },
            RatchetError::InvalidState(_)
            | RatchetError::MaxSkipExceeded
            | RatchetError::MaxSkippedKeysExceeded => RoostError::InvalidData {
                reason: e.to_string(),
            },
        }
    }
}

impl From<RatchetStateError> for RoostError {
    fn from(e: RatchetStateError) -> Self {
        match e {
            RatchetStateError::UnsupportedVersion(_) => RoostError::UnsupportedVersion {
                reason: e.to_string(),
            },
            RatchetStateError::Encode => RoostError::InternalError {
                reason: e.to_string(),
            },
            RatchetStateError::Decode | RatchetStateError::MaxSkippedKeysExceeded => {
                RoostError::InvalidData {
                    reason: e.to_string(),
                }
            }
        }
    }
}

impl From<SealedFrameError> for RoostError {
    fn from(e: SealedFrameError) -> Self {
        match e {
            SealedFrameError::Aead | SealedFrameError::NonContributorySharedSecret => {
                RoostError::AuthenticationFailed {
                    reason: e.to_string(),
                }
            }
            SealedFrameError::Encode | SealedFrameError::HkdfExpand => RoostError::InternalError {
                reason: e.to_string(),
            },
            SealedFrameError::Decode => RoostError::InvalidData {
                reason: e.to_string(),
            },
        }
    }
}

impl From<SignatureError> for RoostError {
    fn from(e: SignatureError) -> Self {
        match e {
            SignatureError::SignatureInvalid => RoostError::AuthenticationFailed {
                reason: e.to_string(),
            },
            SignatureError::InvalidSignatureContext => RoostError::InvalidData {
                reason: e.to_string(),
            },
        }
    }
}

impl From<MessageError> for RoostError {
    fn from(e: MessageError) -> Self {
        match e {
            MessageError::UnsupportedPayloadKind(_) | MessageError::UnsupportedVersion(_) => {
                RoostError::UnsupportedVersion {
                    reason: e.to_string(),
                }
            }
            // Encoding also validates caller-supplied public keys.
            MessageError::Encode
            | MessageError::Decode
            | MessageError::EncodedTooLarge
            | MessageError::InvalidPublicKey
            | MessageError::PayloadTooLarge => RoostError::InvalidData {
                reason: e.to_string(),
            },
        }
    }
}

impl From<ProtocolStateError> for RoostError {
    fn from(e: ProtocolStateError) -> Self {
        match e {
            ProtocolStateError::SenderCertificateValidation(source) => source.into(),
            ProtocolStateError::UnsupportedBlobVersion { .. } => RoostError::UnsupportedVersion {
                reason: e.to_string(),
            },
            ProtocolStateError::MissingSenderCertificateValidation
            | ProtocolStateError::InvalidDeduplicationCapacity { .. }
            | ProtocolStateError::InvalidHardeningLimit { .. }
            | ProtocolStateError::InvalidMessage { .. }
            | ProtocolStateError::InvalidStateKey { .. } => RoostError::InvalidData {
                reason: e.to_string(),
            },
            ProtocolStateError::BlockedContact => RoostError::BlockedContact {
                reason: e.to_string(),
            },
            ProtocolStateError::ContactNotAccepted => RoostError::ContactNotAccepted,
            ProtocolStateError::SessionUnrecoverable => RoostError::TerminalSessionRecovery {
                reason: e.to_string(),
            },
            ProtocolStateError::BlobEncode { .. } => RoostError::InternalError {
                reason: e.to_string(),
            },
            ProtocolStateError::MessageEncode(source) => source.into(),
            ProtocolStateError::SnapshotCapacityExceeded => RoostError::InvalidData {
                reason: e.to_string(),
            },
            ProtocolStateError::Ratchet(source) => source.into(),
            ProtocolStateError::RatchetState(source) => source.into(),
            ProtocolStateError::SealedFrame(source) => source.into(),
            ProtocolStateError::Signature(source) => source.into(),
            ProtocolStateError::BlobDecode { .. }
            | ProtocolStateError::InvalidStateBinding { .. }
            | ProtocolStateError::MissingRequiredState { .. } => RoostError::ProtocolStateFault {
                reason: e.to_string(),
            },
        }
    }
}

impl From<SenderCertificateValidationError> for RoostError {
    fn from(e: SenderCertificateValidationError) -> Self {
        match e {
            // An oversized grace window is the host's setting, not a fault in the certificate.
            SenderCertificateValidationError::GraceWindowTooLarge { .. } => {
                RoostError::InvalidData {
                    reason: e.to_string(),
                }
            }
            SenderCertificateValidationError::MalformedCertificate
            | SenderCertificateValidationError::RelayDomainMismatch
            | SenderCertificateValidationError::InvalidKeyEncoding
            | SenderCertificateValidationError::UnknownSigningKeyId
            | SenderCertificateValidationError::UntrustedSigningKeyId
            | SenderCertificateValidationError::DuplicateSigningKeyId
            | SenderCertificateValidationError::SignatureFailure
            | SenderCertificateValidationError::RevocationStateUnavailable
            | SenderCertificateValidationError::RevokedIdentityKey
            | SenderCertificateValidationError::ExpiredCertificate => {
                RoostError::CertificateRejected {
                    reason: e.to_string(),
                }
            }
        }
    }
}

impl From<SafetyNumberError> for RoostError {
    fn from(e: SafetyNumberError) -> Self {
        RoostError::InvalidData {
            reason: e.to_string(),
        }
    }
}

impl From<SessionEstablishmentError> for RoostError {
    fn from(e: SessionEstablishmentError) -> Self {
        match e {
            SessionEstablishmentError::Discovery(e) => e.into(),
            SessionEstablishmentError::Handshake(e) => e.into(),
            SessionEstablishmentError::Identity(e) => e.into(),
            SessionEstablishmentError::PublicKey(e) => e.into(),
            SessionEstablishmentError::Message(e) => e.into(),
            SessionEstablishmentError::OneTimePreKey(e) => e.into(),
            SessionEstablishmentError::Operation(e) => e.into(),
            SessionEstablishmentError::ProtocolState(e) => e.into(),
            SessionEstablishmentError::SignedPreKey(e) => e.into(),
        }
    }
}

impl From<MessageOperationError> for RoostError {
    fn from(e: MessageOperationError) -> Self {
        match e {
            MessageOperationError::Discovery(e) => e.into(),
            MessageOperationError::Identity(e) => e.into(),
            MessageOperationError::Operation(e) => e.into(),
            MessageOperationError::ProtocolState(e) => e.into(),
        }
    }
}

impl From<TransportBindingError> for RoostError {
    fn from(e: TransportBindingError) -> Self {
        RoostError::InvalidData {
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
                RoostError::from(ProtocolStateError::MessageEncode(error)),
                RoostError::InvalidData { .. }
            ));
        }
    }
}
