//! Error mapping for failures crossing the UniFFI boundary.

use aether_core::{
    DiscoveryKeyError, EvidenceVerificationError, IdentityError, KeyStoreError,
    KeyStoreOperationError, MessageError, MessageOperationError, OneTimePreKeyError,
    ProtocolStateError, SafetyNumberError, SenderCertificateValidationError,
    SessionEstablishmentError, SignedPreKeyError, StorageError,
};
use aether_crypto::CryptoError;

/// Errors surfaced across the UniFFI boundary.
///
/// Variants group storage, identity, backup, and internal failures returned through generated
/// bindings. `reason` fields are diagnostic strings for logs and must not drive application
/// logic.
#[derive(Debug, uniffi::Error)]
pub enum AetherError {
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
    /// Stored identity, discovery key, or signed pre-key material is corrupt or incomplete.
    Corrupt,
    /// Backup decryption failed because the passphrase or backup bytes did not authenticate.
    DecryptionFailed,
    /// An event observer is no longer registered.
    EventStreamClosed,
    /// An event observer lagged and must recover from a snapshot.
    EventLag {
        /// Number of missed events.
        missed: u64,
    },
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
        operation_identifier: Vec<u8>,
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

impl std::error::Error for AetherError {}

impl std::fmt::Display for AetherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AetherError::AlreadyExists => write!(f, "identity already exists"),
            AetherError::AuthenticationFailed { reason } => {
                write!(f, "authentication failed: {reason}")
            }
            AetherError::BackupFailed { reason } => write!(f, "backup failed: {reason}"),
            AetherError::BackupImportFailed { reason } => {
                write!(f, "backup import failed: {reason}")
            }
            AetherError::BlockedContact { reason } => write!(f, "blocked contact: {reason}"),
            AetherError::CertificateRejected { reason } => {
                write!(f, "certificate rejected: {reason}")
            }
            AetherError::Corrupt => write!(f, "stored key material is corrupt"),
            AetherError::DecryptionFailed => write!(f, "decryption failed"),
            AetherError::EventStreamClosed => write!(f, "event stream observer is closed"),
            AetherError::EventLag { missed } => write!(f, "event stream observer lagged: {missed}"),
            AetherError::InternalError { reason } => write!(f, "internal error: {reason}"),
            AetherError::InvalidData { reason } => write!(f, "invalid data: {reason}"),
            AetherError::InboxRotationRequired => {
                write!(f, "inbox rotation required after backup restore")
            }
            AetherError::NotFound => write!(f, "key material not found"),
            AetherError::OperationConflict { reason } => {
                write!(f, "prepared-operation conflict: {reason}")
            }
            AetherError::OperationRecoveryRequired { reason, .. } => {
                write!(f, "prepared-operation recovery required: {reason}")
            }
            AetherError::ProtocolStateFault { reason } => {
                write!(f, "protocol-state fault: {reason}")
            }
            AetherError::Storage { reason } => write!(f, "storage error: {reason}"),
            AetherError::SecureStoragePreconditionChanged { key } => {
                write!(f, "secure-storage precondition changed for {key}")
            }
            AetherError::TerminalSessionRecovery { reason } => {
                write!(f, "terminal session recovery required: {reason}")
            }
            AetherError::TooManyUnfinishedOperations => {
                write!(f, "too many unfinished prepared operations")
            }
            AetherError::UnsupportedVersion { reason } => {
                write!(f, "unsupported version: {reason}")
            }
        }
    }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for AetherError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        AetherError::InternalError {
            reason: "unexpected foreign callback failure".into(),
        }
    }
}

impl From<IdentityError> for AetherError {
    fn from(e: IdentityError) -> Self {
        match e {
            IdentityError::AlreadyExists => AetherError::AlreadyExists,
            IdentityError::BackupFailed(reason) => AetherError::BackupFailed { reason },
            IdentityError::InvalidData(reason) if reason.contains("unsupported") => {
                AetherError::UnsupportedVersion { reason }
            }
            IdentityError::Corrupt => AetherError::Corrupt,
            IdentityError::DecryptionFailed => AetherError::DecryptionFailed,
            IdentityError::InvalidData(reason) => AetherError::InvalidData { reason },
            IdentityError::LockPoisoned => AetherError::InternalError {
                reason: "internal lock poisoned".into(),
            },
            IdentityError::NotFound => AetherError::NotFound,
            IdentityError::Storage(e) => AetherError::Storage {
                reason: e.to_string(),
            },
        }
    }
}

impl From<SignedPreKeyError> for AetherError {
    fn from(e: SignedPreKeyError) -> Self {
        match e {
            SignedPreKeyError::Clock => AetherError::InternalError {
                reason: "system clock is before Unix epoch".into(),
            },
            SignedPreKeyError::Corrupt => AetherError::Corrupt,
            SignedPreKeyError::Discovery(e) => e.into(),
            SignedPreKeyError::InboxRotationRequired => AetherError::InboxRotationRequired,
            SignedPreKeyError::InvalidData(reason) if reason.contains("unsupported") => {
                AetherError::UnsupportedVersion { reason }
            }
            SignedPreKeyError::InvalidData(reason) => AetherError::InvalidData { reason },
            SignedPreKeyError::LockPoisoned => AetherError::InternalError {
                reason: "internal lock poisoned".into(),
            },
            SignedPreKeyError::NotFound => AetherError::NotFound,
            SignedPreKeyError::Storage(e) => e.into(),
        }
    }
}

impl From<OneTimePreKeyError> for AetherError {
    fn from(e: OneTimePreKeyError) -> Self {
        match e {
            OneTimePreKeyError::Clock => AetherError::InternalError {
                reason: "system clock is before Unix epoch".into(),
            },
            OneTimePreKeyError::Discovery(e) => e.into(),
            OneTimePreKeyError::InboxRotationRequired => AetherError::InboxRotationRequired,
            OneTimePreKeyError::InvalidData(reason) if reason.contains("unsupported") => {
                AetherError::UnsupportedVersion { reason }
            }
            OneTimePreKeyError::InvalidData(reason) => AetherError::InvalidData { reason },
            OneTimePreKeyError::LockPoisoned => AetherError::InternalError {
                reason: "internal lock poisoned".into(),
            },
            OneTimePreKeyError::NotFound => AetherError::NotFound,
            OneTimePreKeyError::StaleEpoch => AetherError::InvalidData {
                reason: "one-time pre-key belongs to a superseded discovery-key epoch".into(),
            },
            OneTimePreKeyError::Storage(e) => e.into(),
        }
    }
}

impl From<DiscoveryKeyError> for AetherError {
    fn from(e: DiscoveryKeyError) -> Self {
        match e {
            DiscoveryKeyError::Clock => AetherError::InternalError {
                reason: "system clock is before Unix epoch".into(),
            },
            DiscoveryKeyError::Corrupt => AetherError::Corrupt,
            DiscoveryKeyError::Identity(e) => e.into(),
            DiscoveryKeyError::InvalidData(reason) if reason.contains("unsupported") => {
                AetherError::UnsupportedVersion { reason }
            }
            DiscoveryKeyError::InvalidData(reason) => AetherError::InvalidData { reason },
            DiscoveryKeyError::LockPoisoned => AetherError::InternalError {
                reason: "internal lock poisoned".into(),
            },
            DiscoveryKeyError::NotFound => AetherError::NotFound,
            DiscoveryKeyError::Storage(e) => e.into(),
        }
    }
}

impl From<StorageError> for AetherError {
    fn from(e: StorageError) -> Self {
        AetherError::Storage {
            reason: e.to_string(),
        }
    }
}

impl From<KeyStoreOperationError> for AetherError {
    fn from(e: KeyStoreOperationError) -> Self {
        match e {
            KeyStoreOperationError::Corrupt(_) => AetherError::Corrupt,
            KeyStoreOperationError::InvalidTransition { status, action } => {
                AetherError::OperationConflict {
                    reason: format!("cannot {action} operation in {status:?} state"),
                }
            }
            KeyStoreOperationError::LockPoisoned => AetherError::InternalError {
                reason: "prepared-operation lock poisoned".into(),
            },
            KeyStoreOperationError::NotFound => AetherError::NotFound,
            KeyStoreOperationError::PreconditionChanged { key } => {
                AetherError::SecureStoragePreconditionChanged { key }
            }
            KeyStoreOperationError::Randomness => AetherError::InternalError {
                reason: "operation identifier generation failed".into(),
            },
            KeyStoreOperationError::RecoveryRequired { identifier } => {
                AetherError::OperationRecoveryRequired {
                    operation_identifier: identifier.as_bytes().to_vec(),
                    reason: "recover the identified operation before continuing".into(),
                }
            }
            KeyStoreOperationError::Storage(e) => e.into(),
            KeyStoreOperationError::TooManyUnfinishedOperations => {
                AetherError::TooManyUnfinishedOperations
            }
        }
    }
}

impl From<KeyStoreError> for AetherError {
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

impl From<CryptoError> for AetherError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::Aead
            | CryptoError::HandshakeSignedPreKeyMismatch
            | CryptoError::NonContributorySharedSecret
            | CryptoError::OneTimePreKeyMismatch
            | CryptoError::SenderIdentityMismatch
            | CryptoError::SignatureInvalid => AetherError::AuthenticationFailed {
                reason: e.to_string(),
            },
            CryptoError::UnsupportedPreKeyBundleVersion(_)
            | CryptoError::UnsupportedRatchetVersion(_) => AetherError::UnsupportedVersion {
                reason: e.to_string(),
            },
            CryptoError::HandshakeEnvelopeDecode
            | CryptoError::HandshakeEnvelopeEncode
            | CryptoError::SealedFrameDecode
            | CryptoError::SealedFrameEncode
            | CryptoError::InvalidHmacKey
            | CryptoError::InvalidKeyEncoding
            | CryptoError::InvalidSignatureContext
            | CryptoError::InvalidState(_)
            | CryptoError::MaxSkipExceeded
            | CryptoError::MaxSkippedKeysExceeded
            | CryptoError::MissingOneTimePreKey
            | CryptoError::RatchetStateDecode
            | CryptoError::RatchetStateEncode
            | CryptoError::StalePreKey
            | CryptoError::HkdfExpand => AetherError::InvalidData {
                reason: e.to_string(),
            },
            _ => AetherError::InvalidData {
                reason: e.to_string(),
            },
        }
    }
}

impl From<MessageError> for AetherError {
    fn from(e: MessageError) -> Self {
        match e {
            MessageError::UnsupportedPayloadKind(_) | MessageError::UnsupportedVersion(_) => {
                AetherError::UnsupportedVersion {
                    reason: e.to_string(),
                }
            }
            MessageError::Decode
            | MessageError::EncodedTooLarge
            | MessageError::Encode
            | MessageError::InvalidPublicKey
            | MessageError::PayloadTooLarge => AetherError::InvalidData {
                reason: e.to_string(),
            },
        }
    }
}

impl From<ProtocolStateError> for AetherError {
    fn from(e: ProtocolStateError) -> Self {
        match &e {
            ProtocolStateError::SenderCertificateValidation(source) => {
                AetherError::CertificateRejected {
                    reason: source.to_string(),
                }
            }
            ProtocolStateError::UnsupportedBlobVersion { .. } => AetherError::UnsupportedVersion {
                reason: e.to_string(),
            },
            ProtocolStateError::MissingSenderCertificateValidation
            | ProtocolStateError::InvalidDeduplicationCapacity { .. }
            | ProtocolStateError::InvalidHardeningLimit { .. }
            | ProtocolStateError::InvalidMessage { .. }
            | ProtocolStateError::InvalidStateKey { .. }
            | ProtocolStateError::MessageEncode(_)
            | ProtocolStateError::RelayRoute(_) => AetherError::InvalidData {
                reason: e.to_string(),
            },
            ProtocolStateError::InvalidStateBinding { reason, .. }
                if reason.contains("blocked contact") =>
            {
                AetherError::BlockedContact {
                    reason: e.to_string(),
                }
            }
            ProtocolStateError::Crypto(source) => AetherError::from(source.clone_for_mapping()),
            _ => AetherError::ProtocolStateFault {
                reason: e.to_string(),
            },
        }
    }
}

impl From<SenderCertificateValidationError> for AetherError {
    fn from(e: SenderCertificateValidationError) -> Self {
        AetherError::CertificateRejected {
            reason: e.to_string(),
        }
    }
}

impl From<EvidenceVerificationError> for AetherError {
    fn from(e: EvidenceVerificationError) -> Self {
        match e {
            EvidenceVerificationError::BundleTooLarge
            | EvidenceVerificationError::MalformedBundle
            | EvidenceVerificationError::WrongProfile { .. }
            | EvidenceVerificationError::TooManyDomainSigningKeys { .. }
            | EvidenceVerificationError::GraceWindowTooLarge { .. } => AetherError::InvalidData {
                reason: e.to_string(),
            },
            EvidenceVerificationError::UnsupportedVersion(_) => AetherError::UnsupportedVersion {
                reason: e.to_string(),
            },
            EvidenceVerificationError::SenderCertificate(e) => e.into(),
            EvidenceVerificationError::SignatureFailure => AetherError::AuthenticationFailed {
                reason: e.to_string(),
            },
            _ => AetherError::InternalError {
                reason: e.to_string(),
            },
        }
    }
}

impl From<SafetyNumberError> for AetherError {
    fn from(e: SafetyNumberError) -> Self {
        AetherError::InvalidData {
            reason: e.to_string(),
        }
    }
}

impl From<SessionEstablishmentError> for AetherError {
    fn from(e: SessionEstablishmentError) -> Self {
        match e {
            SessionEstablishmentError::Crypto(e) => e.into(),
            SessionEstablishmentError::Discovery(e) => e.into(),
            SessionEstablishmentError::Identity(e) => e.into(),
            SessionEstablishmentError::Message(e) => e.into(),
            SessionEstablishmentError::OneTimePreKey(e) => e.into(),
            SessionEstablishmentError::Operation(e) => e.into(),
            SessionEstablishmentError::ProtocolState(e) => e.into(),
            SessionEstablishmentError::RelayRoute(e) => AetherError::InvalidData {
                reason: e.to_string(),
            },
            SessionEstablishmentError::SignedPreKey(e) => e.into(),
        }
    }
}

impl From<MessageOperationError> for AetherError {
    fn from(e: MessageOperationError) -> Self {
        match e {
            MessageOperationError::Discovery(e) => e.into(),
            MessageOperationError::Identity(e) => e.into(),
            MessageOperationError::Operation(e) => e.into(),
            MessageOperationError::ProtocolState(e) => e.into(),
        }
    }
}

trait CloneCryptoForMapping {
    fn clone_for_mapping(&self) -> CryptoError;
}

impl CloneCryptoForMapping for CryptoError {
    fn clone_for_mapping(&self) -> CryptoError {
        match self {
            CryptoError::Aead => CryptoError::Aead,
            CryptoError::HandshakeEnvelopeDecode => CryptoError::HandshakeEnvelopeDecode,
            CryptoError::HandshakeEnvelopeEncode => CryptoError::HandshakeEnvelopeEncode,
            CryptoError::SealedFrameDecode => CryptoError::SealedFrameDecode,
            CryptoError::SealedFrameEncode => CryptoError::SealedFrameEncode,
            CryptoError::HandshakeSignedPreKeyMismatch => {
                CryptoError::HandshakeSignedPreKeyMismatch
            }
            CryptoError::HkdfExpand => CryptoError::HkdfExpand,
            CryptoError::InvalidHmacKey => CryptoError::InvalidHmacKey,
            CryptoError::InvalidSignatureContext => CryptoError::InvalidSignatureContext,
            CryptoError::InvalidKeyEncoding => CryptoError::InvalidKeyEncoding,
            CryptoError::NonContributorySharedSecret => CryptoError::NonContributorySharedSecret,
            CryptoError::InvalidState(reason) => CryptoError::InvalidState(reason),
            CryptoError::MaxSkipExceeded => CryptoError::MaxSkipExceeded,
            CryptoError::MaxSkippedKeysExceeded => CryptoError::MaxSkippedKeysExceeded,
            CryptoError::MissingOneTimePreKey => CryptoError::MissingOneTimePreKey,
            CryptoError::OneTimePreKeyMismatch => CryptoError::OneTimePreKeyMismatch,
            CryptoError::SenderIdentityMismatch => CryptoError::SenderIdentityMismatch,
            CryptoError::RatchetStateDecode => CryptoError::RatchetStateDecode,
            CryptoError::RatchetStateEncode => CryptoError::RatchetStateEncode,
            CryptoError::SignatureInvalid => CryptoError::SignatureInvalid,
            CryptoError::StalePreKey => CryptoError::StalePreKey,
            CryptoError::UnsupportedRatchetVersion(version) => {
                CryptoError::UnsupportedRatchetVersion(*version)
            }
            CryptoError::UnsupportedPreKeyBundleVersion(version) => {
                CryptoError::UnsupportedPreKeyBundleVersion(*version)
            }
            _ => CryptoError::InvalidState("unknown crypto error"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decryption_failed_error_formats_are_redacted() {
        let err = AetherError::from(IdentityError::DecryptionFailed);
        let display = err.to_string();
        let debug = format!("{err:?}");

        assert_eq!(display, "decryption failed");
        assert!(!display.contains("passphrase"));
        assert!(!debug.contains("wrong-passphrase-secret"));
        assert!(!debug.contains("backup plaintext"));
    }

    #[test]
    fn backup_failed_error_formats_do_not_add_secret_context() {
        let err = AetherError::from(IdentityError::BackupFailed(
            "argon2 parameter rejected".into(),
        ));
        let display = err.to_string();
        let debug = format!("{err:?}");

        assert!(display.contains("argon2 parameter rejected"));
        assert!(!display.contains("passphrase"));
        assert!(!debug.contains("wrong-passphrase-secret"));
        assert!(!debug.contains("backup plaintext"));
    }
}
