//! Error mapping for failures crossing the UniFFI boundary.

use roost_core::CryptoError;
use roost_core::{
    DiscoveryKeyError, IdentityError, KeyStoreError, KeyStoreOperationError, MessageError,
    MessageOperationError, OneTimePreKeyError, ProtocolStateError, SafetyNumberError,
    SessionEstablishmentError, SignedPreKeyError, StorageError, TransportBindingError,
};
use roost_protocol::{EvidenceVerificationError, SenderCertificateValidationError};

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
    /// A contact-event snapshot belongs to another event stream.
    ForeignEventSnapshot,
    /// A contact-event snapshot predates the latest imported current state.
    StaleEventSnapshot {
        /// State revision carried by the rejected snapshot.
        snapshot_revision: u64,
        /// Latest state revision held by the stream.
        current_revision: u64,
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
            ClientError::Corrupt => write!(f, "stored key material is corrupt"),
            ClientError::DecryptionFailed => write!(f, "decryption failed"),
            ClientError::EventStreamClosed => write!(f, "event stream observer is closed"),
            ClientError::EventLag { missed } => write!(f, "event stream observer lagged: {missed}"),
            ClientError::ForeignEventSnapshot => {
                write!(f, "event snapshot belongs to another stream")
            }
            ClientError::StaleEventSnapshot {
                snapshot_revision,
                current_revision,
            } => write!(
                f,
                "stale event snapshot revision {snapshot_revision}; current revision is {current_revision}"
            ),
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
            IdentityError::InvalidData(reason) if reason.contains("unsupported") => {
                ClientError::UnsupportedVersion { reason }
            }
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
            SignedPreKeyError::InvalidData(reason) if reason.contains("unsupported") => {
                ClientError::UnsupportedVersion { reason }
            }
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
            OneTimePreKeyError::InvalidData(reason) if reason.contains("unsupported") => {
                ClientError::UnsupportedVersion { reason }
            }
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
            DiscoveryKeyError::InvalidData(reason) if reason.contains("unsupported") => {
                ClientError::UnsupportedVersion { reason }
            }
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
            KeyStoreOperationError::RecoveryRequired { identifier } => {
                ClientError::OperationRecoveryRequired {
                    operation_identifier: identifier.as_bytes().to_vec(),
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

impl From<CryptoError> for ClientError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::Aead
            | CryptoError::HandshakeSignedPreKeyMismatch
            | CryptoError::NonContributorySharedSecret
            | CryptoError::OneTimePreKeyMismatch
            | CryptoError::SenderIdentityMismatch
            | CryptoError::SignatureInvalid => ClientError::AuthenticationFailed {
                reason: e.to_string(),
            },
            CryptoError::UnsupportedPreKeyBundleVersion(_)
            | CryptoError::UnsupportedRatchetVersion(_) => ClientError::UnsupportedVersion {
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
            | CryptoError::HkdfExpand => ClientError::InvalidData {
                reason: e.to_string(),
            },
            _ => ClientError::InvalidData {
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
            MessageError::Decode
            | MessageError::EncodedTooLarge
            | MessageError::Encode
            | MessageError::InvalidPublicKey
            | MessageError::PayloadTooLarge => ClientError::InvalidData {
                reason: e.to_string(),
            },
        }
    }
}

impl From<ProtocolStateError> for ClientError {
    fn from(e: ProtocolStateError) -> Self {
        match &e {
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
            | ProtocolStateError::InvalidStateKey { .. }
            | ProtocolStateError::MessageEncode(_) => ClientError::InvalidData {
                reason: e.to_string(),
            },
            ProtocolStateError::InvalidStateBinding { reason, .. }
                if reason.contains("blocked contact") =>
            {
                ClientError::BlockedContact {
                    reason: e.to_string(),
                }
            }
            ProtocolStateError::Crypto(source) => ClientError::from(source.clone_for_mapping()),
            _ => ClientError::ProtocolStateFault {
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
            _ => ClientError::InternalError {
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
            SessionEstablishmentError::Crypto(e) => e.into(),
            SessionEstablishmentError::Discovery(e) => e.into(),
            SessionEstablishmentError::Identity(e) => e.into(),
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
        let err = ClientError::from(IdentityError::DecryptionFailed);
        let display = err.to_string();
        let debug = format!("{err:?}");

        assert_eq!(display, "decryption failed");
        assert!(!display.contains("passphrase"));
        assert!(!debug.contains("wrong-passphrase-secret"));
        assert!(!debug.contains("backup plaintext"));
    }

    #[test]
    fn backup_failed_error_formats_do_not_add_secret_context() {
        let err = ClientError::from(IdentityError::BackupFailed(
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
