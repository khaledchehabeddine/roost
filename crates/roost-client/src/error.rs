use roost_core::{
    ContactPublicationError, DiscoveryKeyError, HandshakeError, IdentityError, KeyStoreError,
    KeyStoreOperationError, MessageOperationError, MessageStartError, OneTimePreKeyError,
    ProtocolStateError, PublicKeyError, RatchetError, RatchetStateError, SafetyNumberError,
    SealedFrameError, SignedPreKeyError, StateEntryError, StorageError, StoredDataError,
    TransportBindingError,
};
use roost_protocol::{SenderCertificateValidationError, SignatureError};

/// The error Roost's calls throw.
///
/// Each variant is a failure the host handles differently. `reason` fields are diagnostic strings
/// for logs and must not drive application logic.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum RoostError {
    /// An identity already exists in storage.
    #[error("identity already exists")]
    AlreadyExists,
    /// Cryptographic authentication or decryption failed.
    #[error("authentication failed: {reason}")]
    AuthenticationFailed {
        /// Diagnostic context for logging only.
        reason: String,
    },
    /// Encrypted backup creation failed during randomness, key derivation, or encryption.
    #[error("backup failed: {reason}")]
    BackupFailed {
        /// Diagnostic failure context for logs only.
        reason: String,
    },
    /// A contact is locally blocked.
    #[error("blocked contact: {reason}")]
    BlockedContact {
        /// Diagnostic context for logging only.
        reason: String,
    },
    /// Sender certificate validation rejected the certificate.
    #[error("certificate rejected: {reason}")]
    CertificateRejected {
        /// Diagnostic context for logging only.
        reason: String,
    },
    /// The contact isn't accepted, so Roost refuses the send: this side already sent the most
    /// messages allowed before acceptance, no session exists to send on, or a grant update would
    /// give a requester this side hasn't accepted its inbox grant.
    #[error("contact is not accepted: {reason}")]
    ContactNotAccepted {
        /// Diagnostic context for logging only.
        reason: String,
    },
    /// Stored discovery key, signed prekey, or prepared-operation material is corrupt.
    #[error("stored key material is corrupt")]
    Corrupt,
    /// Backup decryption failed because the passphrase or backup bytes did not authenticate.
    #[error("decryption failed")]
    DecryptionFailed,
    /// Internal failure that does not expose a more specific failure category.
    #[error("internal error: {reason}")]
    InternalError {
        /// Diagnostic context for logging only.
        reason: String,
    },
    /// Input bytes are malformed or the wrong length.
    #[error("invalid data: {reason}")]
    InvalidData {
        /// Description of what was invalid for logging only.
        reason: String,
    },
    /// A restored identity must rotate its inbox before using prekeys.
    #[error("inbox rotation required after backup restore")]
    InboxRotationRequired,
    /// An established message needs the contact's delivery capability, and no inbox grant from
    /// the contact has supplied one for its current discovery key.
    #[error("no delivery capability for this contact")]
    NoDeliveryCapability,
    /// Requested identity, discovery key, or prekey material is not stored.
    #[error("key material not found")]
    NotFound,
    /// A different first message already used the one-time prekey this one names, so Roost refuses
    /// it.
    #[error("one-time prekey already used: {reason}")]
    OneTimePreKeyUsed {
        /// Diagnostic context for logging only.
        reason: String,
    },
    /// A message operation already returned its result or failed, so start a new one from fresh
    /// reads.
    #[error("message operation has finished")]
    OperationFinished,
    /// The requested prepared-operation transition conflicts with its durable state.
    #[error("prepared-operation conflict: {reason}")]
    OperationConflict {
        /// Diagnostic context for logging only.
        reason: String,
    },
    /// A reserved or finalizing operation must be finalized or aborted before other work.
    #[error("prepared-operation recovery required: {reason}")]
    OperationRecoveryRequired {
        /// The operation to recover.
        operation_id: crate::OperationId,
        /// Diagnostic context for logging only.
        reason: String,
    },
    /// Protocol-state load, decode, encode, binding, or missing-state fault.
    #[error("protocol-state fault: {reason}")]
    ProtocolStateFault {
        /// Diagnostic context for logging only.
        reason: String,
    },
    /// Underlying [`SecureStorage`](crate::SecureStorage) returned a platform error.
    #[error("storage error: {reason}")]
    Storage {
        /// What Roost was storing, followed by the message the
        /// [`SecureStorage`](crate::SecureStorage) implementation returned.
        reason: String,
    },
    /// A SecureStorage entry that a prepared operation read changed before the operation was
    /// reserved.
    #[error("secure-storage precondition changed for {key}")]
    SecureStoragePreconditionChanged {
        /// Stable SecureStorage entry name that changed.
        key: String,
    },
    /// The bounded prepared-operation journal has no free unfinished-operation slot.
    #[error("too many unfinished prepared operations")]
    TooManyUnfinishedOperations,
    /// The most sent messages allowed already wait for the contact's acknowledgment on the
    /// session, so Roost refuses another. Keep the draft and send it once the contact acknowledges
    /// some, or a delivery check gives up on them.
    #[error("{limit} messages already wait for an acknowledgment")]
    TooManyPendingAcknowledgments {
        /// Most messages that wait for an acknowledgment on one session.
        limit: u64,
    },
    /// A message, sender certificate, blob, backup, or prekey version is unsupported.
    #[error("unsupported version: {reason}")]
    UnsupportedVersion {
        /// Diagnostic context for logging only.
        reason: String,
    },
}

impl RoostError {
    // Replaces the reason of a variant that carries one, keeping the variant itself.
    fn with_reason(mut self, new_reason: String) -> Self {
        match &mut self {
            RoostError::AuthenticationFailed { reason }
            | RoostError::BackupFailed { reason }
            | RoostError::BlockedContact { reason }
            | RoostError::CertificateRejected { reason }
            | RoostError::ContactNotAccepted { reason }
            | RoostError::InternalError { reason }
            | RoostError::InvalidData { reason }
            | RoostError::OneTimePreKeyUsed { reason }
            | RoostError::OperationConflict { reason }
            | RoostError::OperationRecoveryRequired { reason, .. }
            | RoostError::ProtocolStateFault { reason }
            | RoostError::Storage { reason }
            | RoostError::UnsupportedVersion { reason } => *reason = new_reason,
            RoostError::AlreadyExists
            | RoostError::Corrupt
            | RoostError::DecryptionFailed
            | RoostError::InboxRotationRequired
            | RoostError::NoDeliveryCapability
            | RoostError::NotFound
            | RoostError::OperationFinished
            | RoostError::SecureStoragePreconditionChanged { .. }
            | RoostError::TooManyPendingAcknowledgments { .. }
            | RoostError::TooManyUnfinishedOperations => {}
        }
        self
    }

    // Encoded data this build has no reader for is an unsupported version, data that fails to
    // decode is invalid, and a value that fails to encode is a bug.
    fn from_stored_data(error: &StoredDataError, reason: String) -> Self {
        match error {
            StoredDataError::UnsupportedVersion(_) => RoostError::UnsupportedVersion { reason },
            StoredDataError::Decode(_) | StoredDataError::TrailingBytes { .. } => {
                RoostError::InvalidData { reason }
            }
            StoredDataError::Encode(_) => RoostError::InternalError { reason },
        }
    }
}

/// Returns `error`'s message followed by each source's message, outermost first.
pub(crate) fn reason_from_chain(error: &dyn std::error::Error) -> String {
    let mut reason = error.to_string();
    let mut source = error.source();
    while let Some(error) = source {
        reason.push_str(": ");
        reason.push_str(&error.to_string());
        source = error.source();
    }
    reason
}

// SecureStorage is the only foreign trait, so a callback that throws something other than a
// `RoostError` is a storage failure.
impl From<uniffi::UnexpectedUniFFICallbackError> for RoostError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        RoostError::Storage {
            reason: error.reason,
        }
    }
}

impl From<IdentityError> for RoostError {
    fn from(e: IdentityError) -> Self {
        let reason = reason_from_chain(&e);
        match e {
            IdentityError::AlreadyExists => RoostError::AlreadyExists,
            IdentityError::BackupEncryption
            | IdentityError::BackupKeyDerivation(_)
            | IdentityError::BackupRandomness(_) => RoostError::BackupFailed { reason },
            IdentityError::BackupFormat(error) | IdentityError::SecretBlob(error) => {
                RoostError::from_stored_data(&error, reason)
            }
            IdentityError::DecryptionFailed => RoostError::DecryptionFailed,
            IdentityError::BackupParametersOutOfRange { .. }
            | IdentityError::BindingSignature(_) => RoostError::InvalidData { reason },
            IdentityError::LockPoisoned => RoostError::InternalError { reason },
            IdentityError::NotFound => RoostError::NotFound,
            IdentityError::Storage(_) => RoostError::Storage { reason },
        }
    }
}

impl From<SignedPreKeyError> for RoostError {
    fn from(e: SignedPreKeyError) -> Self {
        let reason = reason_from_chain(&e);
        match e {
            SignedPreKeyError::Clock
            | SignedPreKeyError::LockPoisoned
            | SignedPreKeyError::SignedPreKeySignature(_) => RoostError::InternalError { reason },
            SignedPreKeyError::Corrupt => RoostError::Corrupt,
            SignedPreKeyError::Discovery(e) => RoostError::from(e).with_reason(reason),
            SignedPreKeyError::InboxRotationRequired => RoostError::InboxRotationRequired,
            SignedPreKeyError::StoredData(error) => RoostError::from_stored_data(&error, reason),
            SignedPreKeyError::DuplicateRetainedId(_)
            | SignedPreKeyError::IdentifiersExhausted
            | SignedPreKeyError::NextIdMismatch { .. }
            | SignedPreKeyError::RetainedCapacityReached { .. }
            | SignedPreKeyError::RetainedEpochMismatch { .. }
            | SignedPreKeyError::RetainedIdNotOlder { .. } => RoostError::InvalidData { reason },
            SignedPreKeyError::NotFound => RoostError::NotFound,
            SignedPreKeyError::Storage(_) => RoostError::Storage { reason },
        }
    }
}

impl From<OneTimePreKeyError> for RoostError {
    fn from(e: OneTimePreKeyError) -> Self {
        let reason = reason_from_chain(&e);
        match e {
            OneTimePreKeyError::LockPoisoned => RoostError::InternalError { reason },
            OneTimePreKeyError::Discovery(e) => RoostError::from(e).with_reason(reason),
            OneTimePreKeyError::InboxRotationRequired => RoostError::InboxRotationRequired,
            OneTimePreKeyError::StoredData(error) => RoostError::from_stored_data(&error, reason),
            OneTimePreKeyError::BatchExceedsCapacity { .. }
            | OneTimePreKeyError::DuplicateId(_)
            | OneTimePreKeyError::IdentifiersExhausted
            | OneTimePreKeyError::IdNotBelowNextId { .. }
            | OneTimePreKeyError::StaleEpoch { .. } => RoostError::InvalidData { reason },
            OneTimePreKeyError::NotFound => RoostError::NotFound,
            OneTimePreKeyError::Used { .. } => RoostError::OneTimePreKeyUsed { reason },
            OneTimePreKeyError::Storage(_) => RoostError::Storage { reason },
        }
    }
}

impl From<DiscoveryKeyError> for RoostError {
    fn from(e: DiscoveryKeyError) -> Self {
        let reason = reason_from_chain(&e);
        match e {
            DiscoveryKeyError::Clock
            | DiscoveryKeyError::LockPoisoned
            | DiscoveryKeyError::DiscoveryKeySignature(_) => RoostError::InternalError { reason },
            DiscoveryKeyError::Corrupt => RoostError::Corrupt,
            DiscoveryKeyError::Identity(e) => RoostError::from(e).with_reason(reason),
            DiscoveryKeyError::StoredData(error) => RoostError::from_stored_data(&error, reason),
            DiscoveryKeyError::IdentityBindingSignature(_) => RoostError::InvalidData { reason },
            DiscoveryKeyError::NotFound => RoostError::NotFound,
            DiscoveryKeyError::Storage(_) => RoostError::Storage { reason },
        }
    }
}

impl From<ContactPublicationError> for RoostError {
    fn from(e: ContactPublicationError) -> Self {
        let reason = reason_from_chain(&e);
        match e {
            ContactPublicationError::Format(error) => RoostError::from_stored_data(&error, reason),
            ContactPublicationError::Key(e) => RoostError::from(e).with_reason(reason),
            ContactPublicationError::NotCanonical
            | ContactPublicationError::VersionBeforeFirst(_) => RoostError::InvalidData { reason },
        }
    }
}

impl From<StorageError> for RoostError {
    fn from(e: StorageError) -> Self {
        RoostError::Storage {
            reason: reason_from_chain(&e),
        }
    }
}

impl From<KeyStoreOperationError> for RoostError {
    fn from(e: KeyStoreOperationError) -> Self {
        let reason = reason_from_chain(&e);
        match e {
            KeyStoreOperationError::Corrupt(_) => RoostError::Corrupt,
            KeyStoreOperationError::InvalidTransition { .. } => {
                RoostError::OperationConflict { reason }
            }
            KeyStoreOperationError::IdCollision
            | KeyStoreOperationError::LockPoisoned
            | KeyStoreOperationError::Randomness(_) => RoostError::InternalError { reason },
            KeyStoreOperationError::NotFound => RoostError::NotFound,
            KeyStoreOperationError::PreconditionChanged { key } => {
                RoostError::SecureStoragePreconditionChanged { key }
            }
            KeyStoreOperationError::RecoveryRequired { id } => {
                RoostError::OperationRecoveryRequired {
                    operation_id: crate::OperationId::from_core(id),
                    reason,
                }
            }
            KeyStoreOperationError::Storage(_) => RoostError::Storage { reason },
            KeyStoreOperationError::TooManyUnfinishedOperations => {
                RoostError::TooManyUnfinishedOperations
            }
        }
    }
}

// `KeyStoreError`, `MessageStartError`, and `MessageOperationError` are transparent, so the inner
// error's chain is already the whole chain.
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
        let reason = reason_from_chain(&e);
        match e {
            HandshakeError::PublicKey(e) => RoostError::from(e).with_reason(reason),
            HandshakeError::Ratchet(e) => RoostError::from(e).with_reason(reason),
            HandshakeError::NonContributorySharedSecret
            | HandshakeError::OneTimePreKeyMismatch
            | HandshakeError::SenderProofInvalid
            | HandshakeError::SignedPreKeyMismatch => RoostError::AuthenticationFailed { reason },
            HandshakeError::UnsupportedPreKeyBundleVersion { .. } => {
                RoostError::UnsupportedVersion { reason }
            }
            HandshakeError::HkdfExpand => RoostError::InternalError { reason },
            HandshakeError::DiscoveryKeyMismatch
            | HandshakeError::MissingOneTimePreKey
            | HandshakeError::SenderProofFieldTooLong { .. }
            | HandshakeError::StalePreKey { .. } => RoostError::InvalidData { reason },
        }
    }
}

impl From<PublicKeyError> for RoostError {
    fn from(e: PublicKeyError) -> Self {
        let reason = reason_from_chain(&e);
        match e {
            PublicKeyError::Signature(e) => RoostError::from(e).with_reason(reason),
            PublicKeyError::InvalidKeyEncoding => RoostError::InvalidData { reason },
        }
    }
}

impl From<RatchetError> for RoostError {
    fn from(e: RatchetError) -> Self {
        let reason = reason_from_chain(&e);
        match e {
            RatchetError::Aead | RatchetError::NonContributorySharedSecret => {
                RoostError::AuthenticationFailed { reason }
            }
            RatchetError::HkdfExpand | RatchetError::InvalidHmacKey => {
                RoostError::InternalError { reason }
            }
            RatchetError::InvalidState(_)
            | RatchetError::MaxSkipExceeded { .. }
            | RatchetError::MaxSkippedKeysExceeded { .. } => RoostError::InvalidData { reason },
        }
    }
}

impl From<RatchetStateError> for RoostError {
    fn from(e: RatchetStateError) -> Self {
        let reason = reason_from_chain(&e);
        match e {
            RatchetStateError::Encode => RoostError::InternalError { reason },
            RatchetStateError::Decode
            | RatchetStateError::MaxSkippedKeysExceeded { .. }
            | RatchetStateError::TrailingBytes { .. } => RoostError::InvalidData { reason },
        }
    }
}

impl From<SealedFrameError> for RoostError {
    fn from(e: SealedFrameError) -> Self {
        let reason = reason_from_chain(&e);
        match e {
            SealedFrameError::Aead | SealedFrameError::NonContributorySharedSecret => {
                RoostError::AuthenticationFailed { reason }
            }
            SealedFrameError::Encode | SealedFrameError::HkdfExpand => {
                RoostError::InternalError { reason }
            }
            SealedFrameError::UnsupportedVersion { .. } => {
                RoostError::UnsupportedVersion { reason }
            }
            SealedFrameError::CiphertextTooLong { .. }
            | SealedFrameError::Decode
            | SealedFrameError::FrameTooLong { .. }
            | SealedFrameError::InvalidPublicKey
            | SealedFrameError::RecipientMismatch
            | SealedFrameError::TrailingBytes { .. } => RoostError::InvalidData { reason },
        }
    }
}

impl From<SignatureError> for RoostError {
    fn from(e: SignatureError) -> Self {
        let reason = reason_from_chain(&e);
        match e {
            SignatureError::SignatureInvalid => RoostError::AuthenticationFailed { reason },
            SignatureError::InvalidSignatureContext | SignatureError::MessageTooLong { .. } => {
                RoostError::InvalidData { reason }
            }
        }
    }
}

impl From<ProtocolStateError> for RoostError {
    fn from(e: ProtocolStateError) -> Self {
        let reason = reason_from_chain(&e);
        match e {
            ProtocolStateError::SenderCertificateValidation(e) => {
                RoostError::from(e).with_reason(reason)
            }
            ProtocolStateError::UnsupportedBlobVersion { .. } => {
                RoostError::UnsupportedVersion { reason }
            }
            ProtocolStateError::InvalidDeduplicationCapacity { .. }
            | ProtocolStateError::InvalidMessage { .. }
            | ProtocolStateError::ContentTooLong { .. }
            | ProtocolStateError::EmptyStateKey
            | ProtocolStateError::MessageTranscript(_)
            | ProtocolStateError::NoContactRequest
            | ProtocolStateError::SealedPayload(_)
            | ProtocolStateError::SnapshotCapacityExceeded { .. }
            | ProtocolStateError::StateKeyTooLong { .. }
            | ProtocolStateError::StateEntry(_)
            | ProtocolStateError::TimeOutOfRange
            | ProtocolStateError::UnsolicitedAcceptance => RoostError::InvalidData { reason },
            ProtocolStateError::InvalidInboxGrant => RoostError::AuthenticationFailed { reason },
            ProtocolStateError::BlockedContact => RoostError::BlockedContact { reason },
            ProtocolStateError::ContactNotAccepted
            | ProtocolStateError::PendingLimitReached { .. } => {
                RoostError::ContactNotAccepted { reason }
            }
            ProtocolStateError::NoDeliveryCapability => RoostError::NoDeliveryCapability,
            // Every limit is a fixed constant well inside `u64`.
            ProtocolStateError::PendingAcknowledgmentLimitReached { limit } => {
                RoostError::TooManyPendingAcknowledgments {
                    limit: limit as u64,
                }
            }
            ProtocolStateError::Handshake(e) => RoostError::from(e).with_reason(reason),
            ProtocolStateError::BlobEncode { .. } | ProtocolStateError::Randomness(_) => {
                RoostError::InternalError { reason }
            }
            ProtocolStateError::Ratchet(e) => RoostError::from(e).with_reason(reason),
            ProtocolStateError::RatchetState(e) => RoostError::from(e).with_reason(reason),
            ProtocolStateError::SealedFrame(e) => RoostError::from(e).with_reason(reason),
            ProtocolStateError::Signature(e) => RoostError::from(e).with_reason(reason),
            ProtocolStateError::BlobDecode { .. }
            | ProtocolStateError::InvalidStateBinding { .. }
            | ProtocolStateError::MissingRequiredState { .. } => {
                RoostError::ProtocolStateFault { reason }
            }
        }
    }
}

impl From<SenderCertificateValidationError> for RoostError {
    fn from(e: SenderCertificateValidationError) -> Self {
        let reason = reason_from_chain(&e);
        match e {
            // These errors come from the app's own inputs, not from the certificate.
            SenderCertificateValidationError::GraceWindowTooLarge { .. }
            | SenderCertificateValidationError::EmptySigningKeyId { .. }
            | SenderCertificateValidationError::DuplicateSigningKeyId { .. }
            | SenderCertificateValidationError::InvalidDomainSigningKey { .. }
            | SenderCertificateValidationError::EmptyRelayDomain
            | SenderCertificateValidationError::InvalidRevokedIdentityKey { .. } => {
                RoostError::InvalidData { reason }
            }
            SenderCertificateValidationError::UnsupportedVersion { .. } => {
                RoostError::UnsupportedVersion { reason }
            }
            SenderCertificateValidationError::MalformedCertificate
            | SenderCertificateValidationError::CertificateTooLong { .. }
            | SenderCertificateValidationError::RelayDomainMismatch
            | SenderCertificateValidationError::InvalidKeyEncoding
            | SenderCertificateValidationError::UnknownSigningKeyId
            | SenderCertificateValidationError::SignatureFailure
            | SenderCertificateValidationError::RevocationStateUnavailable
            | SenderCertificateValidationError::RevokedIdentityKey
            | SenderCertificateValidationError::ExpiredCertificate => {
                RoostError::CertificateRejected { reason }
            }
        }
    }
}

impl From<SafetyNumberError> for RoostError {
    fn from(e: SafetyNumberError) -> Self {
        RoostError::InvalidData {
            reason: reason_from_chain(&e),
        }
    }
}

impl From<MessageStartError> for RoostError {
    fn from(e: MessageStartError) -> Self {
        match e {
            MessageStartError::Discovery(e) => e.into(),
            MessageStartError::Identity(e) => e.into(),
            MessageStartError::Operation(e) => e.into(),
            MessageStartError::ProtocolState(e) => e.into(),
        }
    }
}

impl From<MessageOperationError> for RoostError {
    fn from(e: MessageOperationError) -> Self {
        let reason = reason_from_chain(&e);
        match e {
            MessageOperationError::Finished => RoostError::OperationFinished,
            MessageOperationError::NotAwaitingAdmission
            | MessageOperationError::NotAwaitingContent
            | MessageOperationError::NotAwaitingState
            | MessageOperationError::NotAwaitingTransportBinding => {
                RoostError::InvalidData { reason }
            }
            MessageOperationError::KeyStore(e) => e.into(),
            MessageOperationError::ProtocolState(e) => e.into(),
        }
    }
}

impl From<StateEntryError> for RoostError {
    fn from(e: StateEntryError) -> Self {
        RoostError::InvalidData {
            reason: reason_from_chain(&e),
        }
    }
}

impl From<TransportBindingError> for RoostError {
    fn from(e: TransportBindingError) -> Self {
        RoostError::InvalidData {
            reason: reason_from_chain(&e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_acknowledgment_limit_has_its_own_variant() {
        assert!(matches!(
            RoostError::from(ProtocolStateError::PendingAcknowledgmentLimitReached { limit: 1024 }),
            RoostError::TooManyPendingAcknowledgments { limit: 1024 }
        ));
    }

    #[test]
    fn unexpected_storage_callback_failure_keeps_the_host_reason() {
        assert!(matches!(
            RoostError::from(uniffi::UnexpectedUniFFICallbackError::new("disk full")),
            RoostError::Storage { reason } if reason == "disk full"
        ));
    }

    #[test]
    fn message_input_rejections_remain_invalid_data_across_protocol_error_boundary() {
        for error in [
            SealedFrameError::CiphertextTooLong { len: 2, max: 1 },
            SealedFrameError::FrameTooLong { len: 2, max: 1 },
            SealedFrameError::InvalidPublicKey,
        ] {
            assert!(matches!(
                RoostError::from(ProtocolStateError::SealedFrame(error)),
                RoostError::InvalidData { .. }
            ));
        }
    }

    #[test]
    fn an_unknown_backup_version_is_an_unsupported_version() {
        assert!(matches!(
            RoostError::from(KeyStoreError::Identity(IdentityError::BackupFormat(
                StoredDataError::UnsupportedVersion(0xff)
            ))),
            RoostError::UnsupportedVersion { .. }
        ));
    }

    #[test]
    fn an_unknown_sender_certificate_version_is_an_unsupported_version() {
        assert!(matches!(
            RoostError::from(ProtocolStateError::SenderCertificateValidation(
                SenderCertificateValidationError::UnsupportedVersion { version: 2 }
            )),
            RoostError::UnsupportedVersion { .. }
        ));
    }
}
