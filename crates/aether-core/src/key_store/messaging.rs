use super::KeyStore;
use crate::{
    AcknowledgmentOutcome, DiscoveryKeyError, IdentityError, InboundAcknowledgmentMessage,
    InboundEncryptedMessage, InboundMessageOutcome, InboundSenderCertificateValidation,
    KeyStoreOperationError, Message, MessageId, OutboundAcknowledgment, OutboundMessageResult,
    OutboundPlaintext, ProtocolStateError, ProtocolStateKey, ProtocolStateSnapshot,
};
use aether_crypto::SenderIdentityMaterial;
use std::error::Error;
use std::fmt;

/// Inputs for encrypting an established-session Message with stored local identity material.
pub struct MessageEncryption<'a> {
    /// Consumer-held protocol-state snapshot.
    pub snapshot: &'a ProtocolStateSnapshot,
    /// Session-scoped protocol-state key.
    pub session_key: ProtocolStateKey,
    /// Stable Message identifier.
    pub message_id: MessageId,
    /// Recipient contact Identity Key.
    pub contact_identity_key: crate::ContactIdentityKey,
    /// Recipient Discovery Key X25519 public bytes.
    pub recipient_public_key: [u8; 32],
    /// Sender-observed Unix timestamp in milliseconds.
    pub timestamp_millis: u64,
    /// Opaque sender certificate sealed into the Message.
    pub sender_certificate: &'a [u8],
    /// Opaque sender signature sealed into the Message.
    pub sender_signature: &'a [u8],
    /// Plaintext bytes to encrypt.
    pub plaintext: &'a [u8],
}

/// Inputs for decrypting an established-session Message with stored local discovery material.
pub struct MessageDecryption<'a> {
    /// Consumer-held protocol-state snapshot.
    pub snapshot: &'a ProtocolStateSnapshot,
    /// Session-scoped protocol-state key.
    pub session_key: ProtocolStateKey,
    /// Identity-scoped deduplication-set key.
    pub deduplication_key: ProtocolStateKey,
    /// Encrypted Message to receive.
    pub message: &'a Message,
    /// Stable identifier for the acknowledgment Message to produce.
    pub acknowledgment_id: MessageId,
    /// Recipient Discovery Key X25519 public bytes for the produced acknowledgment.
    pub acknowledgment_recipient_public_key: [u8; 32],
    /// Receiver-observed Unix timestamp in milliseconds.
    pub acknowledgment_timestamp_millis: u64,
    /// Opaque receiver certificate sealed into the produced acknowledgment.
    pub acknowledgment_sender_certificate: &'a [u8],
    /// Opaque receiver signature sealed into the produced acknowledgment.
    pub acknowledgment_sender_signature: &'a [u8],
    /// Sender-certificate validation input for unique Messages.
    pub sender_certificate_validation: Option<InboundSenderCertificateValidation<'a>>,
}

/// Inputs for processing an encrypted acknowledgment with stored local discovery material.
pub struct AcknowledgmentProcessing<'a> {
    /// Consumer-held protocol-state snapshot.
    pub snapshot: &'a ProtocolStateSnapshot,
    /// Session-scoped protocol-state key.
    pub session_key: ProtocolStateKey,
    /// Encrypted acknowledgment Message.
    pub message: &'a Message,
}

/// Errors returned by established-session message helpers.
#[derive(Debug)]
pub enum MessageOperationError {
    /// Loading local discovery-key state failed.
    Discovery(DiscoveryKeyError),
    /// Loading local identity state failed.
    Identity(IdentityError),
    /// A committed KeyStore operation must be recovered before local keys can be used.
    Operation(KeyStoreOperationError),
    /// Protocol-state or message processing failed.
    ProtocolState(ProtocolStateError),
}

impl fmt::Display for MessageOperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discovery(e) => write!(f, "message operation discovery key: {e}"),
            Self::Identity(e) => write!(f, "message operation identity: {e}"),
            Self::Operation(e) => write!(f, "message operation prepared operation: {e}"),
            Self::ProtocolState(e) => write!(f, "message operation protocol state: {e}"),
        }
    }
}

impl Error for MessageOperationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Discovery(e) => Some(e),
            Self::Identity(e) => Some(e),
            Self::Operation(e) => Some(e),
            Self::ProtocolState(e) => Some(e),
        }
    }
}

impl From<DiscoveryKeyError> for MessageOperationError {
    fn from(e: DiscoveryKeyError) -> Self {
        Self::Discovery(e)
    }
}

impl From<IdentityError> for MessageOperationError {
    fn from(e: IdentityError) -> Self {
        Self::Identity(e)
    }
}

impl From<KeyStoreOperationError> for MessageOperationError {
    fn from(e: KeyStoreOperationError) -> Self {
        Self::Operation(e)
    }
}

impl From<ProtocolStateError> for MessageOperationError {
    fn from(e: ProtocolStateError) -> Self {
        Self::ProtocolState(e)
    }
}

impl KeyStore {
    /// Encrypts an established-session Message using stored local identity signing material.
    ///
    /// # Errors
    /// - [`MessageOperationError::Identity`] if local Identity material is missing or malformed.
    /// - [`MessageOperationError::Operation`] if a committed operation needs recovery.
    /// - [`MessageOperationError::ProtocolState`] if state loading, contact gating, encryption, or
    ///   update encoding fails.
    pub fn encrypt_message(
        &self,
        input: MessageEncryption<'_>,
    ) -> Result<OutboundMessageResult, MessageOperationError> {
        let _lifecycle = self.lifecycle_guard();
        self.ensure_no_recovery_required()?;
        let identity = self.0.identity.load_identity()?;
        let sender_identity =
            sender_identity_material(&identity, input.sender_certificate, input.sender_signature)?;
        Ok(crate::ProtocolStateEngine::new().encrypt_message(
            input.snapshot,
            input.session_key,
            OutboundPlaintext {
                id: input.message_id,
                sender_identity: &sender_identity,
                sender_identity_signing_key: identity.signing_key_pair(),
                contact_identity_key: input.contact_identity_key,
                recipient_public_key: input.recipient_public_key,
                timestamp_millis: input.timestamp_millis,
                plaintext: input.plaintext,
            },
        )?)
    }

    /// Decrypts an established-session Message using stored local discovery and identity material.
    ///
    /// # Errors
    /// - [`MessageOperationError::Discovery`] if local Discovery Key material is missing or
    ///   malformed.
    /// - [`MessageOperationError::Identity`] if local Identity material is missing or malformed.
    /// - [`MessageOperationError::Operation`] if a committed operation needs recovery.
    /// - [`MessageOperationError::ProtocolState`] if deduplication, decryption, sender-certificate
    ///   validation, acknowledgment encryption, or update encoding fails.
    pub fn decrypt_message(
        &self,
        input: MessageDecryption<'_>,
    ) -> Result<InboundMessageOutcome, MessageOperationError> {
        let _lifecycle = self.lifecycle_guard();
        self.ensure_no_recovery_required()?;
        let identity = self.0.identity.load_identity()?;
        let discovery_key = self.0.discovery.current()?;
        let sender_identity = sender_identity_material(
            &identity,
            input.acknowledgment_sender_certificate,
            input.acknowledgment_sender_signature,
        )?;
        let mut rng = rand::rngs::OsRng;
        Ok(crate::ProtocolStateEngine::new().decrypt_message(
            &mut rng,
            input.snapshot,
            InboundEncryptedMessage {
                session_key: input.session_key,
                deduplication_key: input.deduplication_key,
                message: input.message,
                recipient_discovery_key: &discovery_key,
                acknowledgment: OutboundAcknowledgment {
                    id: input.acknowledgment_id,
                    sender_identity: &sender_identity,
                    sender_identity_signing_key: identity.signing_key_pair(),
                    recipient_public_key: input.acknowledgment_recipient_public_key,
                    timestamp_millis: input.acknowledgment_timestamp_millis,
                },
                sender_certificate_validation: input.sender_certificate_validation,
            },
        )?)
    }

    /// Processes an encrypted acknowledgment using stored local discovery and identity material.
    ///
    /// # Errors
    /// - [`MessageOperationError::Discovery`] if local Discovery Key material is missing or
    ///   malformed.
    /// - [`MessageOperationError::Identity`] if local Identity material is missing or malformed.
    /// - [`MessageOperationError::Operation`] if a committed operation needs recovery.
    /// - [`MessageOperationError::ProtocolState`] if state loading, decryption, or update encoding
    ///   fails.
    pub fn process_acknowledgment(
        &self,
        input: AcknowledgmentProcessing<'_>,
    ) -> Result<AcknowledgmentOutcome, MessageOperationError> {
        let _lifecycle = self.lifecycle_guard();
        self.ensure_no_recovery_required()?;
        let identity = self.0.identity.load_identity()?;
        let discovery_key = self.0.discovery.current()?;
        let mut rng = rand::rngs::OsRng;
        Ok(crate::ProtocolStateEngine::new().process_acknowledgment(
            &mut rng,
            input.snapshot,
            InboundAcknowledgmentMessage {
                session_key: input.session_key,
                message: input.message,
                recipient_discovery_key: &discovery_key,
                recipient_identity_verifying_key: identity.verifying_key().to_bytes(),
            },
        )?)
    }
}

fn sender_identity_material(
    identity: &crate::Identity,
    certificate: &[u8],
    signature: &[u8],
) -> Result<SenderIdentityMaterial, IdentityError> {
    let bundle = identity.identity_key_bundle()?;
    Ok(SenderIdentityMaterial {
        identity_key: *bundle.public_key.as_bytes(),
        identity_verifying_key: bundle.verifying_key.to_bytes(),
        identity_binding_signature: bundle.binding_signature.to_bytes().to_vec(),
        certificate: certificate.to_vec(),
        signature: signature.to_vec(),
    })
}
