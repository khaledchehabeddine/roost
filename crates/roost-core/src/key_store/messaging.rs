use super::KeyStore;
use crate::{
    AcknowledgmentOutcome, DiscoveryKeyError, IdentityError, InboundAcknowledgmentMessage,
    InboundEncryptedMessage, InboundMessageOutcome, InboundSenderCertificateValidation,
    KeyStoreOperationError, Message, MessageId, OutboundAcknowledgment, OutboundMessageResult,
    OutboundPlaintext, ProtocolStateError, ProtocolStateKey, ProtocolStateSnapshot,
    TransportBinding,
};
use roost_crypto::SenderIdentityMaterial;
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
    pub sent_at_millis: u64,
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
    pub acknowledgment_sent_at_millis: u64,
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
    /// Encrypts an established-session Message while authenticating a Transport Binding.
    /// The caller must retain the exact binding with the returned Message for retransmission.
    ///
    /// # Examples
    /// ```
    /// use roost_core::{
    ///     KeyStore, MessageEncryption, MessageOperationError, OutboundMessageResult,
    ///     TransportBinding,
    /// };
    ///
    /// fn encrypt_bound_message(
    ///     store: &KeyStore,
    ///     input: MessageEncryption<'_>,
    ///     binding: TransportBinding,
    /// ) -> Result<(OutboundMessageResult, TransportBinding), MessageOperationError> {
    ///     let result = store.encrypt_message_with_transport_binding(input, &binding)?;
    ///     // Persist `result.state_updates`, `result.message`, and `binding` atomically before send.
    ///     Ok((result, binding))
    /// }
    /// ```
    pub fn encrypt_message_with_transport_binding(
        &self,
        input: MessageEncryption<'_>,
        transport_binding: &TransportBinding,
    ) -> Result<OutboundMessageResult, MessageOperationError> {
        let _lifecycle = self.lifecycle_guard();
        self.ensure_no_recovery_required()?;
        let identity = self.0.identity.load_identity()?;
        let sender_identity =
            sender_identity_material(&identity, input.sender_certificate, input.sender_signature)?;
        let plaintext = OutboundPlaintext {
            id: input.message_id,
            sender_identity: &sender_identity,
            sender_identity_signing_key: identity.signing_key_pair(),
            contact_identity_key: input.contact_identity_key,
            recipient_public_key: input.recipient_public_key,
            sent_at_millis: input.sent_at_millis,
            plaintext: input.plaintext,
        };
        let engine = &self.0.engine;
        Ok(engine.encrypt_message_with_transport_binding(
            input.snapshot,
            input.session_key,
            plaintext,
            transport_binding,
        )?)
    }

    /// Decrypts an established-session Message and authenticates its Transport Binding plus the
    /// binding used for the returned acknowledgment.
    /// The caller must retain `acknowledgment_transport_binding` with that acknowledgment.
    pub fn decrypt_message_with_transport_bindings(
        &self,
        input: MessageDecryption<'_>,
        message_transport_binding: &TransportBinding,
        acknowledgment_transport_binding: &TransportBinding,
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
        let inbound = InboundEncryptedMessage {
            session_key: input.session_key,
            deduplication_key: input.deduplication_key,
            message: input.message,
            recipient_discovery_key: &discovery_key,
            recipient_identity_verifying_key: identity.verifying_key().to_bytes(),
            acknowledgment: OutboundAcknowledgment {
                id: input.acknowledgment_id,
                sender_identity: &sender_identity,
                sender_identity_signing_key: identity.signing_key_pair(),
                recipient_public_key: input.acknowledgment_recipient_public_key,
                sent_at_millis: input.acknowledgment_sent_at_millis,
            },
            sender_certificate_validation: input.sender_certificate_validation,
        };
        let engine = &self.0.engine;
        Ok(engine.decrypt_message_with_transport_bindings(
            &mut rng,
            input.snapshot,
            inbound,
            message_transport_binding,
            acknowledgment_transport_binding,
        )?)
    }

    /// Processes an encrypted acknowledgment while authenticating its Transport Binding.
    pub fn process_acknowledgment_with_transport_binding(
        &self,
        input: AcknowledgmentProcessing<'_>,
        transport_binding: &TransportBinding,
    ) -> Result<AcknowledgmentOutcome, MessageOperationError> {
        let _lifecycle = self.lifecycle_guard();
        self.ensure_no_recovery_required()?;
        let identity = self.0.identity.load_identity()?;
        let discovery_key = self.0.discovery.current()?;
        let mut rng = rand::rngs::OsRng;
        let inbound = InboundAcknowledgmentMessage {
            session_key: input.session_key,
            message: input.message,
            recipient_discovery_key: &discovery_key,
            recipient_identity_verifying_key: identity.verifying_key().to_bytes(),
        };
        let engine = &self.0.engine;
        Ok(engine.process_acknowledgment_with_transport_binding(
            &mut rng,
            input.snapshot,
            inbound,
            transport_binding,
        )?)
    }
}

fn sender_identity_material(
    identity: &crate::Identity,
    certificate: &[u8],
    signature: &[u8],
) -> Result<SenderIdentityMaterial, IdentityError> {
    let bundle = identity.public()?;
    Ok(SenderIdentityMaterial {
        identity_key: *bundle.public_key.as_bytes(),
        identity_verifying_key: bundle.verifying_key.to_bytes(),
        identity_binding_signature: bundle.binding_signature.to_bytes().to_vec(),
        certificate: certificate.to_vec(),
        signature: signature.to_vec(),
    })
}
