use super::KeyStore;
use crate::{
    AcknowledgmentOutcome, DiscoveryKeyError, IdentityError, InboundAcknowledgmentMessage,
    InboundEncryptedMessage, InboundMessageOutcome, InboundSenderCertificateValidation,
    KeyStoreOperationError, LocalSender, Message, MessageId, OutboundAcknowledgment,
    OutboundMessageResult, OutboundPlaintext, ProtocolStateError, ProtocolStateKey,
    ProtocolStateSnapshot, SenderIdentityMaterial, TransportBinding,
};
use rand::rngs::OsRng;
use roost_crypto::{PublicDiscoveryKey, Signature};

/// Inputs for encrypting a Message to a contact with stored local identity material.
pub struct MessageEncryption<'a> {
    /// Consumer-held protocol-state snapshot.
    pub snapshot: &'a ProtocolStateSnapshot,
    /// Stable Message identifier.
    pub message_id: MessageId,
    /// Recipient contact Identity Key, which selects the Session and the destination.
    pub contact_identity_key: crate::ContactIdentityKey,
    /// Sender-observed Unix timestamp in milliseconds.
    pub sent_at_millis: u64,
    /// Domain-signed sender certificate sealed into the Message.
    pub sender_certificate: &'a [u8],
    /// Domain signature over the sender certificate.
    pub sender_signature: &'a [u8],
    /// Plaintext bytes to encrypt.
    pub plaintext: &'a [u8],
}

/// Inputs for decrypting a Message with stored local discovery material.
pub struct MessageDecryption<'a> {
    /// Consumer-held protocol-state snapshot.
    pub snapshot: &'a ProtocolStateSnapshot,
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
    /// Domain-signed receiver certificate sealed into the produced acknowledgment.
    pub acknowledgment_sender_certificate: &'a [u8],
    /// Domain signature over the receiver certificate.
    pub acknowledgment_sender_signature: &'a [u8],
    /// Sender-certificate validation input for unique Messages.
    pub sender_certificate_validation: Option<InboundSenderCertificateValidation<'a>>,
}

/// Inputs for processing an encrypted acknowledgment with stored local discovery material.
pub struct AcknowledgmentProcessing<'a> {
    /// Consumer-held protocol-state snapshot.
    pub snapshot: &'a ProtocolStateSnapshot,
    /// Encrypted acknowledgment Message.
    pub message: &'a Message,
}

/// Errors returned by established-session message helpers.
#[derive(Debug, thiserror::Error)]
pub enum MessageOperationError {
    /// Loading local discovery-key state failed.
    #[error(transparent)]
    Discovery(#[from] DiscoveryKeyError),
    /// Loading local identity state failed.
    #[error(transparent)]
    Identity(#[from] IdentityError),
    /// A committed KeyStore operation must be recovered before local keys can be used.
    #[error(transparent)]
    Operation(#[from] KeyStoreOperationError),
    /// Protocol-state or message processing failed.
    #[error(transparent)]
    ProtocolState(#[from] ProtocolStateError),
}

/// The local keys and credentials one operation loads to authenticate what it sends.
pub(super) struct LoadedSender {
    identity: crate::Identity,
    sender_identity: SenderIdentityMaterial,
    discovery_key: PublicDiscoveryKey,
    discovery_to_identity: Signature,
}

impl LoadedSender {
    pub(super) fn local_sender(&self) -> LocalSender<'_> {
        LocalSender {
            identity: &self.sender_identity,
            signing_key: self.identity.signing_key_pair(),
            agreement_key: self.identity.key_pair(),
            discovery_key: &self.discovery_key,
            discovery_to_identity: &self.discovery_to_identity,
        }
    }
}

impl KeyStore {
    /// Encrypts a Message to a contact while authenticating a Transport Binding.
    ///
    /// Roost selects the Session and the contact's Discovery Key. The caller must retain the exact
    /// binding with the returned Message for retransmission.
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
        let sender: LoadedSender = self.load_sender::<MessageOperationError>(
            input.sender_certificate,
            input.sender_signature,
        )?;
        let plaintext = OutboundPlaintext {
            id: input.message_id,
            sender: sender.local_sender(),
            contact_identity_key: input.contact_identity_key,
            sent_at_millis: input.sent_at_millis,
            plaintext: input.plaintext,
        };
        Ok(self.0.engine.encrypt_message_with_transport_binding(
            &mut OsRng,
            input.snapshot,
            plaintext,
            transport_binding,
        )?)
    }

    /// Decrypts a Message on the Session it names, and authenticates its Transport Binding plus
    /// the binding used for the returned acknowledgment.
    ///
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
        let inbound = InboundEncryptedMessage {
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
        Ok(self.0.engine.decrypt_message_with_transport_bindings(
            &mut OsRng,
            input.snapshot,
            inbound,
            message_transport_binding,
            acknowledgment_transport_binding,
        )?)
    }

    /// Processes an encrypted acknowledgment on the Session it names while authenticating its
    /// Transport Binding.
    pub fn process_acknowledgment_with_transport_binding(
        &self,
        input: AcknowledgmentProcessing<'_>,
        transport_binding: &TransportBinding,
    ) -> Result<AcknowledgmentOutcome, MessageOperationError> {
        let _lifecycle = self.lifecycle_guard();
        self.ensure_no_recovery_required()?;
        let identity = self.0.identity.load_identity()?;
        let discovery_key = self.0.discovery.current()?;
        let inbound = InboundAcknowledgmentMessage {
            message: input.message,
            recipient_discovery_key: &discovery_key,
            recipient_identity_verifying_key: identity.verifying_key().to_bytes(),
        };
        Ok(self
            .0
            .engine
            .process_acknowledgment_with_transport_binding(
                &mut OsRng,
                input.snapshot,
                inbound,
                transport_binding,
            )?)
    }

    // Loads the identity, its current Discovery Key, and both binding directions.
    pub(super) fn load_sender<E: From<IdentityError> + From<DiscoveryKeyError>>(
        &self,
        certificate: &[u8],
        signature: &[u8],
    ) -> Result<LoadedSender, E> {
        let identity = self.0.identity.load_identity()?;
        let sender_identity = sender_identity_material(&identity, certificate, signature)?;
        let discovery_key = self.0.discovery.current()?;
        let discovery_to_identity = self.0.discovery.identity_binding(&discovery_key)?;
        Ok(LoadedSender {
            identity,
            sender_identity,
            discovery_key: discovery_key.public(),
            discovery_to_identity,
        })
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
