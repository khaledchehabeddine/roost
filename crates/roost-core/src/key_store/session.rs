use super::KeyStore;
use crate::{
    DiscoveryKeyError, IdentityError, InboundSenderCertificateValidation, InboundSessionStart,
    KeyStoreOperationError, Message, MessageId, OneTimePreKeyError, OutboundSessionStart,
    PreKeySelection, PreparedKeyStoreOperation, ProtocolStateError, ProtocolStateKey,
    ProtocolStateSnapshot, SessionAcceptanceOutcome, SessionInitiationResult, SignedPreKeyError,
    TransportBinding,
};
use rand::rngs::OsRng;
use roost_crypto::{
    HandshakeError, PreKeyBundle, PublicIdentityKey, SealedFramePreKeyReference, Signature,
};
use std::time::SystemTime;

/// Inputs for starting a new Session as the X3DH initiator.
pub struct SessionInitiation<'a> {
    /// Consumer-held protocol-state snapshot, including the Sessions kept with the responder.
    pub snapshot: &'a ProtocolStateSnapshot,
    /// Responder permanent public Identity Key.
    pub responder_identity_key: PublicIdentityKey,
    /// The responder's DK→IK binding: its discovery key signing the identity above.
    ///
    /// Checked before any handshake work. The IK→DK half travels inside
    /// [`Self::responder_prekey_bundle`] and the handshake verifies it, but that direction alone
    /// only proves an identity vouched for a discovery key — not that the discovery key vouches
    /// for this identity. Whoever supplies the bundle would otherwise be free to pair a genuine
    /// discovery key with an identity of their choosing.
    pub responder_discovery_to_identity: Signature,
    /// Responder publication bundle containing DK, signed pre-key, and optional one-time pre-key.
    pub responder_prekey_bundle: PreKeyBundle,
    /// Stable identifier for the first Message.
    pub message_id: MessageId,
    /// Sender-observed Unix timestamp in milliseconds.
    pub sent_at_millis: u64,
    /// Domain-signed sender certificate sealed into the first message.
    pub sender_certificate: &'a [u8],
    /// Domain signature over the sender certificate.
    pub sender_signature: &'a [u8],
    /// First plaintext bytes sealed into the X3DH message.
    pub plaintext: &'a [u8],
}

/// Inputs for accepting a new Session as the X3DH responder.
pub struct SessionAcceptance<'a> {
    /// Consumer-held protocol-state snapshot, including the deduplication set and the Sessions
    /// kept with the sender.
    pub snapshot: &'a ProtocolStateSnapshot,
    /// Identity-scoped deduplication-set key.
    pub deduplication_key: ProtocolStateKey,
    /// X3DH first message received from the initiator.
    pub message: &'a Message,
    /// Sender-certificate validation inputs for the first Message.
    pub sender_certificate_validation: InboundSenderCertificateValidation<'a>,
}

/// Errors returned by Session establishment helpers.
#[derive(Debug, thiserror::Error)]
pub enum SessionEstablishmentError {
    /// Loading local discovery-key state failed.
    #[error(transparent)]
    Discovery(#[from] DiscoveryKeyError),
    /// The handshake names prekeys the transport didn't select.
    #[error(transparent)]
    Handshake(#[from] HandshakeError),
    /// Loading local identity state failed.
    #[error(transparent)]
    Identity(#[from] IdentityError),
    /// Loading or consuming local one-time-prekey state failed.
    #[error(transparent)]
    OneTimePreKey(#[from] OneTimePreKeyError),
    /// Preparing the recoverable secure mutation failed.
    #[error(transparent)]
    Operation(#[from] KeyStoreOperationError),
    /// The handshake, the first Message, or the Session state failed.
    #[error(transparent)]
    ProtocolState(#[from] ProtocolStateError),
    /// Loading local signed-prekey state failed.
    #[error(transparent)]
    SignedPreKey(#[from] SignedPreKeyError),
}

impl KeyStore {
    /// Starts a new Session while authenticating a caller-owned Transport Binding.
    /// The caller must retain the exact binding with the returned first Message for retransmission.
    /// The returned Message and state updates must be committed
    /// atomically before the Message is handed to transport.
    ///
    /// # Examples
    /// ```
    /// use roost_core::{
    ///     KeyStore, SessionEstablishmentError, SessionInitiation, SessionInitiationResult,
    ///     TransportBinding,
    /// };
    ///
    /// fn start_bound_session(
    ///     store: &KeyStore,
    ///     input: SessionInitiation<'_>,
    ///     binding: TransportBinding,
    /// ) -> Result<(SessionInitiationResult, TransportBinding), SessionEstablishmentError> {
    ///     let result = store.initiate_session_with_transport_binding(input, &binding)?;
    ///     // Persist `result.state_updates`, `result.message`, and `binding` atomically before send.
    ///     Ok((result, binding))
    /// }
    /// ```
    pub fn initiate_session_with_transport_binding(
        &self,
        input: SessionInitiation<'_>,
        transport_binding: &TransportBinding,
    ) -> Result<SessionInitiationResult, SessionEstablishmentError> {
        let _lifecycle = self.lifecycle_guard();
        self.ensure_no_recovery_required()?;
        let sender = self.load_sender::<SessionEstablishmentError>(
            input.sender_certificate,
            input.sender_signature,
        )?;
        Ok(self.0.engine.initiate_session(
            &mut OsRng,
            input.snapshot,
            OutboundSessionStart {
                responder_identity_key: &input.responder_identity_key,
                responder_discovery_to_identity: &input.responder_discovery_to_identity,
                responder_prekey_bundle: &input.responder_prekey_bundle,
                sender: sender.local_sender(),
                id: input.message_id,
                sent_at_millis: input.sent_at_millis,
                plaintext: input.plaintext,
            },
            transport_binding,
        )?)
    }

    /// Prepares Session acceptance while authenticating a caller-owned Transport Binding.
    ///
    /// Call this only for a Message that carries a handshake and named a Session this identity
    /// doesn't have. For a retained superseded signed prekey, the caller must first validate that
    /// its transport accepted the item before supersession.
    ///
    /// One-time-prekey consumption remains staged until finalization. Reserve the operation,
    /// atomically persist the returned state updates and operation identifier, then finalize the
    /// secure-storage mutation.
    pub fn prepare_accept_session_with_transport_binding(
        &self,
        input: SessionAcceptance<'_>,
        transport_binding: &TransportBinding,
        prekey_selection: PreKeySelection,
    ) -> Result<PreparedKeyStoreOperation<SessionAcceptanceOutcome>, SessionEstablishmentError>
    {
        self.prepare_operation(move |staged| {
            staged.accept_session_eager(input, transport_binding, prekey_selection)
        })
    }

    fn accept_session_eager(
        &self,
        input: SessionAcceptance<'_>,
        transport_binding: &TransportBinding,
        prekey_selection: PreKeySelection,
    ) -> Result<SessionAcceptanceOutcome, SessionEstablishmentError> {
        let _lifecycle = self.lifecycle_guard();
        let discovery_key = self.0.discovery.current()?;
        let prekey_reference =
            input
                .message
                .prekey_reference
                .ok_or_else(|| ProtocolStateError::InvalidMessage {
                    reason: "message carries no handshake".into(),
                })?;
        validate_prekey_selection(&prekey_reference, prekey_selection)?;
        let now = SystemTime::now();
        let signed_prekey = self.0.signed_prekey.prekey_for_reference(
            prekey_reference.discovery_epoch,
            prekey_selection.signed_prekey_id,
            &prekey_reference.signed_prekey_public_key,
            now,
        )?;
        let held_signed_prekeys = self.0.signed_prekey.held_public(now)?;
        let one_time_prekey = match (
            prekey_reference.one_time_prekey_id,
            prekey_reference.one_time_prekey_public_key,
        ) {
            (None, None) => None,
            (Some(id), Some(public_key)) => {
                Some(self.0.one_time_prekey.one_time_prekey_for_public_key(
                    prekey_reference.discovery_epoch,
                    id,
                    &public_key,
                )?)
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(HandshakeError::OneTimePreKeyMismatch.into());
            }
        };
        let outcome = self.0.engine.accept_session(
            &mut OsRng,
            input.snapshot,
            InboundSessionStart {
                deduplication_key: input.deduplication_key,
                message: input.message,
                recipient_discovery_key: &discovery_key,
                signed_prekey: &signed_prekey,
                one_time_prekey,
                held_signed_prekeys: &held_signed_prekeys,
                sender_certificate_validation: input.sender_certificate_validation,
            },
            transport_binding,
        )?;
        if let SessionAcceptanceOutcome::Accepted(_) = &outcome
            && let Some(id) = prekey_reference.one_time_prekey_id
        {
            self.0
                .one_time_prekey
                .consume_one_time_prekey(prekey_reference.discovery_epoch, id)?;
        }
        Ok(outcome)
    }
}

fn validate_prekey_selection(
    reference: &SealedFramePreKeyReference,
    selection: PreKeySelection,
) -> Result<(), HandshakeError> {
    if reference.one_time_prekey_id != selection.one_time_prekey_id {
        return Err(HandshakeError::OneTimePreKeyMismatch);
    }
    Ok(())
}
