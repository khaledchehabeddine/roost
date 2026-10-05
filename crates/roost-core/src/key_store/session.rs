use super::KeyStore;
use crate::{
    DiscoveryKeyError, IdentityError, KeyStoreOperationError, Message, MessageError,
    OneTimePreKeyError, PreKeySelection, PreparedKeyStoreOperation, ProtocolStateError,
    ProtocolStateKey, ProtocolStateUpdate, SignedPreKeyError, TransportBinding,
};
use rand::rngs::OsRng;
use roost_crypto::{
    HandshakeEnvelope, HandshakeError, InitialPlaintext, PreKeyBundle, PublicIdentityKey,
    PublicKeyError, SealedFramePreKeyReference, SenderIdentityMaterial, Signature,
    accept_with_associated_data, initiate_with_associated_data,
    initiator_identity_hint_with_associated_data, verify_discovery_to_identity_binding,
};
use std::time::SystemTime;
use zeroize::Zeroizing;

/// Inputs for starting a new Session as the X3DH initiator.
pub struct SessionInitiation<'a> {
    /// Session-scoped protocol-state key for the new ratchet/session blob.
    pub session_key: ProtocolStateKey,
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
    /// Opaque sender certificate sealed into the first message.
    pub sender_certificate: &'a [u8],
    /// Opaque sender signature sealed into the first message.
    pub sender_signature: &'a [u8],
    /// First plaintext bytes sealed into the X3DH message.
    pub plaintext: &'a [u8],
}

/// Output from starting a new Session.
pub struct SessionInitiationResult {
    /// X3DH first message to send after committing `state_updates`.
    pub message: Message,
    /// Protocol-state updates for the new ratchet/session and pending-acknowledgment blobs.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

/// Inputs for accepting a new Session as the X3DH responder.
pub struct SessionAcceptance<'a> {
    /// Session-scoped protocol-state key for the new ratchet/session blob.
    pub session_key: ProtocolStateKey,
    /// Initiator permanent public Identity Key expected by the caller, or `None`
    /// to accept whichever initiator the message names.
    ///
    /// A caller that knows who it expects pins it here and a mismatch fails. A
    /// caller receiving a first message from a stranger cannot know, and passes
    /// `None`; the identity is then read from the handshake frame and still
    /// checked against the sealed envelope's own copy after decryption.
    pub initiator_identity_key: Option<PublicIdentityKey>,
    /// X3DH first message received from the initiator.
    pub message: &'a Message,
}

/// Output from accepting a new Session.
pub struct SessionAcceptanceResult {
    /// Decrypted first-message plaintext.
    pub plaintext: Zeroizing<Vec<u8>>,
    /// Sender identity material decoded after ciphertext authentication.
    pub sender_identity: SenderIdentityMaterial,
    /// Protocol-state updates for the new ratchet/session and pending-acknowledgment blobs.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

/// Errors returned by Session establishment helpers.
#[derive(Debug, thiserror::Error)]
pub enum SessionEstablishmentError {
    /// Loading local discovery-key state failed.
    #[error(transparent)]
    Discovery(#[from] DiscoveryKeyError),
    /// The X3DH handshake failed.
    #[error(transparent)]
    Handshake(#[from] HandshakeError),
    /// Loading local identity state failed.
    #[error(transparent)]
    Identity(#[from] IdentityError),
    /// The peer's Discovery Key does not bind to its Identity Key.
    #[error(transparent)]
    PublicKey(#[from] PublicKeyError),
    /// Message conversion failed.
    #[error(transparent)]
    Message(#[from] MessageError),
    /// Loading or consuming local one-time-prekey state failed.
    #[error(transparent)]
    OneTimePreKey(#[from] OneTimePreKeyError),
    /// Preparing the recoverable secure mutation failed.
    #[error(transparent)]
    Operation(#[from] KeyStoreOperationError),
    /// Encoding install updates failed.
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

        // Before any local state is loaded or any handshake work is spent: the
        // mapping this session is built on has to hold in both directions.
        // `initiate` checks IK→DK from inside the prekey bundle;
        // nothing but this checks DK→IK, and a bundle that fails it names an
        // identity its discovery key never vouched for.
        verify_discovery_to_identity_binding(
            &input.responder_identity_key,
            &input.responder_prekey_bundle.discovery_key.verifying_key,
            &input.responder_discovery_to_identity,
        )?;
        let transport_binding = transport_binding.as_bytes();

        let identity = self.0.identity.load_identity()?;
        let identity_key = identity.public()?;
        let discovery_key = self.0.discovery.current()?;
        let mut rng = OsRng;
        let (state, envelope) = initiate_with_associated_data(
            &mut rng,
            &discovery_key,
            &identity_key,
            &input.responder_identity_key,
            &input.responder_prekey_bundle,
            InitialPlaintext {
                sender_certificate: input.sender_certificate,
                sender_signature: input.sender_signature,
                plaintext: input.plaintext,
            },
            transport_binding,
        )?;
        let message = message_from_handshake_envelope(envelope)?;
        let engine = &self.0.engine;
        let state_updates = vec![
            engine.set_session_state_with_peer_identity_key(
                input.session_key.clone(),
                &state,
                *input.responder_identity_key.public_key.as_bytes(),
            )?,
            engine.initialize_pending_acknowledgments(input.session_key)?,
        ];

        Ok(SessionInitiationResult {
            message,
            state_updates,
        })
    }

    /// Reads the initiator identity while authenticating a caller-owned Transport Binding.
    ///
    /// Transport Binding authentication does not authenticate the claimed initiator. The returned
    /// identity remains a sender claim until
    /// [`Self::prepare_accept_session_with_transport_binding`] checks it against the sealed
    /// envelope's authenticated copy.
    pub fn initiator_identity_hint_with_transport_binding(
        &self,
        message: &Message,
        transport_binding: &TransportBinding,
        prekey_selection: PreKeySelection,
    ) -> Result<PublicIdentityKey, SessionEstablishmentError> {
        let _lifecycle = self.lifecycle_guard();
        self.ensure_no_recovery_required()?;
        let discovery_key = self.0.discovery.current()?;
        let envelope = handshake_envelope_from_message(message)?;
        let prekey_reference = envelope
            .prekey_reference
            .ok_or(HandshakeError::EnvelopeDecode)?;
        validate_prekey_selection(&prekey_reference, prekey_selection)?;
        self.0.signed_prekey.prekey_for_reference(
            prekey_reference.discovery_epoch,
            prekey_selection.signed_prekey_id,
            &prekey_reference.signed_prekey_public_key,
            SystemTime::now(),
        )?;
        let transport_binding = transport_binding.as_bytes();
        Ok(initiator_identity_hint_with_associated_data(
            &envelope,
            &discovery_key,
            transport_binding,
        )?)
    }

    /// Prepares Session acceptance while authenticating a caller-owned Transport Binding.
    /// For a retained superseded signed prekey, the caller must first validate that its transport
    /// accepted the item before supersession.
    ///
    /// One-time-prekey consumption remains staged until
    /// finalization. Reserve the operation, atomically persist the returned state updates and
    /// operation identifier, then finalize the secure-storage mutation.
    pub fn prepare_accept_session_with_transport_binding(
        &self,
        input: SessionAcceptance<'_>,
        transport_binding: &TransportBinding,
        prekey_selection: PreKeySelection,
    ) -> Result<PreparedKeyStoreOperation<SessionAcceptanceResult>, SessionEstablishmentError> {
        self.prepare_operation(move |staged| {
            staged.accept_session_eager(input, transport_binding, prekey_selection)
        })
    }

    fn accept_session_eager(
        &self,
        input: SessionAcceptance<'_>,
        transport_binding: &TransportBinding,
        prekey_selection: PreKeySelection,
    ) -> Result<SessionAcceptanceResult, SessionEstablishmentError> {
        let _lifecycle = self.lifecycle_guard();
        let identity = self.0.identity.load_identity()?;
        let identity_key = identity.public()?;
        let discovery_key = self.0.discovery.current()?;
        let envelope = handshake_envelope_from_message(input.message)?;
        let prekey_reference = envelope
            .prekey_reference
            .ok_or(HandshakeError::EnvelopeDecode)?;
        validate_prekey_selection(&prekey_reference, prekey_selection)?;
        let signed_prekey = self.0.signed_prekey.prekey_for_reference(
            prekey_reference.discovery_epoch,
            prekey_selection.signed_prekey_id,
            &prekey_reference.signed_prekey_public_key,
            SystemTime::now(),
        )?;
        let transport_binding = transport_binding.as_bytes();
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
        let mut rng = OsRng;
        let (state, accepted) = accept_with_associated_data(
            &mut rng,
            &envelope,
            input.initiator_identity_key.as_ref(),
            &identity_key,
            &discovery_key,
            &signed_prekey,
            one_time_prekey,
            transport_binding,
        )?;
        if let Some(id) = prekey_reference.one_time_prekey_id {
            self.0
                .one_time_prekey
                .consume_one_time_prekey(prekey_reference.discovery_epoch, id)?;
        }

        let engine = &self.0.engine;
        let state_updates = vec![
            engine.set_session_state_with_peer_identity(
                input.session_key.clone(),
                &state,
                &accepted.sender_identity,
            )?,
            engine.initialize_pending_acknowledgments(input.session_key)?,
        ];

        Ok(SessionAcceptanceResult {
            plaintext: accepted.plaintext,
            sender_identity: accepted.sender_identity,
            state_updates,
        })
    }
}

#[cfg(test)]
impl KeyStore {
    fn accept_session(
        &self,
        input: SessionAcceptance<'_>,
    ) -> Result<SessionAcceptanceResult, SessionEstablishmentError> {
        {
            let selection = PreKeySelection {
                signed_prekey_id: self.0.signed_prekey.current_public(SystemTime::now())?.id,
                one_time_prekey_id: input
                    .message
                    .prekey_reference
                    .as_ref()
                    .and_then(|p| p.one_time_prekey_id),
            };
            self.accept_session_eager(
                input,
                &TransportBinding::new(b"test-route".to_vec()).unwrap(),
                selection,
            )
        }
    }
}

fn message_from_handshake_envelope(envelope: HandshakeEnvelope) -> Result<Message, MessageError> {
    let message = Message {
        version: envelope.version,
        recipient_public_key: envelope.recipient_public_key,
        prekey_reference: envelope.prekey_reference,
        ephemeral_public_key: envelope.ephemeral_public_key,
        ciphertext: envelope.ciphertext,
    };
    message.to_bytes()?;
    Ok(message)
}

fn handshake_envelope_from_message(
    message: &Message,
) -> Result<HandshakeEnvelope, SessionEstablishmentError> {
    let bytes = message.to_bytes()?;
    Ok(HandshakeEnvelope::from_bytes(&bytes)?)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InMemorySecureStorage, ProtocolStateKind, SessionId};
    use roost_protocol::SignatureError;

    fn store() -> KeyStore {
        KeyStore::new(Box::new(InMemorySecureStorage::new()))
    }

    fn state_update_kinds(updates: &[ProtocolStateUpdate]) -> Vec<ProtocolStateKind> {
        updates
            .iter()
            .map(|update| update.address().kind())
            .collect()
    }

    /// Both binding directions must hold before a discovery-key-to-identity
    /// mapping is trusted. The IK→DK half rides on the public discovery key and
    /// the handshake already checks it; this is the other half, which proves the
    /// discovery key vouches for the identity rather than merely being named
    /// alongside it. Without it, whoever hands over the bundle — the relay, or
    /// anyone who can answer for it — can pair a real discovery key with an
    /// identity of their choosing.
    #[test]
    fn initiation_refuses_a_discovery_key_that_does_not_vouch_for_the_identity() {
        let alice = store();
        let bob = store();
        let mallory = store();
        alice.generate_identity().unwrap();
        let bob_identity = bob.generate_identity().unwrap();
        mallory.generate_identity().unwrap();
        bob.rotate_signed_prekey_now().unwrap();
        mallory.rotate_signed_prekey_now().unwrap();
        let bob_publication = bob.current_publication().unwrap();
        // Mallory's DK→IK signature: valid bytes over the wrong identity.
        let mallory_publication = mallory.current_publication().unwrap();

        let result = alice.initiate_session_with_transport_binding(
            SessionInitiation {
                session_key: ProtocolStateKey::session(SessionId::from_bytes([0x24; 16])),
                responder_identity_key: bob_identity.public().unwrap(),
                responder_discovery_to_identity: mallory_publication.discovery_to_identity,
                responder_prekey_bundle: roost_crypto::PreKeyBundle {
                    version: bob_publication.version,
                    discovery_key: bob_publication.discovery_key,
                    signed_prekey: bob_publication.signed_prekey,
                    one_time_prekey: None,
                },
                sender_certificate: b"alice certificate",
                sender_signature: b"alice signature",
                plaintext: b"hello bob",
            },
            &crate::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        );

        assert!(
            matches!(
                result,
                Err(SessionEstablishmentError::PublicKey(
                    PublicKeyError::Signature(SignatureError::SignatureInvalid)
                ))
            ),
            "a DK→IK signature over another identity must not establish a session"
        );
    }

    #[test]
    fn initiate_and_accept_session_return_first_message_plaintext_and_state_updates() {
        let alice = store();
        let bob = store();
        let alice_identity = alice.generate_identity().unwrap();
        let bob_identity = bob.generate_identity().unwrap();
        bob.rotate_signed_prekey_now().unwrap();
        let bob_publication = bob.current_publication().unwrap();
        let bob_one_time_prekey = bob.generate_one_time_prekeys(1).unwrap().remove(0);

        let session_key = ProtocolStateKey::session(SessionId::from_bytes([0x22; 16]));
        let initiation = alice
            .initiate_session_with_transport_binding(
                SessionInitiation {
                    session_key: session_key.clone(),
                    responder_identity_key: bob_identity.public().unwrap(),
                    responder_discovery_to_identity: bob_publication.discovery_to_identity,
                    responder_prekey_bundle: roost_crypto::PreKeyBundle {
                        version: bob_publication.version,
                        discovery_key: bob_publication.discovery_key,
                        signed_prekey: bob_publication.signed_prekey,
                        one_time_prekey: Some(bob_one_time_prekey.clone()),
                    },
                    sender_certificate: b"alice certificate",
                    sender_signature: b"alice signature",
                    plaintext: b"hello bob",
                },
                &crate::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            )
            .unwrap();

        assert!(initiation.message.prekey_reference.is_some());
        assert_eq!(
            state_update_kinds(&initiation.state_updates),
            vec![
                ProtocolStateKind::RatchetSession,
                ProtocolStateKind::PendingAcknowledgments
            ]
        );

        let acceptance = bob
            .accept_session(SessionAcceptance {
                session_key,
                initiator_identity_key: Some(alice_identity.public().unwrap()),
                message: &initiation.message,
            })
            .unwrap();

        assert_eq!(&*acceptance.plaintext, b"hello bob");
        assert_eq!(
            acceptance.sender_identity.certificate,
            b"alice certificate".to_vec()
        );
        assert_eq!(
            state_update_kinds(&acceptance.state_updates),
            vec![
                ProtocolStateKind::RatchetSession,
                ProtocolStateKind::PendingAcknowledgments
            ]
        );
    }

    #[test]
    fn accept_session_consumes_referenced_one_time_prekey_once() {
        let alice = store();
        let bob = store();
        let alice_identity = alice.generate_identity().unwrap();
        let bob_identity = bob.generate_identity().unwrap();
        bob.rotate_signed_prekey_now().unwrap();
        let bob_publication = bob.current_publication().unwrap();
        let bob_one_time_prekey = bob.generate_one_time_prekeys(1).unwrap().remove(0);

        let initiation = alice
            .initiate_session_with_transport_binding(
                SessionInitiation {
                    session_key: ProtocolStateKey::session(SessionId::from_bytes([0x33; 16])),
                    responder_identity_key: bob_identity.public().unwrap(),
                    responder_discovery_to_identity: bob_publication.discovery_to_identity,
                    responder_prekey_bundle: roost_crypto::PreKeyBundle {
                        version: bob_publication.version,
                        discovery_key: bob_publication.discovery_key,
                        signed_prekey: bob_publication.signed_prekey,
                        one_time_prekey: Some(bob_one_time_prekey),
                    },
                    sender_certificate: b"alice certificate",
                    sender_signature: b"alice signature",
                    plaintext: b"hello bob",
                },
                &crate::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            )
            .unwrap();

        bob.accept_session(SessionAcceptance {
            session_key: ProtocolStateKey::session(SessionId::from_bytes([0x33; 16])),
            initiator_identity_key: Some(alice_identity.public().unwrap()),
            message: &initiation.message,
        })
        .unwrap();

        let second = bob.accept_session(SessionAcceptance {
            session_key: ProtocolStateKey::session(SessionId::from_bytes([0x34; 16])),
            initiator_identity_key: Some(alice_identity.public().unwrap()),
            message: &initiation.message,
        });

        assert!(matches!(
            second,
            Err(SessionEstablishmentError::OneTimePreKey(
                OneTimePreKeyError::NotFound
            ))
        ));
    }
}
