use super::KeyStore;
use crate::{
    DiscoveryKeyError, IdentityError, KeyStoreOperationError, Message, MessageError,
    OneTimePreKeyError, PreparedKeyStoreOperation, ProtocolStateError, ProtocolStateKey,
    ProtocolStateUpdate, SignedPreKeyError,
};
use aether_crypto::{
    CryptoError, HandshakeEnvelope, IdentityKeyBundle, InitialPlaintext, PreKeyBundle,
    SenderIdentityMaterial, Signature, accept, initiate, verify_discovery_to_identity_binding,
};
use rand::rngs::OsRng;
use std::error::Error;
use std::fmt;
use zeroize::Zeroizing;

/// Inputs for starting a new Session as the X3DH initiator.
pub struct SessionInitiation<'a> {
    /// Session-scoped protocol-state key for the new ratchet/session blob.
    pub session_key: ProtocolStateKey,
    /// Responder permanent Identity Key bundle.
    pub responder_identity_key: IdentityKeyBundle,
    /// The responder's DK→IK binding: its discovery key signing the identity above (AE-KEY-04).
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
    /// Initiator permanent Identity Key bundle expected by the caller, or `None`
    /// to accept whichever initiator the message names.
    ///
    /// A caller that knows who it expects pins it here and a mismatch fails. A
    /// caller receiving a first message from a stranger cannot know, and passes
    /// `None`; the identity is then read from the handshake frame and still
    /// checked against the sealed envelope's own copy after decryption.
    pub initiator_identity_key: Option<IdentityKeyBundle>,
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
#[derive(Debug)]
pub enum SessionEstablishmentError {
    /// A cryptographic X3DH, sealed-frame, or ratchet operation failed.
    Crypto(CryptoError),
    /// Loading local discovery-key state failed.
    Discovery(DiscoveryKeyError),
    /// Loading local identity state failed.
    Identity(IdentityError),
    /// Message conversion failed.
    Message(MessageError),
    /// Loading or consuming local one-time-prekey state failed.
    OneTimePreKey(OneTimePreKeyError),
    /// Preparing the recoverable secure mutation failed.
    Operation(KeyStoreOperationError),
    /// Encoding install updates failed.
    ProtocolState(ProtocolStateError),
    /// Loading local signed-prekey state failed.
    SignedPreKey(SignedPreKeyError),
}

impl fmt::Display for SessionEstablishmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(e) => write!(f, "session establishment crypto: {e}"),
            Self::Discovery(e) => write!(f, "session establishment discovery key: {e}"),
            Self::Identity(e) => write!(f, "session establishment identity: {e}"),
            Self::Message(e) => write!(f, "session establishment message: {e}"),
            Self::OneTimePreKey(e) => write!(f, "session establishment one-time pre-key: {e}"),
            Self::Operation(e) => write!(f, "session establishment prepared operation: {e}"),
            Self::ProtocolState(e) => write!(f, "session establishment protocol state: {e}"),
            Self::SignedPreKey(e) => write!(f, "session establishment signed pre-key: {e}"),
        }
    }
}

impl Error for SessionEstablishmentError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Crypto(e) => Some(e),
            Self::Discovery(e) => Some(e),
            Self::Identity(e) => Some(e),
            Self::Message(e) => Some(e),
            Self::OneTimePreKey(e) => Some(e),
            Self::Operation(e) => Some(e),
            Self::ProtocolState(e) => Some(e),
            Self::SignedPreKey(e) => Some(e),
        }
    }
}

impl From<CryptoError> for SessionEstablishmentError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl From<DiscoveryKeyError> for SessionEstablishmentError {
    fn from(e: DiscoveryKeyError) -> Self {
        Self::Discovery(e)
    }
}

impl From<IdentityError> for SessionEstablishmentError {
    fn from(e: IdentityError) -> Self {
        Self::Identity(e)
    }
}

impl From<MessageError> for SessionEstablishmentError {
    fn from(e: MessageError) -> Self {
        Self::Message(e)
    }
}

impl From<OneTimePreKeyError> for SessionEstablishmentError {
    fn from(e: OneTimePreKeyError) -> Self {
        Self::OneTimePreKey(e)
    }
}

impl From<KeyStoreOperationError> for SessionEstablishmentError {
    fn from(e: KeyStoreOperationError) -> Self {
        Self::Operation(e)
    }
}

impl From<ProtocolStateError> for SessionEstablishmentError {
    fn from(e: ProtocolStateError) -> Self {
        Self::ProtocolState(e)
    }
}

impl From<SignedPreKeyError> for SessionEstablishmentError {
    fn from(e: SignedPreKeyError) -> Self {
        Self::SignedPreKey(e)
    }
}

impl KeyStore {
    /// Starts a new Session as the X3DH initiator.
    ///
    /// The returned first Message and state updates must be committed atomically by the consumer
    /// before the Message is handed to transport.
    ///
    /// # Errors
    /// - [`SessionEstablishmentError::Crypto`] if X3DH initiation or frame encoding fails.
    /// - [`SessionEstablishmentError::Discovery`] if local Discovery Key state cannot be loaded.
    /// - [`SessionEstablishmentError::Identity`] if local Identity state cannot be loaded.
    /// - [`SessionEstablishmentError::Message`] if the produced frame cannot be represented as a
    ///   Core Message.
    /// - [`SessionEstablishmentError::Operation`] if a committed operation needs recovery.
    /// - [`SessionEstablishmentError::ProtocolState`] if install updates cannot be encoded.
    pub fn initiate_session(
        &self,
        input: SessionInitiation<'_>,
    ) -> Result<SessionInitiationResult, SessionEstablishmentError> {
        let _lifecycle = self.lifecycle_guard();
        self.ensure_no_recovery_required()?;

        // Before any local state is loaded or any handshake work is spent: the
        // mapping this session is built on has to hold in both directions
        // (AE-KEY-04). `initiate` checks IK→DK from inside the prekey bundle;
        // nothing but this checks DK→IK, and a bundle that fails it names an
        // identity its discovery key never vouched for.
        verify_discovery_to_identity_binding(
            &input.responder_identity_key,
            &input.responder_prekey_bundle.discovery_key.verifying_key,
            &input.responder_discovery_to_identity,
        )?;

        let identity = self.0.identity.load_identity()?;
        let identity_key = identity.identity_key_bundle()?;
        let discovery_key = self.0.discovery.current()?;
        let mut rng = OsRng;
        let (state, envelope) = initiate(
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
        )?;
        let message = message_from_handshake_envelope(envelope)?;
        let engine = crate::ProtocolStateEngine::new();
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

    /// Reads who sent an X3DH first message, without accepting it.
    ///
    /// A caller addresses session state by a key derived from both identities,
    /// so it needs the sender before it can accept. [`Self::prepare_accept_session`] stages
    /// consumption of the referenced one-time prekey, so it should not be run merely to find out.
    /// This opens only the layer sealed to this device's own Discovery Key and consumes nothing.
    ///
    /// The returned identity is the sender's *claim*, carrying its own verified
    /// binding signature. It is what `prepare_accept_session` then checks against the
    /// sealed envelope's authenticated copy; on its own it proves only that
    /// someone who could reach this inbox named this identity.
    ///
    /// # Errors
    /// - [`SessionEstablishmentError::Crypto`] if the message is not an initial,
    ///   is not sealed to this Discovery Key, or names an identity whose binding
    ///   does not verify.
    /// - [`SessionEstablishmentError::Discovery`] if local Discovery Key state cannot be loaded.
    /// - [`SessionEstablishmentError::Message`] if the Message cannot be encoded.
    /// - [`SessionEstablishmentError::Operation`] if a committed operation needs recovery.
    pub fn initiator_identity_hint(
        &self,
        message: &Message,
    ) -> Result<IdentityKeyBundle, SessionEstablishmentError> {
        let _lifecycle = self.lifecycle_guard();
        self.ensure_no_recovery_required()?;
        let discovery_key = self.0.discovery.current()?;
        let envelope = handshake_envelope_from_message(message)?;
        Ok(aether_crypto::initiator_identity_hint(
            &envelope,
            &discovery_key,
        )?)
    }

    /// Accepts a new Session as the X3DH responder.
    ///
    /// A referenced one-time pre-key is consumed only after the first Message authenticates and the
    /// new Session state has been produced.
    ///
    /// # Errors
    /// - [`SessionEstablishmentError::Crypto`] if X3DH acceptance, sender proof validation, or
    ///   frame decoding fails.
    /// - [`SessionEstablishmentError::Discovery`] if local Discovery Key state cannot be loaded.
    /// - [`SessionEstablishmentError::Identity`] if local Identity state cannot be loaded.
    /// - [`SessionEstablishmentError::Message`] if the received Message cannot be encoded for
    ///   handshake validation.
    /// - [`SessionEstablishmentError::OneTimePreKey`] if a referenced one-time pre-key is absent,
    ///   stale, already consumed, or cannot be consumed after acceptance.
    /// - [`SessionEstablishmentError::Operation`] if staging fails or a committed operation needs
    ///   recovery.
    /// - [`SessionEstablishmentError::ProtocolState`] if install updates cannot be encoded.
    /// - [`SessionEstablishmentError::SignedPreKey`] if the referenced signed pre-key is absent
    ///   or cannot be loaded.
    pub fn prepare_accept_session(
        &self,
        input: SessionAcceptance<'_>,
    ) -> Result<PreparedKeyStoreOperation<SessionAcceptanceResult>, SessionEstablishmentError> {
        self.prepare_operation(move |staged| staged.accept_session_eager(input))
    }

    fn accept_session_eager(
        &self,
        input: SessionAcceptance<'_>,
    ) -> Result<SessionAcceptanceResult, SessionEstablishmentError> {
        let _lifecycle = self.lifecycle_guard();
        let identity = self.0.identity.load_identity()?;
        let identity_key = identity.identity_key_bundle()?;
        let discovery_key = self.0.discovery.current()?;
        let envelope = handshake_envelope_from_message(input.message)?;
        let prekey_reference = envelope
            .prekey_reference
            .ok_or(CryptoError::HandshakeEnvelopeDecode)?;
        let signed_prekey = self.0.signed_prekey.prekey_for_public_key(
            prekey_reference.discovery_epoch,
            &prekey_reference.signed_prekey_public_key,
        )?;
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
                return Err(CryptoError::OneTimePreKeyMismatch.into());
            }
        };
        let mut rng = OsRng;
        let (state, accepted) = accept(
            &mut rng,
            &envelope,
            input.initiator_identity_key.as_ref(),
            &identity_key,
            &discovery_key,
            &signed_prekey,
            one_time_prekey,
        )?;
        if let Some(id) = prekey_reference.one_time_prekey_id {
            self.0
                .one_time_prekey
                .consume_one_time_prekey(prekey_reference.discovery_epoch, id)?;
        }

        let engine = crate::ProtocolStateEngine::new();
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
        self.accept_session_eager(input)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InMemorySecureStorage, ProtocolStateKind, SessionId};

    fn store() -> KeyStore {
        KeyStore::new(Box::new(InMemorySecureStorage::new()))
    }

    fn state_update_kinds(updates: &[ProtocolStateUpdate]) -> Vec<ProtocolStateKind> {
        updates
            .iter()
            .map(|update| update.address().kind())
            .collect()
    }

    /// AE-KEY-04 requires both directions before a discovery-key-to-identity
    /// mapping is trusted. The IK→DK half rides on the discovery-key bundle and
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
        let bob_publication = bob.current_publication_bundle().unwrap();
        // Mallory's DK→IK signature: valid bytes over the wrong identity.
        let mallory_publication = mallory.current_publication_bundle().unwrap();

        let result = alice.initiate_session(SessionInitiation {
            session_key: ProtocolStateKey::session(SessionId::from_bytes([0x24; 16])),
            responder_identity_key: bob_identity.identity_key_bundle().unwrap(),
            responder_discovery_to_identity: mallory_publication.discovery_to_identity,
            responder_prekey_bundle: aether_crypto::PreKeyBundle {
                version: bob_publication.version,
                discovery_key: bob_publication.discovery_key,
                signed_prekey: bob_publication.signed_prekey,
                one_time_prekey: None,
            },
            sender_certificate: b"alice certificate",
            sender_signature: b"alice signature",
            plaintext: b"hello bob",
        });

        assert!(
            result.is_err(),
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
        let bob_publication = bob.current_publication_bundle().unwrap();
        let bob_one_time_prekey = bob.generate_one_time_prekeys(1).unwrap().remove(0);

        let session_key = ProtocolStateKey::session(SessionId::from_bytes([0x22; 16]));
        let initiation = alice
            .initiate_session(SessionInitiation {
                session_key: session_key.clone(),
                responder_identity_key: bob_identity.identity_key_bundle().unwrap(),
                responder_discovery_to_identity: bob_publication.discovery_to_identity,
                responder_prekey_bundle: aether_crypto::PreKeyBundle {
                    version: bob_publication.version,
                    discovery_key: bob_publication.discovery_key,
                    signed_prekey: bob_publication.signed_prekey,
                    one_time_prekey: Some(bob_one_time_prekey.clone()),
                },
                sender_certificate: b"alice certificate",
                sender_signature: b"alice signature",
                plaintext: b"hello bob",
            })
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
                initiator_identity_key: Some(alice_identity.identity_key_bundle().unwrap()),
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
        let bob_publication = bob.current_publication_bundle().unwrap();
        let bob_one_time_prekey = bob.generate_one_time_prekeys(1).unwrap().remove(0);

        let initiation = alice
            .initiate_session(SessionInitiation {
                session_key: ProtocolStateKey::session(SessionId::from_bytes([0x33; 16])),
                responder_identity_key: bob_identity.identity_key_bundle().unwrap(),
                responder_discovery_to_identity: bob_publication.discovery_to_identity,
                responder_prekey_bundle: aether_crypto::PreKeyBundle {
                    version: bob_publication.version,
                    discovery_key: bob_publication.discovery_key,
                    signed_prekey: bob_publication.signed_prekey,
                    one_time_prekey: Some(bob_one_time_prekey),
                },
                sender_certificate: b"alice certificate",
                sender_signature: b"alice signature",
                plaintext: b"hello bob",
            })
            .unwrap();

        bob.accept_session(SessionAcceptance {
            session_key: ProtocolStateKey::session(SessionId::from_bytes([0x33; 16])),
            initiator_identity_key: Some(alice_identity.identity_key_bundle().unwrap()),
            message: &initiation.message,
        })
        .unwrap();

        let second = bob.accept_session(SessionAcceptance {
            session_key: ProtocolStateKey::session(SessionId::from_bytes([0x34; 16])),
            initiator_identity_key: Some(alice_identity.identity_key_bundle().unwrap()),
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
