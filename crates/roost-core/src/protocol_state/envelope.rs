//! The layers inside a Sealed Sender Frame: the part sealed to the recipient's Discovery Key, the
//! ratchet ciphertext, and the Sealed Sender Envelope inside it, and the checks that authenticate a
//! Message's sender.

use super::{
    InboundSenderCertificateValidation, ProtocolStateError, contact_identity_keys_match,
    encode_zeroizing,
};
use crate::contact::{ContactDiscoveryKey, ContactIdentityKey};
use crate::hardening::ProtocolHardeningLimits;
use crate::{MessageId, PayloadKind, TransportBinding};
use rand::{CryptoRng, RngCore};
use roost_crypto::{
    DiscoveryKey, Handshake, Header, KeyPair, PublicDiscoveryKey, PublicIdentityKey, PublicKey,
    RatchetState, SENDER_PROOF_LEN, SealedFrame, SealedFramePreKeyReference, SenderProofTranscript,
    Signature, SignedPreKey, SigningKeyPair, open_frame_for_discovery_key_with_associated_data,
    prove_sender, seal_frame_with_associated_data, verify_discovery_to_identity_binding,
    verify_public_discovery_key, verify_public_identity_key, verify_sender_proof,
};
use roost_protocol::{
    MESSAGE_TRANSCRIPT_CONTEXT, MessageTranscriptInput, PUBLIC_KEY_LEN, SessionId,
    is_valid_x25519_public_key, message_transcript, pad_sealed_payload,
    parse_ed25519_verifying_key_bytes, unpad_sealed_payload, verify_with_context,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const RATCHETED_PAYLOAD_CONTEXT: &[u8] = b"RoostRatchetedPayload-v1:";
const SIGNATURE_LEN: usize = 64;

/// Sender identity material decoded only after a Message's ciphertext authenticates.
///
/// `Clone` is intentional for post-decryption metadata handoff; owned opaque bytes zeroize on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SenderIdentityMaterial {
    /// Sender Identity Key X25519 public bytes. Always 32 bytes.
    #[zeroize(skip)]
    pub identity_key: [u8; 32],
    /// Sender Identity Key Ed25519 verifying-key bytes. Always 32 bytes.
    #[zeroize(skip)]
    pub identity_verifying_key: [u8; 32],
    /// Ed25519 signature binding `identity_key` to `identity_verifying_key`.
    pub identity_binding_signature: Vec<u8>,
    /// Domain-signed sender certificate bytes.
    pub certificate: Vec<u8>,
    /// Domain signature over the sender certificate.
    pub signature: Vec<u8>,
}

impl SenderIdentityMaterial {
    /// Returns the sender's Identity Key as contact state records it.
    pub(super) fn contact_identity_key(&self) -> ContactIdentityKey {
        ContactIdentityKey {
            x25519_public_key: self.identity_key,
            ed25519_verifying_key: self.identity_verifying_key,
        }
    }

    pub(super) fn public_identity_key(&self) -> Result<PublicIdentityKey, ProtocolStateError> {
        PublicIdentityKey::from_bytes(
            &self.identity_key,
            &self.identity_verifying_key,
            &self.identity_binding_signature,
        )
        .map_err(|_| invalid("sender public identity key encoding is invalid"))
    }
}

/// The fields every Message seals to the recipient's Discovery Key beside its ratchet ciphertext.
#[derive(Clone, Copy)]
pub(super) struct MessageMetadata {
    pub(super) session_id: SessionId,
    /// The X3DH base key, carried until the initiator's first reply.
    pub(super) base_key: Option<[u8; PUBLIC_KEY_LEN]>,
    pub(super) id: MessageId,
    pub(super) sent_at_millis: u64,
    pub(super) payload_kind: PayloadKind,
}

impl MessageMetadata {
    // Binds the whole sealed layer and the recipient to the ratchet ciphertext, so a Discovery Key
    // holder can't move a ciphertext to another Session or change what the Message claims to be.
    fn associated_data(&self, recipient_public_key: &[u8; PUBLIC_KEY_LEN]) -> Vec<u8> {
        let mut associated_data =
            Vec::with_capacity(RATCHETED_PAYLOAD_CONTEXT.len() + 16 + 32 + 16 + 8 + 1 + 33);
        associated_data.extend_from_slice(RATCHETED_PAYLOAD_CONTEXT);
        associated_data.extend_from_slice(self.session_id.as_bytes());
        associated_data.extend_from_slice(recipient_public_key);
        associated_data.extend_from_slice(self.id.as_bytes());
        associated_data.extend_from_slice(&self.sent_at_millis.to_be_bytes());
        associated_data.push(self.payload_kind.tag());
        match &self.base_key {
            Some(base_key) => {
                associated_data.push(1);
                associated_data.extend_from_slice(base_key);
            }
            None => associated_data.push(0),
        }
        associated_data
    }
}

/// A Message's layer sealed to the recipient's Discovery Key, after opening.
pub(super) struct OpenedMessage {
    pub(super) metadata: MessageMetadata,
    pub(super) recipient_public_key: [u8; PUBLIC_KEY_LEN],
    header: Header,
    ciphertext: Vec<u8>,
}

impl OpenedMessage {
    /// Decrypts the ratchet ciphertext and decodes the Sealed Sender Envelope inside it.
    ///
    /// `state` changes even when decoding fails afterwards, so callers keep the advanced state only
    /// after the envelope authenticates.
    pub(super) fn decrypt<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        state: &mut RatchetState,
        limits: ProtocolHardeningLimits,
    ) -> Result<DecodedSealedSenderEnvelope, ProtocolStateError> {
        let associated_data = self.metadata.associated_data(&self.recipient_public_key);
        let sealed =
            state.ratchet_decrypt(rng, &self.ciphertext, &self.header, &associated_data)?;
        let decoded = decode_sealed_sender_envelope(&sealed, limits)?;
        match (self.metadata.base_key, &decoded.authentication) {
            (Some(_), SenderAuthentication::Proof { .. })
            | (None, SenderAuthentication::Signature(_)) => Ok(decoded),
            (Some(_), SenderAuthentication::Signature(_))
            | (None, SenderAuthentication::Proof { .. }) => Err(invalid(
                "message authentication does not match its handshake",
            )),
        }
    }
}

/// Seals `envelope` under the ratchet and then to the recipient's Discovery Key.
fn seal_message<R: RngCore + CryptoRng>(
    rng: &mut R,
    state: &mut RatchetState,
    metadata: MessageMetadata,
    recipient_public_key: [u8; PUBLIC_KEY_LEN],
    prekey_reference: Option<SealedFramePreKeyReference>,
    envelope: &[u8],
    transport_binding: &TransportBinding,
) -> Result<SealedFrame, ProtocolStateError> {
    let associated_data = metadata.associated_data(&recipient_public_key);
    let (header, ciphertext) = state.ratchet_encrypt(envelope, &associated_data)?;
    let frame_plaintext = encode_zeroizing(&FramePlaintextWire {
        session_id: *metadata.session_id.as_bytes(),
        base_key: metadata.base_key,
        id: *metadata.id.as_bytes(),
        sent_at_millis: metadata.sent_at_millis,
        payload_kind: metadata.payload_kind.tag(),
        ratchet_public_key: *header.public_key.as_bytes(),
        previous_chain_length: header.previous_chain_length,
        message_number: header.message_number,
        ciphertext: &ciphertext,
    })
    .map_err(|_| invalid("message frame plaintext failed to encode"))?;
    Ok(seal_frame_with_associated_data(
        rng,
        &PublicKey::from(recipient_public_key),
        prekey_reference,
        &frame_plaintext,
        transport_binding.as_bytes(),
    )?)
}

/// Opens the layer of `message` sealed to `recipient_discovery_key`.
///
/// Nothing in the result is authenticated beyond having been sealed to this Discovery Key, which
/// anyone can do, until its ratchet ciphertext decrypts.
pub(super) fn open_message(
    message: &SealedFrame,
    recipient_discovery_key: &DiscoveryKey,
    transport_binding: &TransportBinding,
) -> Result<OpenedMessage, ProtocolStateError> {
    let frame_plaintext = open_frame_for_discovery_key_with_associated_data(
        recipient_discovery_key,
        message,
        transport_binding.as_bytes(),
    )?;
    let (wire, trailing): (DecodedFramePlaintextWire, &[u8]) =
        postcard::take_from_bytes(&frame_plaintext)
            .map_err(|_| invalid("message frame plaintext failed to decode"))?;
    if !trailing.is_empty() {
        return Err(invalid("message frame plaintext has trailing bytes"));
    }
    if wire.base_key.is_some() != message.prekey_reference.is_some() {
        return Err(invalid(
            "message handshake does not match its prekey reference",
        ));
    }
    if wire
        .base_key
        .is_some_and(|base_key| !is_valid_x25519_public_key(&base_key))
        || !is_valid_x25519_public_key(&wire.ratchet_public_key)
    {
        return Err(invalid(
            "message frame plaintext carries an invalid public key",
        ));
    }
    let payload_kind = PayloadKind::from_tag(wire.payload_kind).ok_or_else(|| {
        invalid(&format!(
            "unsupported message payload kind: {}",
            wire.payload_kind
        ))
    })?;
    Ok(OpenedMessage {
        metadata: MessageMetadata {
            session_id: SessionId::from_bytes(wire.session_id),
            base_key: wire.base_key,
            id: MessageId::from_bytes(wire.id),
            sent_at_millis: wire.sent_at_millis,
            payload_kind,
        },
        recipient_public_key: message.recipient_public_key,
        header: Header {
            public_key: PublicKey::from(wire.ratchet_public_key),
            previous_chain_length: wire.previous_chain_length,
            message_number: wire.message_number,
        },
        ciphertext: wire.ciphertext,
    })
}

/// How the sender of a Message proves who they are.
enum OutboundAuthentication<'a> {
    /// A signature over the Message Transcript, for Messages after the handshake.
    Signature(&'a Signature),
    /// A first-message proof, with the Discovery Key the recipient replies to.
    Proof {
        discovery_key: &'a PublicDiscoveryKey,
        discovery_to_identity: &'a Signature,
        proof: &'a [u8; SENDER_PROOF_LEN],
    },
}

/// How a received Message's sender proved who they are.
pub(super) enum SenderAuthentication {
    Signature([u8; SIGNATURE_LEN]),
    Proof {
        discovery_key: Box<PublicDiscoveryKey>,
        discovery_to_identity: Signature,
        proof: [u8; SENDER_PROOF_LEN],
    },
}

pub(super) struct DecodedSealedSenderEnvelope {
    pub(super) sender_identity: SenderIdentityMaterial,
    pub(super) authentication: SenderAuthentication,
    pub(super) padded_plaintext: Zeroizing<Vec<u8>>,
    pub(super) plaintext: Zeroizing<Vec<u8>>,
}

fn encode_sealed_sender_envelope(
    sender_identity: &SenderIdentityMaterial,
    authentication: OutboundAuthentication<'_>,
    padded_plaintext: &[u8],
    limits: ProtocolHardeningLimits,
) -> Result<Zeroizing<Vec<u8>>, ProtocolStateError> {
    validate_sender_identity(sender_identity, limits)?;
    let signature_bytes;
    let identity_signature_bytes;
    let discovery_to_identity_bytes;
    let authentication = match authentication {
        OutboundAuthentication::Signature(signature) => {
            signature_bytes = signature.to_bytes();
            AuthenticationWire::Signature(&signature_bytes)
        }
        OutboundAuthentication::Proof {
            discovery_key,
            discovery_to_identity,
            proof,
        } => {
            identity_signature_bytes = discovery_key.signature.to_bytes();
            discovery_to_identity_bytes = discovery_to_identity.to_bytes();
            AuthenticationWire::Proof {
                discovery_key: DiscoveryKeyWire {
                    x25519_public_key: *discovery_key.public_key.as_bytes(),
                    ed25519_verifying_key: discovery_key.verifying_key.to_bytes(),
                    epoch: discovery_key.epoch,
                    created_at_secs: discovery_key.created_at_secs,
                    identity_signature: &identity_signature_bytes,
                },
                discovery_to_identity: &discovery_to_identity_bytes,
                proof: *proof,
            }
        }
    };
    // The sealed Message's encoded size is checked against Roost's limits once it exists.
    encode_zeroizing(&SealedSenderEnvelopeWire {
        sender_identity_key: sender_identity.identity_key,
        sender_identity_verifying_key: sender_identity.identity_verifying_key,
        sender_identity_binding_signature: &sender_identity.identity_binding_signature,
        sender_certificate: &sender_identity.certificate,
        sender_signature: &sender_identity.signature,
        authentication,
        padded_plaintext,
    })
    .map_err(|_| invalid("sealed-sender envelope failed to encode"))
}

fn decode_sealed_sender_envelope(
    bytes: &[u8],
    limits: ProtocolHardeningLimits,
) -> Result<DecodedSealedSenderEnvelope, ProtocolStateError> {
    let (wire, trailing): (DecodedSealedSenderEnvelopeWire, &[u8]) =
        postcard::take_from_bytes(bytes)
            .map_err(|_| invalid("sealed-sender envelope failed to decode"))?;
    let padded_plaintext = Zeroizing::new(wire.padded_plaintext);
    let sender_identity = SenderIdentityMaterial {
        identity_key: wire.sender_identity_key,
        identity_verifying_key: wire.sender_identity_verifying_key,
        identity_binding_signature: wire.sender_identity_binding_signature,
        certificate: wire.sender_certificate,
        signature: wire.sender_signature,
    };
    if !trailing.is_empty() {
        return Err(invalid("sealed-sender envelope has trailing bytes"));
    }
    // The frame's payload limit already bounds the envelope, so only the fields with limits of
    // their own are checked here.
    validate_sender_identity(&sender_identity, limits)?;
    let authentication = decoded_authentication(wire.authentication)?;
    let plaintext = unpad_sealed_payload(&padded_plaintext)?;
    Ok(DecodedSealedSenderEnvelope {
        sender_identity,
        authentication,
        padded_plaintext,
        plaintext,
    })
}

fn decoded_authentication(
    wire: DecodedAuthenticationWire,
) -> Result<SenderAuthentication, ProtocolStateError> {
    match wire {
        DecodedAuthenticationWire::Signature(signature) => signature
            .try_into()
            .map(SenderAuthentication::Signature)
            .map_err(|_| invalid("message transcript signature length is invalid")),
        DecodedAuthenticationWire::Proof {
            discovery_key,
            discovery_to_identity,
            proof,
        } => {
            if !is_valid_x25519_public_key(&discovery_key.x25519_public_key) {
                return Err(invalid("sender discovery key is invalid"));
            }
            let verifying_key =
                parse_ed25519_verifying_key_bytes(&discovery_key.ed25519_verifying_key)
                    .ok_or_else(|| invalid("sender discovery key is invalid"))?;
            let identity_signature: [u8; SIGNATURE_LEN] = discovery_key
                .identity_signature
                .try_into()
                .map_err(|_| invalid("sender discovery key signature length is invalid"))?;
            let discovery_to_identity: [u8; SIGNATURE_LEN] = discovery_to_identity
                .try_into()
                .map_err(|_| invalid("sender discovery binding signature length is invalid"))?;
            Ok(SenderAuthentication::Proof {
                discovery_key: Box::new(PublicDiscoveryKey {
                    public_key: PublicKey::from(discovery_key.x25519_public_key),
                    verifying_key,
                    epoch: discovery_key.epoch,
                    created_at_secs: discovery_key.created_at_secs,
                    signature: Signature::from_bytes(&identity_signature),
                }),
                discovery_to_identity: Signature::from_bytes(&discovery_to_identity),
                proof,
            })
        }
    }
}

fn sign_message_transcript(
    signing_key: &SigningKeyPair,
    input: MessageTranscriptInput<'_>,
) -> Result<Signature, ProtocolStateError> {
    let transcript = message_transcript(input)?;
    Ok(signing_key.sign_with_context(MESSAGE_TRANSCRIPT_CONTEXT, &transcript)?)
}

fn verify_message_transcript(
    sender_identity: &SenderIdentityMaterial,
    input: MessageTranscriptInput<'_>,
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), ProtocolStateError> {
    let signature = Signature::from_bytes(signature);
    let verifying_key = parse_ed25519_verifying_key_bytes(&sender_identity.identity_verifying_key)
        .ok_or_else(|| invalid("sender identity verifying key is invalid"))?;
    let transcript = message_transcript(input)?;
    verify_with_context(
        &verifying_key,
        MESSAGE_TRANSCRIPT_CONTEXT,
        &transcript,
        &signature,
    )
    .map_err(ProtocolStateError::from)
}

pub(super) fn encode_acknowledgment_plaintext(
    acknowledged_message_id: MessageId,
) -> Result<Zeroizing<Vec<u8>>, ProtocolStateError> {
    encode_zeroizing(&AcknowledgmentPlaintextWire {
        acknowledged_message_id: *acknowledged_message_id.as_bytes(),
    })
    .map_err(|_| invalid("acknowledgment plaintext failed to encode"))
}

pub(super) fn decode_acknowledgment_plaintext(
    bytes: &[u8],
) -> Result<MessageId, ProtocolStateError> {
    let (wire, trailing): (AcknowledgmentPlaintextWire, &[u8]) =
        postcard::take_from_bytes(bytes)
            .map_err(|_| invalid("acknowledgment plaintext failed to decode"))?;
    if !trailing.is_empty() {
        return Err(invalid("acknowledgment plaintext has trailing bytes"));
    }
    Ok(MessageId::from_bytes(wire.acknowledged_message_id))
}

pub(super) fn validate_sender_identity(
    sender_identity: &SenderIdentityMaterial,
    limits: ProtocolHardeningLimits,
) -> Result<(), ProtocolStateError> {
    let bundle = sender_identity.public_identity_key()?;
    verify_public_identity_key(&bundle)
        .map_err(|_| invalid("sender identity key binding signature failed"))?;
    if sender_identity.certificate.len() > limits.max_sender_certificate_len {
        return Err(invalid(&format!(
            "sender certificate length exceeds limit: {}",
            sender_identity.certificate.len()
        )));
    }
    if sender_identity.signature.len() > limits.max_sender_signature_len {
        return Err(invalid(&format!(
            "sender signature length exceeds limit: {}",
            sender_identity.signature.len()
        )));
    }
    Ok(())
}

// The local Identity's keys and credentials, which authenticate the Messages it sends.
pub(super) struct LocalSender<'a> {
    // Public identity material and sender certificate sealed into each Message.
    pub(super) identity: &'a SenderIdentityMaterial,
    // Identity Key signing half, which signs Messages sent after the peer replies.
    pub(super) signing_key: &'a SigningKeyPair,
    // Identity Key agreement half, which proves Messages that carry a handshake.
    pub(super) agreement_key: &'a KeyPair,
    // Current Discovery Key, sealed into Messages that carry a handshake so the peer can reply.
    pub(super) discovery_key: &'a PublicDiscoveryKey,
    // The current Discovery Key's signature over the Identity Key.
    pub(super) discovery_to_identity: &'a Signature,
}

// Validates the sender certificate an authenticated Message seals, and returns the Identity Key it
// certifies, which must be the one the Message's sealed sender names.
pub(super) fn certified_sender_identity_key(
    validation: &InboundSenderCertificateValidation,
    certificate_grace: Duration,
    sender_identity: &SenderIdentityMaterial,
) -> Result<ContactIdentityKey, ProtocolStateError> {
    let validated = validation
        .validate(
            &sender_identity.certificate,
            &sender_identity.signature,
            certificate_grace,
        )
        .map_err(ProtocolStateError::SenderCertificateValidation)?;
    let identity_key = ContactIdentityKey {
        x25519_public_key: validated.identity_key.x25519_public_key,
        ed25519_verifying_key: validated.identity_key.ed25519_verifying_key,
    };
    if !contact_identity_keys_match(&identity_key, &sender_identity.contact_identity_key()) {
        return Err(invalid(
            "sender certificate identity key does not match sealed sender",
        ));
    }
    Ok(identity_key)
}

// What one outbound Message says, before Roost seals it.
pub(super) struct OutboundContent<'a> {
    pub(super) session_id: SessionId,
    pub(super) id: MessageId,
    pub(super) sent_at_millis: u64,
    pub(super) payload_kind: PayloadKind,
    // The plaintext, after the Inbox Grant when the payload kind carries one.
    pub(super) payload: &'a [u8],
}

// Where a signed Message goes and whose Identity Key its transcript names.
pub(super) struct SignedRecipient<'a> {
    pub(super) discovery_key: [u8; PUBLIC_KEY_LEN],
    pub(super) identity_verifying_key: &'a [u8; PUBLIC_KEY_LEN],
}

// Seals a Message whose sender signs its transcript, as every Message after the handshake does.
pub(super) fn seal_signed<R: RngCore + CryptoRng>(
    rng: &mut R,
    state: &mut RatchetState,
    content: OutboundContent<'_>,
    recipient: SignedRecipient<'_>,
    sender: &LocalSender<'_>,
    transport_binding: &TransportBinding,
    limits: ProtocolHardeningLimits,
) -> Result<SealedFrame, ProtocolStateError> {
    let sender_identity = sender.identity;
    let payload_kind = content.payload_kind;
    let padded_plaintext = pad_sealed_payload(content.payload)?;
    let signature = sign_message_transcript(
        sender.signing_key,
        MessageTranscriptInput {
            session_id: content.session_id,
            recipient_identity_verifying_key: recipient.identity_verifying_key,
            id: content.id,
            sent_at_millis: content.sent_at_millis,
            payload_kind,
            payload: &padded_plaintext,
            sender_certificate: &sender_identity.certificate,
        },
    )?;
    let envelope = encode_sealed_sender_envelope(
        sender_identity,
        OutboundAuthentication::Signature(&signature),
        &padded_plaintext,
        limits,
    )?;
    seal_message(
        rng,
        state,
        MessageMetadata {
            session_id: content.session_id,
            base_key: None,
            id: content.id,
            sent_at_millis: content.sent_at_millis,
            payload_kind,
        },
        recipient.discovery_key,
        None,
        &envelope,
        transport_binding,
    )
}

// Seals a Message that carries the handshake and proves its sender instead of signing.
pub(super) fn seal_proved<R: RngCore + CryptoRng>(
    rng: &mut R,
    state: &mut RatchetState,
    content: OutboundContent<'_>,
    handshake: &Handshake,
    sender: &LocalSender<'_>,
    transport_binding: &TransportBinding,
    limits: ProtocolHardeningLimits,
) -> Result<SealedFrame, ProtocolStateError> {
    let padded_plaintext = pad_sealed_payload(content.payload)?;
    let proof = prove_sender(
        sender.agreement_key,
        &SenderProofTranscript {
            handshake,
            sender_identity_key: &sender.identity.public_identity_key()?,
            sender_discovery_key: sender.discovery_key,
            sender_certificate: &sender.identity.certificate,
            sender_certificate_signature: &sender.identity.signature,
        },
    )?;
    let envelope = encode_sealed_sender_envelope(
        sender.identity,
        OutboundAuthentication::Proof {
            discovery_key: sender.discovery_key,
            discovery_to_identity: sender.discovery_to_identity,
            proof: &proof,
        },
        &padded_plaintext,
        limits,
    )?;
    seal_message(
        rng,
        state,
        MessageMetadata {
            session_id: content.session_id,
            base_key: Some(*handshake.base_key.as_bytes()),
            id: content.id,
            sent_at_millis: content.sent_at_millis,
            payload_kind: content.payload_kind,
        },
        *handshake.responder_discovery_key.as_bytes(),
        Some(handshake.prekey_reference),
        &envelope,
        transport_binding,
    )
}

// Checks a first Message's proof and the Discovery Key it seals, and returns the sender's
// Identity Key and that Discovery Key.
pub(super) fn authenticate_first_message(
    decoded: &DecodedSealedSenderEnvelope,
    handshake: &Handshake,
    signed_prekey: &SignedPreKey,
) -> Result<(PublicIdentityKey, ContactDiscoveryKey), ProtocolStateError> {
    let SenderAuthentication::Proof {
        discovery_key,
        discovery_to_identity,
        proof,
    } = &decoded.authentication
    else {
        return Err(invalid("first message carries no sender proof"));
    };
    let sender_identity_key = decoded.sender_identity.public_identity_key()?;
    verify_public_discovery_key(discovery_key, &sender_identity_key.verifying_key)
        .map_err(|_| invalid("sender discovery key is not signed by its identity key"))?;
    verify_discovery_to_identity_binding(
        &sender_identity_key,
        &discovery_key.verifying_key,
        discovery_to_identity,
    )
    .map_err(|_| invalid("sender discovery key does not sign its identity key"))?;
    verify_sender_proof(
        signed_prekey,
        &SenderProofTranscript {
            handshake,
            sender_identity_key: &sender_identity_key,
            sender_discovery_key: discovery_key,
            sender_certificate: &decoded.sender_identity.certificate,
            sender_certificate_signature: &decoded.sender_identity.signature,
        },
        proof,
    )?;
    Ok((
        sender_identity_key,
        ContactDiscoveryKey::from(&**discovery_key),
    ))
}

// Checks that a Message on a known Session comes from the Session's peer and, after the handshake,
// that the peer signed it.
//
// A Message that still carries the handshake needs no further check: only the peer holds the
// Session's keys, and the handshake was proved when the Session was created.
pub(super) fn authenticate_session_message(
    decoded: &DecodedSealedSenderEnvelope,
    opened: &OpenedMessage,
    peer_identity_key: ContactIdentityKey,
    recipient_identity_verifying_key: &[u8; PUBLIC_KEY_LEN],
) -> Result<(), ProtocolStateError> {
    if !contact_identity_keys_match(
        &decoded.sender_identity.contact_identity_key(),
        &peer_identity_key,
    ) {
        return Err(invalid("sealed sender identity key does not match session"));
    }
    match &decoded.authentication {
        SenderAuthentication::Signature(signature) => verify_message_transcript(
            &decoded.sender_identity,
            MessageTranscriptInput {
                session_id: opened.metadata.session_id,
                recipient_identity_verifying_key,
                id: opened.metadata.id,
                sent_at_millis: opened.metadata.sent_at_millis,
                payload_kind: opened.metadata.payload_kind,
                payload: &decoded.padded_plaintext,
                sender_certificate: &decoded.sender_identity.certificate,
            },
            signature,
        ),
        SenderAuthentication::Proof { .. } => Ok(()),
    }
}

// Checks that the local Discovery Key belongs to the local Identity Key a transcript names.
pub(super) fn verify_recipient_keys(
    recipient_discovery_key: &DiscoveryKey,
    recipient_identity_verifying_key: &[u8; PUBLIC_KEY_LEN],
) -> Result<(), ProtocolStateError> {
    let recipient_identity_verifying_key =
        parse_ed25519_verifying_key_bytes(recipient_identity_verifying_key)
            .ok_or_else(|| invalid("recipient identity verifying key is not canonical"))?;
    verify_public_discovery_key(
        &recipient_discovery_key.public(),
        &recipient_identity_verifying_key,
    )
    .map_err(|_| invalid("recipient discovery key does not match recipient identity key"))
}

fn invalid(reason: &str) -> ProtocolStateError {
    ProtocolStateError::InvalidMessage {
        reason: reason.into(),
    }
}

#[derive(Serialize)]
struct FramePlaintextWire<'a> {
    session_id: [u8; 16],
    base_key: Option<[u8; PUBLIC_KEY_LEN]>,
    id: [u8; 16],
    sent_at_millis: u64,
    payload_kind: u8,
    ratchet_public_key: [u8; PUBLIC_KEY_LEN],
    previous_chain_length: u32,
    message_number: u32,
    ciphertext: &'a [u8],
}

#[derive(Deserialize)]
struct DecodedFramePlaintextWire {
    session_id: [u8; 16],
    base_key: Option<[u8; PUBLIC_KEY_LEN]>,
    id: [u8; 16],
    sent_at_millis: u64,
    payload_kind: u8,
    ratchet_public_key: [u8; PUBLIC_KEY_LEN],
    previous_chain_length: u32,
    message_number: u32,
    ciphertext: Vec<u8>,
}

#[derive(Serialize)]
struct SealedSenderEnvelopeWire<'a> {
    sender_identity_key: [u8; PUBLIC_KEY_LEN],
    sender_identity_verifying_key: [u8; PUBLIC_KEY_LEN],
    sender_identity_binding_signature: &'a [u8],
    sender_certificate: &'a [u8],
    sender_signature: &'a [u8],
    authentication: AuthenticationWire<'a>,
    padded_plaintext: &'a [u8],
}

#[derive(Serialize)]
enum AuthenticationWire<'a> {
    Signature(&'a [u8]),
    Proof {
        discovery_key: DiscoveryKeyWire<'a>,
        discovery_to_identity: &'a [u8],
        proof: [u8; SENDER_PROOF_LEN],
    },
}

#[derive(Serialize)]
struct DiscoveryKeyWire<'a> {
    x25519_public_key: [u8; PUBLIC_KEY_LEN],
    ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
    epoch: u32,
    created_at_secs: u64,
    identity_signature: &'a [u8],
}

#[derive(Deserialize)]
struct DecodedSealedSenderEnvelopeWire {
    sender_identity_key: [u8; PUBLIC_KEY_LEN],
    sender_identity_verifying_key: [u8; PUBLIC_KEY_LEN],
    sender_identity_binding_signature: Vec<u8>,
    sender_certificate: Vec<u8>,
    sender_signature: Vec<u8>,
    authentication: DecodedAuthenticationWire,
    padded_plaintext: Vec<u8>,
}

#[derive(Deserialize)]
enum DecodedAuthenticationWire {
    Signature(Vec<u8>),
    Proof {
        discovery_key: DecodedDiscoveryKeyWire,
        discovery_to_identity: Vec<u8>,
        proof: [u8; SENDER_PROOF_LEN],
    },
}

#[derive(Deserialize)]
struct DecodedDiscoveryKeyWire {
    x25519_public_key: [u8; PUBLIC_KEY_LEN],
    ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
    epoch: u32,
    created_at_secs: u64,
    identity_signature: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
struct AcknowledgmentPlaintextWire {
    acknowledged_message_id: [u8; 16],
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use roost_crypto::{
        PREKEY_BUNDLE_VERSION, PreKeyBundle, RatchetError, accept_handshake,
        generate_discovery_key, generate_signed_prekey_for_discovery_key, initiate_handshake,
        sign_identity_key_binding,
    };
    use roost_protocol::SignatureError;

    fn metadata() -> MessageMetadata {
        MessageMetadata {
            session_id: SessionId::from_bytes([1; 16]),
            base_key: Some([2; 32]),
            id: MessageId::from_bytes([3; 16]),
            sent_at_millis: 4,
            payload_kind: PayloadKind::EncryptedText,
        }
    }

    #[test]
    fn ratchet_associated_data_changes_with_each_field_and_the_recipient() {
        let recipient = [5; 32];
        let expected = metadata().associated_data(&recipient);

        for changed in [
            MessageMetadata {
                session_id: SessionId::from_bytes([6; 16]),
                ..metadata()
            },
            MessageMetadata {
                base_key: Some([7; 32]),
                ..metadata()
            },
            MessageMetadata {
                base_key: None,
                ..metadata()
            },
            MessageMetadata {
                id: MessageId::from_bytes([8; 16]),
                ..metadata()
            },
            MessageMetadata {
                sent_at_millis: 9,
                ..metadata()
            },
            MessageMetadata {
                payload_kind: PayloadKind::Acknowledgment,
                ..metadata()
            },
        ] {
            assert_ne!(changed.associated_data(&recipient), expected);
        }
        assert_ne!(metadata().associated_data(&[10; 32]), expected);
    }

    #[test]
    fn message_transcript_signature_rejects_field_transplants() {
        let signing_key = SigningKeyPair::from_signing_bytes([1u8; 32]);
        let identity_key = KeyPair::from_secret_bytes([2u8; 32]);
        let binding_signature =
            sign_identity_key_binding(&signing_key, &identity_key.public).unwrap();
        let sender_identity = SenderIdentityMaterial {
            identity_key: *identity_key.public.as_bytes(),
            identity_verifying_key: signing_key.verifying.to_bytes(),
            identity_binding_signature: binding_signature.to_bytes().to_vec(),
            certificate: b"sender certificate".to_vec(),
            signature: Vec::new(),
        };
        let session_id = SessionId::from_bytes([3u8; 16]);
        let recipient_identity_verifying_key = [4u8; 32];
        let id = MessageId::from_bytes([5u8; 16]);
        let payload = b"payload";
        let signature = sign_message_transcript(
            &signing_key,
            MessageTranscriptInput {
                session_id,
                recipient_identity_verifying_key: &recipient_identity_verifying_key,
                id,
                sent_at_millis: 6,
                payload_kind: PayloadKind::EncryptedText,
                payload,
                sender_certificate: &sender_identity.certificate,
            },
        )
        .unwrap();
        let signature_bytes = signature.to_bytes();

        let valid = || MessageTranscriptInput {
            session_id,
            recipient_identity_verifying_key: &recipient_identity_verifying_key,
            id,
            sent_at_millis: 6,
            payload_kind: PayloadKind::EncryptedText,
            payload,
            sender_certificate: &sender_identity.certificate,
        };
        verify_message_transcript(&sender_identity, valid(), &signature_bytes).unwrap();

        let other_recipient_identity_verifying_key = [8u8; 32];
        let other_payload = b"other payload";
        let other_sender_certificate = b"other sender certificate";
        let cases = [
            MessageTranscriptInput {
                session_id: SessionId::from_bytes([7u8; 16]),
                ..valid()
            },
            MessageTranscriptInput {
                recipient_identity_verifying_key: &other_recipient_identity_verifying_key,
                ..valid()
            },
            MessageTranscriptInput {
                id: MessageId::from_bytes([9u8; 16]),
                ..valid()
            },
            MessageTranscriptInput {
                sent_at_millis: 10,
                ..valid()
            },
            MessageTranscriptInput {
                payload_kind: PayloadKind::Acknowledgment,
                ..valid()
            },
            MessageTranscriptInput {
                payload: other_payload,
                ..valid()
            },
            MessageTranscriptInput {
                sender_certificate: other_sender_certificate,
                ..valid()
            },
        ];
        for input in cases {
            assert!(matches!(
                verify_message_transcript(&sender_identity, input, &signature_bytes),
                Err(ProtocolStateError::Signature(
                    SignatureError::SignatureInvalid
                ))
            ));
        }
    }

    struct Sender {
        identity: PublicIdentityKey,
        signing_key: SigningKeyPair,
        material: SenderIdentityMaterial,
    }

    fn sender(seed: u8) -> Sender {
        let signing_key = SigningKeyPair::from_signing_bytes([seed; 32]);
        let agreement_key = KeyPair::from_secret_bytes([seed.wrapping_add(1); 32]);
        let identity = PublicIdentityKey {
            public_key: agreement_key.public,
            verifying_key: signing_key.verifying,
            binding_signature: sign_identity_key_binding(&signing_key, &agreement_key.public)
                .unwrap(),
        };
        Sender {
            material: SenderIdentityMaterial {
                identity_key: *identity.public_key.as_bytes(),
                identity_verifying_key: identity.verifying_key.to_bytes(),
                identity_binding_signature: identity.binding_signature.to_bytes().to_vec(),
                certificate: Vec::new(),
                signature: Vec::new(),
            },
            identity,
            signing_key,
        }
    }

    fn discovery_key(owner: &Sender, seed: u8) -> DiscoveryKey {
        generate_discovery_key(
            &mut ChaCha20Rng::from_seed([seed; 32]),
            &owner.signing_key,
            1,
            1_700_000_000,
        )
        .unwrap()
    }

    // Authenticates a first Message from `claimed` that seals `sealed` and its binding over
    // `bound`, with a proof the Discovery Key checks reject before anyone verifies it.
    fn authenticate(
        claimed: &Sender,
        sealed: &DiscoveryKey,
        bound: &PublicIdentityKey,
    ) -> Result<(), ProtocolStateError> {
        let responder = sender(0x50);
        let responder_discovery_key = discovery_key(&responder, 0x51);
        let signed_prekey: SignedPreKey = generate_signed_prekey_for_discovery_key(
            &mut ChaCha20Rng::from_seed([0x52; 32]),
            &responder_discovery_key,
            0,
            1_700_000_000,
        )
        .unwrap();
        let decoded = DecodedSealedSenderEnvelope {
            sender_identity: claimed.material.clone(),
            authentication: SenderAuthentication::Proof {
                discovery_key: Box::new(sealed.public()),
                discovery_to_identity: sealed.sign_identity_binding(bound).unwrap(),
                proof: [0; roost_crypto::SENDER_PROOF_LEN],
            },
            padded_plaintext: Zeroizing::new(Vec::new()),
            plaintext: Zeroizing::new(Vec::new()),
        };
        let handshake = Handshake {
            base_key: KeyPair::from_secret_bytes([0x53; 32]).public,
            responder_discovery_key: *responder_discovery_key.public_key(),
            prekey_reference: SealedFramePreKeyReference {
                discovery_epoch: 1,
                signed_prekey_public_key: *signed_prekey.public_key().as_bytes(),
                one_time_prekey: None,
            },
        };
        authenticate_first_message(&decoded, &handshake, &signed_prekey).map(|_| ())
    }

    #[test]
    fn a_first_message_sealing_another_identitys_discovery_key_is_rejected() {
        let alice = sender(0x10);
        let mallory = sender(0x20);
        let mallorys_discovery_key = discovery_key(&mallory, 0x21);

        assert!(matches!(
            authenticate(&alice, &mallorys_discovery_key, &alice.identity),
            Err(ProtocolStateError::InvalidMessage { reason })
                if reason == "sender discovery key is not signed by its identity key"
        ));
    }

    #[test]
    fn a_first_message_whose_discovery_key_vouches_for_another_identity_is_rejected() {
        let alice = sender(0x10);
        let mallory = sender(0x20);
        let alices_discovery_key = discovery_key(&alice, 0x11);

        assert!(matches!(
            authenticate(&alice, &alices_discovery_key, &mallory.identity),
            Err(ProtocolStateError::InvalidMessage { reason })
                if reason == "sender discovery key does not sign its identity key"
        ));
    }

    #[test]
    fn a_session_id_swapped_under_the_discovery_key_fails_the_ratchet_layer() {
        let alice = sender(0x10);
        let alice_discovery_key = discovery_key(&alice, 0x11);
        let bob = sender(0x30);
        let bob_discovery_key = discovery_key(&bob, 0x31);
        let signed_prekey = generate_signed_prekey_for_discovery_key(
            &mut ChaCha20Rng::from_seed([0x32; 32]),
            &bob_discovery_key,
            0,
            1_700_000_000,
        )
        .unwrap();
        let bundle = PreKeyBundle {
            version: PREKEY_BUNDLE_VERSION,
            discovery_key: bob_discovery_key.public(),
            signed_prekey: signed_prekey.public(),
            one_time_prekey: None,
        };
        let mut rng = ChaCha20Rng::from_seed([0x33; 32]);
        let (mut sending, session_id, handshake) =
            initiate_handshake(&mut rng, &bob.identity, &bundle).unwrap();
        let (mut receiving, _) =
            accept_handshake(&handshake, &bob_discovery_key, &signed_prekey, None).unwrap();
        let binding = TransportBinding::new(b"route".to_vec()).unwrap();
        let limits = ProtocolHardeningLimits::default();
        let agreement_key = KeyPair::from_secret_bytes([0x11; 32]);
        let alice_public_discovery_key = alice_discovery_key.public();
        let discovery_to_identity = alice_discovery_key
            .sign_identity_binding(&alice.identity)
            .unwrap();
        let message = seal_signed(
            &mut rng,
            &mut sending,
            OutboundContent {
                session_id,
                id: MessageId::from_bytes([3; 16]),
                sent_at_millis: 4,
                payload_kind: PayloadKind::EncryptedText,
                payload: b"hello bob",
            },
            SignedRecipient {
                discovery_key: *bob_discovery_key.public_key().as_bytes(),
                identity_verifying_key: &bob.material.identity_verifying_key,
            },
            &LocalSender {
                identity: &alice.material,
                signing_key: &alice.signing_key,
                agreement_key: &agreement_key,
                discovery_key: &alice_public_discovery_key,
                discovery_to_identity: &discovery_to_identity,
            },
            &binding,
            limits,
        )
        .unwrap();
        // Whoever holds Bob's Discovery Key seals the same ratchet ciphertext under another
        // SessionID.
        let plaintext = open_frame_for_discovery_key_with_associated_data(
            &bob_discovery_key,
            &message,
            binding.as_bytes(),
        )
        .unwrap();
        let wire: DecodedFramePlaintextWire = postcard::from_bytes(&plaintext).unwrap();
        let swapped = seal_frame_with_associated_data(
            &mut rng,
            bob_discovery_key.public_key(),
            None,
            &postcard::to_stdvec(&FramePlaintextWire {
                session_id: [0x75; 16],
                base_key: wire.base_key,
                id: wire.id,
                sent_at_millis: wire.sent_at_millis,
                payload_kind: wire.payload_kind,
                ratchet_public_key: wire.ratchet_public_key,
                previous_chain_length: wire.previous_chain_length,
                message_number: wire.message_number,
                ciphertext: &wire.ciphertext,
            })
            .unwrap(),
            binding.as_bytes(),
        )
        .unwrap();
        let stored = receiving.to_bytes().unwrap();

        let swapped = open_message(&swapped, &bob_discovery_key, &binding).unwrap();
        assert_eq!(
            swapped.metadata.session_id,
            SessionId::from_bytes([0x75; 16])
        );
        assert!(matches!(
            swapped.decrypt(&mut rng, &mut receiving, limits),
            Err(ProtocolStateError::Ratchet(RatchetError::Aead))
        ));
        // The stored state still opens the genuine Message.
        let original = open_message(&message, &bob_discovery_key, &binding).unwrap();
        let decoded = original
            .decrypt(
                &mut rng,
                &mut RatchetState::from_bytes(&stored).unwrap(),
                limits,
            )
            .unwrap();
        assert_eq!(&*decoded.plaintext, b"hello bob");
    }
}
