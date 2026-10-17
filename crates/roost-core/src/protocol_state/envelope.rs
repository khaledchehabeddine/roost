//! The layers inside a Sealed Sender Frame: the part sealed to the recipient's Discovery Key, the
//! ratchet ciphertext, and the Sealed Sender Envelope inside it.

use super::{ProtocolStateError, encode_zeroizing, unpad_sealed_payload};
use crate::contact::ContactIdentityKey;
use crate::hardening::ProtocolHardeningLimits;
use crate::{Message, MessageId, PayloadKind, TransportBinding};
use rand::{CryptoRng, RngCore};
use roost_crypto::{
    DiscoveryKey, Header, PublicDiscoveryKey, PublicIdentityKey, PublicKey, RatchetState,
    SENDER_PROOF_LEN, SealedFramePreKeyReference, Signature, SigningKeyPair,
    open_frame_for_discovery_key_with_associated_data, seal_frame_with_associated_data,
    verify_public_identity_key,
};
use roost_protocol::{
    MESSAGE_TRANSCRIPT_CONTEXT, MessageTranscriptInput, PUBLIC_KEY_LEN, SessionId,
    is_valid_x25519_public_key, message_transcript, parse_ed25519_verifying_key_bytes,
    verify_with_context,
};
use serde::{Deserialize, Serialize};
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
pub(super) fn seal_message<R: RngCore + CryptoRng>(
    rng: &mut R,
    state: &mut RatchetState,
    metadata: MessageMetadata,
    recipient_public_key: [u8; PUBLIC_KEY_LEN],
    prekey_reference: Option<SealedFramePreKeyReference>,
    envelope: &[u8],
    transport_binding: &TransportBinding,
) -> Result<Message, ProtocolStateError> {
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
    let frame = seal_frame_with_associated_data(
        rng,
        &PublicKey::from(recipient_public_key),
        prekey_reference,
        &frame_plaintext,
        transport_binding.as_bytes(),
    )?;
    let message = Message::from_frame(frame);
    message
        .to_bytes()
        .map_err(ProtocolStateError::MessageEncode)?;
    Ok(message)
}

/// Opens the layer of `message` sealed to `recipient_discovery_key`.
///
/// Nothing in the result is authenticated beyond having been sealed to this Discovery Key, which
/// anyone can do, until its ratchet ciphertext decrypts.
pub(super) fn open_message(
    message: &Message,
    recipient_discovery_key: &DiscoveryKey,
    transport_binding: &TransportBinding,
) -> Result<OpenedMessage, ProtocolStateError> {
    let frame_plaintext = open_frame_for_discovery_key_with_associated_data(
        recipient_discovery_key,
        &message.to_frame(),
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
pub(super) enum OutboundAuthentication<'a> {
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

pub(super) fn encode_sealed_sender_envelope(
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

pub(super) fn sign_message_transcript(
    signing_key: &SigningKeyPair,
    input: MessageTranscriptInput<'_>,
) -> Result<Signature, ProtocolStateError> {
    let transcript =
        message_transcript(input).map_err(|_| invalid("message transcript input exceeds limit"))?;
    Ok(signing_key.sign_with_context(MESSAGE_TRANSCRIPT_CONTEXT, &transcript)?)
}

pub(super) fn verify_message_transcript(
    sender_identity: &SenderIdentityMaterial,
    input: MessageTranscriptInput<'_>,
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), ProtocolStateError> {
    let signature = Signature::from_bytes(signature);
    let verifying_key = parse_ed25519_verifying_key_bytes(&sender_identity.identity_verifying_key)
        .ok_or_else(|| invalid("sender identity verifying key is invalid"))?;
    let transcript =
        message_transcript(input).map_err(|_| invalid("message transcript input exceeds limit"))?;
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
    use roost_crypto::{KeyPair, sign_identity_key_binding};
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
}
