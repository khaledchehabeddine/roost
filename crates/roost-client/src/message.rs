use crate::encoding::{fixed_32, hex_identifier, hex_text};
use crate::error::RoostError;
use crate::identity::{Identity, IdentityKey};
use roost_core::{OneTimePreKeyReference, SealedFrame, SealedFramePreKeyReference};

/// The identifier a sender gives a Message, which a resend after recovery keeps.
///
/// The value is 32 lowercase hexadecimal digits, so it compares and hashes as a plain string.
#[derive(Clone, Debug, Eq, Hash, PartialEq, uniffi::Record)]
pub struct MessageId {
    /// The identifier's canonical text.
    pub value: String,
}

impl MessageId {
    pub(crate) fn from_core(id: roost_protocol::MessageId) -> Self {
        Self {
            value: hex_text(id.as_bytes()),
        }
    }

    pub(crate) fn to_core(&self) -> Result<roost_protocol::MessageId, RoostError> {
        Ok(roost_protocol::MessageId::from_bytes(hex_identifier(
            &self.value,
            "message id",
        )?))
    }
}

/// The identifier both peers derive for a Session, which addresses its state.
///
/// The value is 32 lowercase hexadecimal digits, so it compares and hashes as a plain string.
#[derive(Clone, Debug, Eq, Hash, PartialEq, uniffi::Record)]
pub struct SessionId {
    /// The identifier's canonical text.
    pub value: String,
}

impl SessionId {
    pub(crate) fn from_core(id: roost_core::SessionId) -> Self {
        Self {
            value: hex_text(id.as_bytes()),
        }
    }
}

/// Transport-visible X3DH prekey reference in a sealed-sender frame.
#[derive(Clone, uniffi::Record)]
pub struct FramePreKeyReference {
    /// Recipient Discovery Key epoch.
    pub discovery_epoch: u32,
    /// Recipient signed-prekey X25519 public key. Always 32 bytes.
    pub signed_prekey_public_key: Vec<u8>,
    /// The recipient one-time prekey the handshake used, if one was left.
    pub one_time_prekey: Option<FrameOneTimePreKeyReference>,
}

/// The one-time prekey a sealed-sender frame's handshake used.
#[derive(Clone, uniffi::Record)]
pub struct FrameOneTimePreKeyReference {
    /// The prekey's identifier.
    pub id: u64,
    /// The prekey's X25519 public key. Always 32 bytes.
    pub public_key: Vec<u8>,
}

/// Transport-visible sealed-sender frame exchanged as a Message.
#[derive(Clone, uniffi::Record)]
pub struct Message {
    /// Sealed-frame wire version.
    pub version: u8,
    /// Recipient Discovery Key X25519 public key. Always 32 bytes.
    pub recipient_public_key: Vec<u8>,
    /// X3DH prekey reference, present while a new Session's Messages carry the handshake.
    pub prekey_reference: Option<FramePreKeyReference>,
    /// Per-frame ephemeral X25519 public key. Always 32 bytes.
    pub ephemeral_public_key: Vec<u8>,
    /// Opaque AEAD ciphertext.
    pub ciphertext: Vec<u8>,
}

/// The sender's identity and certificate, revealed only after the Message authenticates.
#[derive(uniffi::Record)]
pub struct SenderIdentityMaterial {
    /// The sender's identity.
    pub identity: Identity,
    /// Opaque sender certificate bytes.
    pub certificate: Vec<u8>,
    /// Opaque sender signature bytes.
    pub signature: Vec<u8>,
}

/// Payload kind recovered after decrypt.
#[derive(uniffi::Enum)]
pub enum PayloadKind {
    /// Encrypted application text content.
    EncryptedText,
    /// Delivery or processing acknowledgment.
    Acknowledgment,
    /// Encrypted application text that carried the sender's Inbox Grant, which Roost kept.
    EncryptedTextWithGrant,
    /// A Contact Acceptance and its encrypted application text.
    ContactAcceptance,
    /// An acknowledgment that carried the sender's Inbox Grant, which Roost kept.
    AcknowledgmentWithGrant,
    /// A Grant Update, which carries only the sender's Inbox Grant.
    GrantUpdate,
}

impl SenderIdentityMaterial {
    pub(crate) fn from_core(value: roost_core::SenderIdentityMaterial) -> Self {
        Self {
            identity: Identity {
                key: IdentityKey {
                    agreement_key: value.identity_key.to_vec(),
                    signing_key: value.identity_verifying_key.to_vec(),
                },
                binding_signature: value.identity_binding_signature.clone(),
            },
            certificate: value.certificate.clone(),
            signature: value.signature.clone(),
        }
    }
}

impl Message {
    pub(crate) fn from_core(message: SealedFrame) -> Self {
        Self {
            version: message.version,
            recipient_public_key: message.recipient_public_key.to_vec(),
            prekey_reference: message
                .prekey_reference
                .map(FramePreKeyReference::from_core),
            ephemeral_public_key: message.ephemeral_public_key.to_vec(),
            ciphertext: message.ciphertext,
        }
    }

    pub(crate) fn into_core(self) -> Result<SealedFrame, RoostError> {
        Ok(SealedFrame {
            version: self.version,
            recipient_public_key: fixed_32(&self.recipient_public_key, "recipient public key")?,
            prekey_reference: self
                .prekey_reference
                .as_ref()
                .map(FramePreKeyReference::to_core)
                .transpose()?,
            ephemeral_public_key: fixed_32(&self.ephemeral_public_key, "ephemeral public key")?,
            ciphertext: self.ciphertext,
        })
    }
}

impl FramePreKeyReference {
    fn from_core(reference: SealedFramePreKeyReference) -> Self {
        Self {
            discovery_epoch: reference.discovery_epoch,
            signed_prekey_public_key: reference.signed_prekey_public_key.to_vec(),
            one_time_prekey: reference
                .one_time_prekey
                .map(FrameOneTimePreKeyReference::from_core),
        }
    }

    fn to_core(&self) -> Result<SealedFramePreKeyReference, RoostError> {
        Ok(SealedFramePreKeyReference {
            discovery_epoch: self.discovery_epoch,
            signed_prekey_public_key: fixed_32(
                &self.signed_prekey_public_key,
                "signed prekey public key",
            )?,
            one_time_prekey: self
                .one_time_prekey
                .as_ref()
                .map(FrameOneTimePreKeyReference::to_core)
                .transpose()?,
        })
    }
}

impl FrameOneTimePreKeyReference {
    fn from_core(reference: OneTimePreKeyReference) -> Self {
        Self {
            id: reference.id,
            public_key: reference.public_key.to_vec(),
        }
    }

    fn to_core(&self) -> Result<OneTimePreKeyReference, RoostError> {
        Ok(OneTimePreKeyReference {
            id: self.id,
            public_key: fixed_32(&self.public_key, "one-time prekey public key")?,
        })
    }
}

impl PayloadKind {
    pub(crate) fn from_protocol(value: roost_protocol::PayloadKind) -> Self {
        match value {
            roost_protocol::PayloadKind::EncryptedText => Self::EncryptedText,
            roost_protocol::PayloadKind::Acknowledgment => Self::Acknowledgment,
            roost_protocol::PayloadKind::EncryptedTextWithGrant => Self::EncryptedTextWithGrant,
            roost_protocol::PayloadKind::ContactAcceptance => Self::ContactAcceptance,
            roost_protocol::PayloadKind::AcknowledgmentWithGrant => Self::AcknowledgmentWithGrant,
            roost_protocol::PayloadKind::GrantUpdate => Self::GrantUpdate,
        }
    }
}

/// Encodes a Message into canonical sealed-frame bytes.
///
/// # Errors
/// - [`RoostError::InvalidData`] if a key has the wrong length or the Message is longer than
///   Roost's limits.
#[uniffi::export]
pub fn encode_message(message: Message) -> Result<Vec<u8>, RoostError> {
    Ok(message.into_core()?.to_bytes()?)
}

/// Decodes canonical sealed-frame bytes into transport-visible fields.
///
/// # Errors
/// - [`RoostError::UnsupportedVersion`] if the Message uses an unknown version.
/// - [`RoostError::InvalidData`] if the bytes are malformed or longer than Roost's limits.
#[uniffi::export]
pub fn decode_message(bytes: Vec<u8>) -> Result<Message, RoostError> {
    Ok(Message::from_core(SealedFrame::from_bytes(&bytes)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_message_reports_an_unknown_frame_version_as_unsupported() {
        assert!(matches!(
            decode_message(vec![u8::MAX]),
            Err(RoostError::UnsupportedVersion { .. })
        ));
    }
}
