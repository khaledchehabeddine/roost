//! FFI-safe sealed-sender Message records and encode/decode helpers.

use crate::error::RoostError;
use crate::records::{fixed_32, hex_identifier, hex_text};
use roost_core::Message as CoreMessage;
use roost_core::SealedFramePreKeyReference as CorePreKeyReference;

/// The identifier of one Message within a Session.
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

/// Transport-visible X3DH prekey reference in a sealed-sender frame.
#[derive(Clone, uniffi::Record)]
pub struct FramePreKeyReference {
    /// Recipient Discovery Key epoch.
    pub discovery_epoch: u32,
    /// Recipient signed-prekey X25519 public key. Always 32 bytes.
    pub signed_prekey_public_key: Vec<u8>,
    /// Optional one-time-prekey identifier.
    pub one_time_prekey_id: Option<u64>,
    /// Optional one-time-prekey X25519 public key. Always 32 bytes when present.
    pub one_time_prekey_public_key: Option<Vec<u8>>,
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

/// Sender identity material revealed only after ciphertext authentication.
#[derive(uniffi::Record)]
pub struct SenderIdentityMaterial {
    /// Sender Identity Key X25519 public bytes. Always 32 bytes.
    pub identity_key: Vec<u8>,
    /// Sender Identity Key Ed25519 verifying-key bytes. Always 32 bytes.
    pub identity_verifying_key: Vec<u8>,
    /// Signature binding the sender Identity Key halves.
    pub identity_binding_signature: Vec<u8>,
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
            identity_key: value.identity_key.to_vec(),
            identity_verifying_key: value.identity_verifying_key.to_vec(),
            identity_binding_signature: value.identity_binding_signature.clone(),
            certificate: value.certificate.clone(),
            signature: value.signature.clone(),
        }
    }
}

impl Message {
    pub(crate) fn from_core(message: CoreMessage) -> Self {
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

    pub(crate) fn to_core(&self) -> Result<CoreMessage, RoostError> {
        Ok(CoreMessage {
            version: self.version,
            recipient_public_key: fixed_32(&self.recipient_public_key, "recipient public key")?,
            prekey_reference: self
                .prekey_reference
                .as_ref()
                .map(FramePreKeyReference::to_core)
                .transpose()?,
            ephemeral_public_key: fixed_32(&self.ephemeral_public_key, "ephemeral public key")?,
            ciphertext: self.ciphertext.clone(),
        })
    }
}

impl FramePreKeyReference {
    fn from_core(reference: CorePreKeyReference) -> Self {
        Self {
            discovery_epoch: reference.discovery_epoch,
            signed_prekey_public_key: reference.signed_prekey_public_key.to_vec(),
            one_time_prekey_id: reference.one_time_prekey_id,
            one_time_prekey_public_key: reference
                .one_time_prekey_public_key
                .map(|public_key| public_key.to_vec()),
        }
    }

    fn to_core(&self) -> Result<CorePreKeyReference, RoostError> {
        Ok(CorePreKeyReference {
            discovery_epoch: self.discovery_epoch,
            signed_prekey_public_key: fixed_32(
                &self.signed_prekey_public_key,
                "signed pre-key public key",
            )?,
            one_time_prekey_id: self.one_time_prekey_id,
            one_time_prekey_public_key: self
                .one_time_prekey_public_key
                .as_deref()
                .map(|public_key| fixed_32(public_key, "one-time pre-key public key"))
                .transpose()?,
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
#[uniffi::export]
pub fn encode_message(message: Message) -> Result<Vec<u8>, RoostError> {
    Ok(message.to_core()?.to_bytes()?)
}

/// Decodes canonical sealed-frame bytes into transport-visible fields.
#[uniffi::export]
pub fn decode_message(bytes: Vec<u8>) -> Result<Message, RoostError> {
    Ok(Message::from_core(CoreMessage::from_bytes(&bytes)?))
}
