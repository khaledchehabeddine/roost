//! Shared sealed-sender frame encryption.

use crate::discovery_key::DiscoveryKey;
use crate::keys::{KeyPair, PublicKey, is_valid_x25519_public_key};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const SEALED_FRAME_VERSION: u8 = 1;
const SEALED_FRAME_KEY_INFO: &[u8] = b"AetherSealedFrame-v1:key";
const SEALED_FRAME_NONCE_INFO: &[u8] = b"AetherSealedFrame-v1:nonce";
const EXTERNAL_ASSOCIATED_DATA_CONTEXT: &[u8] = b"AetherSealedFrame-v1:external-ad";
const XCHACHA20_POLY1305_KEY_LEN: usize = 32;
const XCHACHA20_POLY1305_NONCE_LEN: usize = 24;
const MAX_SEALED_FRAME_CIPHERTEXT_LEN: usize = 128 * 1024;
const MAX_SEALED_FRAME_ENCODED_LEN: usize = MAX_SEALED_FRAME_CIPHERTEXT_LEN + 256;
const MAX_EXTERNAL_ASSOCIATED_DATA_LEN: usize = 1024;

/// Optional X3DH prekey reference carried by an initial sealed-sender frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealedFramePreKeyReference {
    /// Recipient Discovery Key epoch targeted by the frame.
    pub discovery_epoch: u32,
    /// Recipient signed pre-key X25519 public key.
    pub signed_prekey_public_key: [u8; 32],
    /// Recipient one-time pre-key identifier, when used.
    pub one_time_prekey_id: Option<u64>,
    /// Recipient one-time pre-key X25519 public key, when used.
    pub one_time_prekey_public_key: Option<[u8; 32]>,
}

/// Transport-visible sealed-sender frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedFrame {
    /// Sealed-frame wire version.
    pub version: u8,
    /// Recipient Discovery Key X25519 public key.
    pub recipient_public_key: [u8; 32],
    /// Optional X3DH prekey reference.
    pub prekey_reference: Option<SealedFramePreKeyReference>,
    /// Per-frame ephemeral X25519 public key.
    pub ephemeral_public_key: [u8; 32],
    /// AEAD ciphertext.
    pub ciphertext: Vec<u8>,
}

impl SealedFrame {
    /// Current sealed-frame wire version.
    pub const VERSION: u8 = SEALED_FRAME_VERSION;
    /// Maximum encoded sealed-frame byte length accepted before Postcard parsing.
    pub const MAX_ENCODED_LEN: usize = MAX_SEALED_FRAME_ENCODED_LEN;

    /// Encodes the frame into canonical Postcard bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SealedFrameError> {
        validate_frame(self, FrameValidation::Encode)?;
        let bytes = postcard::to_stdvec(&SealedFrameWire::from(self))
            .map_err(|_| SealedFrameError::Encode)?;
        if bytes.len() > MAX_SEALED_FRAME_ENCODED_LEN {
            return Err(SealedFrameError::Encode);
        }
        Ok(bytes)
    }

    /// Decodes a canonical sealed-frame byte sequence.
    ///
    /// Unsupported versions and oversized inputs are rejected before full Postcard parsing.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SealedFrameError> {
        if bytes.len() > MAX_SEALED_FRAME_ENCODED_LEN {
            return Err(SealedFrameError::Decode);
        }
        let version = *bytes.first().ok_or(SealedFrameError::Decode)?;
        if version != SEALED_FRAME_VERSION {
            return Err(SealedFrameError::Decode);
        }

        let (wire, trailing): (SealedFrameWire, &[u8]) =
            postcard::take_from_bytes(bytes).map_err(|_| SealedFrameError::Decode)?;
        if !trailing.is_empty() {
            return Err(SealedFrameError::Decode);
        }
        let frame = SealedFrame::from(wire);
        validate_frame(&frame, FrameValidation::Decode)?;
        Ok(frame)
    }
}

/// Encrypts plaintext into a sealed-sender frame for `recipient_public_key`.
pub fn seal_frame<R: RngCore + CryptoRng>(
    rng: &mut R,
    recipient_public_key: &PublicKey,
    prekey_reference: Option<SealedFramePreKeyReference>,
    plaintext: &[u8],
) -> Result<SealedFrame, SealedFrameError> {
    seal_frame_with_associated_data(rng, recipient_public_key, prekey_reference, plaintext, &[])
}

/// Encrypts plaintext while authenticating caller-supplied transport associated data.
///
/// The additional bytes are authenticated but are not encoded into the returned frame. The
/// recipient must supply the same bytes to
/// [`open_frame_for_discovery_key_with_associated_data`].
pub fn seal_frame_with_associated_data<R: RngCore + CryptoRng>(
    rng: &mut R,
    recipient_public_key: &PublicKey,
    prekey_reference: Option<SealedFramePreKeyReference>,
    plaintext: &[u8],
    additional_associated_data: &[u8],
) -> Result<SealedFrame, SealedFrameError> {
    let ephemeral_key = crate::keys::generate_key_pair(rng);
    seal_frame_with_ephemeral_key_and_associated_data(
        &ephemeral_key,
        recipient_public_key,
        prekey_reference,
        plaintext,
        additional_associated_data,
    )
}

#[cfg(test)]
pub(crate) fn seal_frame_with_ephemeral_key(
    ephemeral_key: &KeyPair,
    recipient_public_key: &PublicKey,
    prekey_reference: Option<SealedFramePreKeyReference>,
    plaintext: &[u8],
) -> Result<SealedFrame, SealedFrameError> {
    seal_frame_with_ephemeral_key_and_associated_data(
        ephemeral_key,
        recipient_public_key,
        prekey_reference,
        plaintext,
        &[],
    )
}

pub(crate) fn seal_frame_with_ephemeral_key_and_associated_data(
    ephemeral_key: &KeyPair,
    recipient_public_key: &PublicKey,
    prekey_reference: Option<SealedFramePreKeyReference>,
    plaintext: &[u8],
    additional_associated_data: &[u8],
) -> Result<SealedFrame, SealedFrameError> {
    let shared_secret = ephemeral_key.diffie_hellman(recipient_public_key);
    if !shared_secret.was_contributory() {
        return Err(SealedFrameError::NonContributorySharedSecret);
    }
    let frame = SealedFrame {
        version: SEALED_FRAME_VERSION,
        recipient_public_key: *recipient_public_key.as_bytes(),
        prekey_reference,
        ephemeral_public_key: *ephemeral_key.public.as_bytes(),
        ciphertext: Vec::new(),
    };
    validate_frame_public_fields(&frame, FrameValidation::Encode)?;
    let (key, nonce) = expand_frame_secret(shared_secret.as_bytes())?;
    let aad = frame_associated_data(&frame, additional_associated_data, FrameValidation::Encode)?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| SealedFrameError::Aead)?;
    if ciphertext.len() > MAX_SEALED_FRAME_CIPHERTEXT_LEN {
        return Err(SealedFrameError::Encode);
    }
    Ok(SealedFrame {
        ciphertext,
        ..frame
    })
}

/// Opens a sealed-sender frame for the local recipient Discovery Key.
pub fn open_frame(
    recipient_key: &KeyPair,
    frame: &SealedFrame,
) -> Result<Zeroizing<Vec<u8>>, SealedFrameError> {
    open_frame_with_associated_data(recipient_key, frame, &[])
}

/// Opens a sealed-sender frame while authenticating caller-supplied transport associated data.
fn open_frame_with_associated_data(
    recipient_key: &KeyPair,
    frame: &SealedFrame,
    additional_associated_data: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SealedFrameError> {
    validate_frame(frame, FrameValidation::Decode)?;
    let recipient_matches: bool = frame
        .recipient_public_key
        .ct_eq(recipient_key.public.as_bytes())
        .into();
    if !recipient_matches {
        return Err(SealedFrameError::Decode);
    }

    let ephemeral_public_key = PublicKey::from(frame.ephemeral_public_key);
    let shared_secret = recipient_key.diffie_hellman(&ephemeral_public_key);
    if !shared_secret.was_contributory() {
        return Err(SealedFrameError::NonContributorySharedSecret);
    }
    let (key, nonce) = expand_frame_secret(shared_secret.as_bytes())?;
    let aad = frame_associated_data(frame, additional_associated_data, FrameValidation::Decode)?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &frame.ciphertext,
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| SealedFrameError::Aead)
}

/// Opens a sealed-sender frame for the local recipient Discovery Key.
pub fn open_frame_for_discovery_key(
    recipient_key: &DiscoveryKey,
    frame: &SealedFrame,
) -> Result<Zeroizing<Vec<u8>>, SealedFrameError> {
    open_frame_for_discovery_key_with_associated_data(recipient_key, frame, &[])
}

/// Opens a sealed-sender frame for a Discovery Key while authenticating caller-supplied transport
/// associated data.
pub fn open_frame_for_discovery_key_with_associated_data(
    recipient_key: &DiscoveryKey,
    frame: &SealedFrame,
    additional_associated_data: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SealedFrameError> {
    validate_frame(frame, FrameValidation::Decode)?;
    let recipient_matches: bool = frame
        .recipient_public_key
        .ct_eq(recipient_key.public_key().as_bytes())
        .into();
    if !recipient_matches {
        return Err(SealedFrameError::Decode);
    }

    let ephemeral_public_key = PublicKey::from(frame.ephemeral_public_key);
    let shared_secret = recipient_key.diffie_hellman(&ephemeral_public_key);
    if !shared_secret.was_contributory() {
        return Err(SealedFrameError::NonContributorySharedSecret);
    }
    let (key, nonce) = expand_frame_secret(shared_secret.as_bytes())?;
    let aad = frame_associated_data(frame, additional_associated_data, FrameValidation::Decode)?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &frame.ciphertext,
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| SealedFrameError::Aead)
}

/// An error returned while encoding, decoding, sealing, or opening a [`SealedFrame`].
#[derive(Debug, thiserror::Error)]
pub enum SealedFrameError {
    /// XChaCha20-Poly1305 encryption, decryption, or authentication failed.
    #[error("xchacha20-poly1305 encryption or decryption failed")]
    Aead,
    /// Frame bytes or fields are malformed, unsupported, oversized, or target another recipient.
    #[error("sealed-sender frame bytes failed to decode")]
    Decode,
    /// Frame fields, ciphertext, or additional associated data exceed local caps or fail to encode.
    #[error("sealed-sender frame failed to encode")]
    Encode,
    /// HKDF-SHA256 rejected the requested output length.
    #[error("hkdf-sha256 expand exceeded output limit")]
    HkdfExpand,
    /// An X25519 exchange produced a non-contributory shared secret.
    #[error("x25519 shared secret was non-contributory")]
    NonContributorySharedSecret,
}

#[derive(Deserialize, Serialize)]
struct SealedFrameWire {
    version: u8,
    recipient_public_key: [u8; 32],
    prekey_reference: Option<SealedFramePreKeyReferenceWire>,
    ephemeral_public_key: [u8; 32],
    ciphertext: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
struct SealedFramePreKeyReferenceWire {
    discovery_epoch: u32,
    signed_prekey_public_key: [u8; 32],
    one_time_prekey_id: Option<u64>,
    one_time_prekey_public_key: Option<[u8; 32]>,
}

impl From<&SealedFrame> for SealedFrameWire {
    fn from(value: &SealedFrame) -> Self {
        Self {
            version: value.version,
            recipient_public_key: value.recipient_public_key,
            prekey_reference: value.prekey_reference.map(Into::into),
            ephemeral_public_key: value.ephemeral_public_key,
            ciphertext: value.ciphertext.clone(),
        }
    }
}

impl From<SealedFrameWire> for SealedFrame {
    fn from(value: SealedFrameWire) -> Self {
        Self {
            version: value.version,
            recipient_public_key: value.recipient_public_key,
            prekey_reference: value.prekey_reference.map(Into::into),
            ephemeral_public_key: value.ephemeral_public_key,
            ciphertext: value.ciphertext,
        }
    }
}

impl From<SealedFramePreKeyReference> for SealedFramePreKeyReferenceWire {
    fn from(value: SealedFramePreKeyReference) -> Self {
        Self {
            discovery_epoch: value.discovery_epoch,
            signed_prekey_public_key: value.signed_prekey_public_key,
            one_time_prekey_id: value.one_time_prekey_id,
            one_time_prekey_public_key: value.one_time_prekey_public_key,
        }
    }
}

impl From<SealedFramePreKeyReferenceWire> for SealedFramePreKeyReference {
    fn from(value: SealedFramePreKeyReferenceWire) -> Self {
        Self {
            discovery_epoch: value.discovery_epoch,
            signed_prekey_public_key: value.signed_prekey_public_key,
            one_time_prekey_id: value.one_time_prekey_id,
            one_time_prekey_public_key: value.one_time_prekey_public_key,
        }
    }
}

fn expand_frame_secret(
    secret: &[u8; 32],
) -> Result<
    (
        Zeroizing<[u8; XCHACHA20_POLY1305_KEY_LEN]>,
        [u8; XCHACHA20_POLY1305_NONCE_LEN],
    ),
    SealedFrameError,
> {
    let hkdf = Hkdf::<Sha256>::new(None, secret);
    let mut key = Zeroizing::new([0u8; XCHACHA20_POLY1305_KEY_LEN]);
    let mut nonce = [0u8; XCHACHA20_POLY1305_NONCE_LEN];
    hkdf.expand(SEALED_FRAME_KEY_INFO, key.as_mut())
        .map_err(|_| SealedFrameError::HkdfExpand)?;
    hkdf.expand(SEALED_FRAME_NONCE_INFO, &mut nonce)
        .map_err(|_| SealedFrameError::HkdfExpand)?;
    Ok((key, nonce))
}

fn frame_associated_data(
    frame: &SealedFrame,
    additional_associated_data: &[u8],
    validation: FrameValidation,
) -> Result<Vec<u8>, SealedFrameError> {
    if additional_associated_data.len() > MAX_EXTERNAL_ASSOCIATED_DATA_LEN {
        return Err(validation.error());
    }
    let mut associated_data = postcard::to_stdvec(&SealedFrameAssociatedDataWire {
        version: frame.version,
        recipient_public_key: frame.recipient_public_key,
        prekey_reference: frame.prekey_reference.map(Into::into),
        ephemeral_public_key: frame.ephemeral_public_key,
    })
    .map_err(|_| validation.error())?;
    if !additional_associated_data.is_empty() {
        associated_data.extend_from_slice(EXTERNAL_ASSOCIATED_DATA_CONTEXT);
        associated_data.extend_from_slice(&(additional_associated_data.len() as u32).to_be_bytes());
        associated_data.extend_from_slice(additional_associated_data);
    }
    Ok(associated_data)
}

#[derive(Serialize)]
struct SealedFrameAssociatedDataWire {
    version: u8,
    recipient_public_key: [u8; 32],
    prekey_reference: Option<SealedFramePreKeyReferenceWire>,
    ephemeral_public_key: [u8; 32],
}

#[derive(Clone, Copy)]
enum FrameValidation {
    Encode,
    Decode,
}

impl FrameValidation {
    fn error(self) -> SealedFrameError {
        match self {
            Self::Encode => SealedFrameError::Encode,
            Self::Decode => SealedFrameError::Decode,
        }
    }
}

fn validate_frame(
    frame: &SealedFrame,
    validation: FrameValidation,
) -> Result<(), SealedFrameError> {
    validate_frame_public_fields(frame, validation)?;
    if frame.ciphertext.len() > MAX_SEALED_FRAME_CIPHERTEXT_LEN {
        return Err(validation.error());
    }
    Ok(())
}

fn validate_frame_public_fields(
    frame: &SealedFrame,
    validation: FrameValidation,
) -> Result<(), SealedFrameError> {
    if frame.version != SEALED_FRAME_VERSION
        || !is_valid_x25519_public_key(&frame.recipient_public_key)
        || !is_valid_x25519_public_key(&frame.ephemeral_public_key)
    {
        return Err(validation.error());
    }
    if let Some(reference) = frame.prekey_reference {
        validate_prekey_reference(reference, validation)?;
    }
    Ok(())
}

fn validate_prekey_reference(
    reference: SealedFramePreKeyReference,
    validation: FrameValidation,
) -> Result<(), SealedFrameError> {
    if !is_valid_x25519_public_key(&reference.signed_prekey_public_key)
        || reference.one_time_prekey_id.is_some() != reference.one_time_prekey_public_key.is_some()
        || reference
            .one_time_prekey_public_key
            .is_some_and(|key| !is_valid_x25519_public_key(&key))
    {
        return Err(validation.error());
    }
    Ok(())
}
