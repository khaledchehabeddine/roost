use crate::discovery_key::DiscoveryKey;
use crate::keys::{PublicKey, generate_key_pair};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use roost_protocol::is_valid_x25519_public_key;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const SEALED_FRAME_VERSION: u8 = 1;
const SEALED_FRAME_KEY_INFO: &[u8] = b"RoostSealedFrame-v1:key";
const SEALED_FRAME_NONCE_INFO: &[u8] = b"RoostSealedFrame-v1:nonce";
const EXTERNAL_ASSOCIATED_DATA_CONTEXT: &[u8] = b"RoostSealedFrame-v1:external-ad";
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
    /// Maximum encoded sealed-frame byte length accepted before Postcard parsing.
    pub const MAX_ENCODED_LEN: usize = MAX_SEALED_FRAME_ENCODED_LEN;

    /// Encodes the frame into canonical Postcard bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SealedFrameError> {
        self.validate()?;
        let bytes = postcard::to_stdvec(&SealedFrameWire::from(self))
            .map_err(|_| SealedFrameError::Encode)?;
        if bytes.len() > MAX_SEALED_FRAME_ENCODED_LEN {
            return Err(SealedFrameError::FrameTooLong {
                len: bytes.len(),
                max: MAX_SEALED_FRAME_ENCODED_LEN,
            });
        }
        Ok(bytes)
    }

    /// Decodes a canonical sealed-frame byte sequence.
    ///
    /// Unsupported versions and oversized inputs are rejected before full Postcard parsing.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SealedFrameError> {
        if bytes.len() > MAX_SEALED_FRAME_ENCODED_LEN {
            return Err(SealedFrameError::FrameTooLong {
                len: bytes.len(),
                max: MAX_SEALED_FRAME_ENCODED_LEN,
            });
        }
        let version = *bytes.first().ok_or(SealedFrameError::Decode)?;
        if version != SEALED_FRAME_VERSION {
            return Err(SealedFrameError::UnsupportedVersion(version));
        }

        let (wire, trailing): (SealedFrameWire, &[u8]) =
            postcard::take_from_bytes(bytes).map_err(|_| SealedFrameError::Decode)?;
        if !trailing.is_empty() {
            return Err(SealedFrameError::TrailingBytes {
                len: trailing.len(),
            });
        }
        let frame = SealedFrame::from(wire);
        frame.validate()?;
        Ok(frame)
    }

    fn validate(&self) -> Result<(), SealedFrameError> {
        self.validate_public_fields()?;
        check_ciphertext_len(self.ciphertext.len())
    }

    // Checks every field but the ciphertext, which sealing produces after this check.
    fn validate_public_fields(&self) -> Result<(), SealedFrameError> {
        if self.version != SEALED_FRAME_VERSION {
            return Err(SealedFrameError::UnsupportedVersion(self.version));
        }
        let mut public_keys = vec![self.recipient_public_key, self.ephemeral_public_key];
        if let Some(reference) = self.prekey_reference {
            if reference.one_time_prekey_id.is_some()
                != reference.one_time_prekey_public_key.is_some()
            {
                return Err(SealedFrameError::IncompleteOneTimePreKey);
            }
            public_keys.push(reference.signed_prekey_public_key);
            public_keys.extend(reference.one_time_prekey_public_key);
        }
        if !public_keys.iter().all(is_valid_x25519_public_key) {
            return Err(SealedFrameError::InvalidPublicKey);
        }
        Ok(())
    }
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
    let ephemeral_key = generate_key_pair(rng).map_err(SealedFrameError::Randomness)?;
    let mut frame = SealedFrame {
        version: SEALED_FRAME_VERSION,
        recipient_public_key: *recipient_public_key.as_bytes(),
        prekey_reference,
        ephemeral_public_key: *ephemeral_key.public.as_bytes(),
        ciphertext: Vec::new(),
    };
    frame.validate_public_fields()?;
    let associated_data = frame_associated_data(&frame, additional_associated_data)?;
    let shared_secret = ephemeral_key
        .diffie_hellman(recipient_public_key)
        .ok_or(SealedFrameError::NonContributorySharedSecret)?;
    let (key, nonce) = expand_frame_secret(shared_secret.as_bytes())?;
    let ciphertext = XChaCha20Poly1305::new((&*key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &associated_data,
            },
        )
        .map_err(|_| SealedFrameError::Aead)?;
    check_ciphertext_len(ciphertext.len())?;
    frame.ciphertext = ciphertext;
    Ok(frame)
}

/// Opens a sealed-sender frame for a Discovery Key while authenticating caller-supplied transport
/// associated data.
pub fn open_frame_for_discovery_key_with_associated_data(
    recipient_key: &DiscoveryKey,
    frame: &SealedFrame,
    additional_associated_data: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SealedFrameError> {
    frame.validate()?;
    let recipient_matches: bool = frame
        .recipient_public_key
        .ct_eq(recipient_key.public_key().as_bytes())
        .into();
    if !recipient_matches {
        return Err(SealedFrameError::RecipientMismatch);
    }
    let associated_data = frame_associated_data(frame, additional_associated_data)?;

    let ephemeral_public_key = PublicKey::from(frame.ephemeral_public_key);
    let shared_secret = recipient_key
        .diffie_hellman(&ephemeral_public_key)
        .ok_or(SealedFrameError::NonContributorySharedSecret)?;
    let (key, nonce) = expand_frame_secret(shared_secret.as_bytes())?;
    XChaCha20Poly1305::new((&*key).into())
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &frame.ciphertext,
                aad: &associated_data,
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
    /// The caller's associated data is longer than a frame authenticates.
    #[error("sealed-sender frame associated data is {len} bytes, longer than {max}")]
    AssociatedDataTooLong {
        /// Associated data length in bytes.
        len: usize,
        /// Longest associated data in bytes.
        max: usize,
    },
    /// The ciphertext is longer than a frame carries.
    #[error("sealed-sender frame ciphertext is {len} bytes, longer than {max}")]
    CiphertextTooLong {
        /// Ciphertext length in bytes.
        len: usize,
        /// Longest ciphertext in bytes.
        max: usize,
    },
    /// Frame bytes aren't a Postcard-encoded frame.
    #[error("sealed-sender frame bytes failed to decode")]
    Decode,
    /// Postcard failed to encode the frame.
    #[error("sealed-sender frame failed to encode")]
    Encode,
    /// The encoded frame is longer than any frame this build encodes.
    #[error("sealed-sender frame is {len} bytes, longer than {max}")]
    FrameTooLong {
        /// Encoded frame length in bytes.
        len: usize,
        /// Longest encoded frame in bytes.
        max: usize,
    },
    /// HKDF-SHA256 rejected the requested output length.
    #[error("hkdf-sha256 expand exceeded output limit")]
    HkdfExpand,
    /// The frame's pre-key reference names a one-time pre-key by only its identifier or its key.
    #[error("sealed-sender frame names half of a one-time pre-key")]
    IncompleteOneTimePreKey,
    /// A frame or prekey-reference key isn't a valid X25519 public key.
    #[error("sealed-sender frame public key is invalid")]
    InvalidPublicKey,
    /// An X25519 exchange produced a non-contributory shared secret.
    #[error("x25519 shared secret was non-contributory")]
    NonContributorySharedSecret,
    /// The random number generator failed while generating the ephemeral key.
    #[error("sealed-sender frame randomness failed")]
    Randomness(#[source] rand::Error),
    /// The frame is sealed to another Discovery Key.
    #[error("sealed-sender frame targets another discovery key")]
    RecipientMismatch,
    /// Frame bytes have bytes left over after decoding.
    #[error("sealed-sender frame has {len} trailing bytes")]
    TrailingBytes {
        /// Number of bytes left over.
        len: usize,
    },
    /// The frame uses a version this build doesn't read.
    #[error("unsupported sealed-sender frame version: {0}")]
    UnsupportedVersion(u8),
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

fn check_ciphertext_len(len: usize) -> Result<(), SealedFrameError> {
    if len > MAX_SEALED_FRAME_CIPHERTEXT_LEN {
        return Err(SealedFrameError::CiphertextTooLong {
            len,
            max: MAX_SEALED_FRAME_CIPHERTEXT_LEN,
        });
    }
    Ok(())
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
) -> Result<Vec<u8>, SealedFrameError> {
    let additional_len = additional_associated_data.len();
    if additional_len > MAX_EXTERNAL_ASSOCIATED_DATA_LEN {
        return Err(SealedFrameError::AssociatedDataTooLong {
            len: additional_len,
            max: MAX_EXTERNAL_ASSOCIATED_DATA_LEN,
        });
    }
    let mut associated_data = postcard::to_stdvec(&SealedFrameAssociatedDataWire {
        version: frame.version,
        recipient_public_key: frame.recipient_public_key,
        prekey_reference: frame.prekey_reference.map(Into::into),
        ephemeral_public_key: frame.ephemeral_public_key,
    })
    .map_err(|_| SealedFrameError::Encode)?;
    if additional_len > 0 {
        associated_data.extend_from_slice(EXTERNAL_ASSOCIATED_DATA_CONTEXT);
        associated_data.extend_from_slice(&(additional_len as u32).to_be_bytes());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_key_and_nonce_change_with_the_secret() {
        let (key, nonce) = expand_frame_secret(&[0x01; 32]).unwrap();
        let (other_key, other_nonce) = expand_frame_secret(&[0x02; 32]).unwrap();

        assert_ne!(*other_key, *key);
        assert_ne!(other_nonce, nonce);
    }
}
