use crate::discovery_key::DiscoveryKey;
use crate::keys::{PublicKey, generate_key_pair};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use roost_protocol::{TransportBinding, is_valid_x25519_public_key};
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

/// The X3DH prekeys that a first message's sealed sender frame names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealedFramePreKeyReference {
    /// Recipient discovery key epoch targeted by the frame.
    pub discovery_epoch: u32,
    /// Recipient signed prekey X25519 public key.
    pub signed_prekey_public_key: [u8; 32],
    /// Recipient one-time prekey, when the handshake used one.
    pub one_time_prekey: Option<OneTimePreKeyReference>,
}

/// The one-time prekey a handshake used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OneTimePreKeyReference {
    /// The prekey's ID within its discovery key epoch.
    pub id: u64,
    /// The prekey's X25519 public key.
    pub public_key: [u8; 32],
}

/// A sealed sender frame as the transport sees it.
#[derive(Clone)]
pub struct SealedFrame {
    /// Recipient discovery key X25519 public key.
    pub recipient_public_key: [u8; 32],
    /// The prekeys a first message names, or `None` on an established message.
    pub prekey_reference: Option<SealedFramePreKeyReference>,
    /// Per-frame ephemeral X25519 public key.
    pub ephemeral_public_key: [u8; 32],
    /// AEAD ciphertext.
    pub ciphertext: Vec<u8>,
}

impl SealedFrame {
    /// Maximum encoded sealed-frame byte length accepted before Postcard parsing.
    pub const MAX_ENCODED_LEN: usize = MAX_SEALED_FRAME_ENCODED_LEN;
    /// Maximum ciphertext byte length a frame carries.
    pub const MAX_CIPHERTEXT_LEN: usize = MAX_SEALED_FRAME_CIPHERTEXT_LEN;

    /// Encodes the frame into canonical Postcard bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SealedFrameError> {
        self.validate()?;
        postcard::to_stdvec(&SealedFrameWire::new(self, &self.ciphertext))
            .map_err(|_| SealedFrameError::Encode)
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
        let (&version, rest) = bytes.split_first().ok_or(SealedFrameError::Decode)?;
        if version != SEALED_FRAME_VERSION {
            return Err(SealedFrameError::UnsupportedVersion { version });
        }

        let (wire, trailing): (DecodedSealedFrameWire, &[u8]) =
            postcard::take_from_bytes(rest).map_err(|_| SealedFrameError::Decode)?;
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
        let mut public_keys = vec![self.recipient_public_key, self.ephemeral_public_key];
        if let Some(reference) = self.prekey_reference {
            public_keys.push(reference.signed_prekey_public_key);
            public_keys.extend(reference.one_time_prekey.map(|prekey| prekey.public_key));
        }
        if !public_keys.iter().all(is_valid_x25519_public_key) {
            return Err(SealedFrameError::InvalidPublicKey);
        }
        Ok(())
    }
}

/// Encrypts plaintext, authenticating it with the frame's visible fields and `transport_binding`.
///
/// The frame doesn't carry the transport binding, so the recipient must pass the same one to
/// [`open_frame_for_discovery_key_with_associated_data`].
pub fn seal_frame_with_associated_data<R: RngCore + CryptoRng>(
    rng: &mut R,
    recipient_public_key: &PublicKey,
    prekey_reference: Option<SealedFramePreKeyReference>,
    plaintext: &[u8],
    transport_binding: &TransportBinding,
) -> Result<SealedFrame, SealedFrameError> {
    let ephemeral_key = generate_key_pair(rng);
    let mut frame = SealedFrame {
        recipient_public_key: *recipient_public_key.as_bytes(),
        prekey_reference,
        ephemeral_public_key: *ephemeral_key.public.as_bytes(),
        ciphertext: Vec::new(),
    };
    frame.validate_public_fields()?;
    let associated_data = frame_associated_data(&frame, transport_binding)?;
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

/// Opens a sealed sender frame for a discovery key, checking it against `transport_binding`.
pub fn open_frame_for_discovery_key_with_associated_data(
    recipient_key: &DiscoveryKey,
    frame: &SealedFrame,
    transport_binding: &TransportBinding,
) -> Result<Zeroizing<Vec<u8>>, SealedFrameError> {
    frame.validate()?;
    let recipient_matches: bool = frame
        .recipient_public_key
        .ct_eq(recipient_key.public_key().as_bytes())
        .into();
    if !recipient_matches {
        return Err(SealedFrameError::RecipientMismatch);
    }
    let associated_data = frame_associated_data(frame, transport_binding)?;

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
    /// A frame or prekey-reference key isn't a valid X25519 public key.
    #[error("sealed-sender frame public key is invalid")]
    InvalidPublicKey,
    /// An X25519 exchange produced a non-contributory shared secret.
    #[error("x25519 shared secret was non-contributory")]
    NonContributorySharedSecret,
    /// The frame is sealed to another discovery key.
    #[error("sealed-sender frame targets another discovery key")]
    RecipientMismatch,
    /// Frame bytes have bytes left over after decoding.
    #[error("sealed-sender frame has {len} trailing bytes")]
    TrailingBytes {
        /// Number of bytes left over.
        len: usize,
    },
    /// The frame uses a version this build doesn't read.
    #[error("unsupported sealed-sender frame version: {version}")]
    UnsupportedVersion {
        /// The version the frame names.
        version: u8,
    },
}

#[derive(Serialize)]
struct SealedFrameWire<'a> {
    version: u8,
    recipient_public_key: [u8; 32],
    prekey_reference: Option<SealedFramePreKeyReferenceWire>,
    ephemeral_public_key: [u8; 32],
    ciphertext: &'a [u8],
}

impl<'a> SealedFrameWire<'a> {
    fn new(frame: &SealedFrame, ciphertext: &'a [u8]) -> Self {
        Self {
            version: SEALED_FRAME_VERSION,
            recipient_public_key: frame.recipient_public_key,
            prekey_reference: frame.prekey_reference.map(Into::into),
            ephemeral_public_key: frame.ephemeral_public_key,
            ciphertext,
        }
    }
}

// Everything after the version byte, which `SealedFrame::from_bytes` reads first.
#[derive(Deserialize)]
struct DecodedSealedFrameWire {
    recipient_public_key: [u8; 32],
    prekey_reference: Option<SealedFramePreKeyReferenceWire>,
    ephemeral_public_key: [u8; 32],
    ciphertext: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
struct SealedFramePreKeyReferenceWire {
    discovery_epoch: u32,
    signed_prekey_public_key: [u8; 32],
    one_time_prekey: Option<OneTimePreKeyReferenceWire>,
}

#[derive(Deserialize, Serialize)]
struct OneTimePreKeyReferenceWire {
    id: u64,
    public_key: [u8; 32],
}

impl From<DecodedSealedFrameWire> for SealedFrame {
    fn from(value: DecodedSealedFrameWire) -> Self {
        Self {
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
            one_time_prekey: value
                .one_time_prekey
                .map(|prekey| OneTimePreKeyReferenceWire {
                    id: prekey.id,
                    public_key: prekey.public_key,
                }),
        }
    }
}

impl From<SealedFramePreKeyReferenceWire> for SealedFramePreKeyReference {
    fn from(value: SealedFramePreKeyReferenceWire) -> Self {
        Self {
            discovery_epoch: value.discovery_epoch,
            signed_prekey_public_key: value.signed_prekey_public_key,
            one_time_prekey: value.one_time_prekey.map(|prekey| OneTimePreKeyReference {
                id: prekey.id,
                public_key: prekey.public_key,
            }),
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

// Authenticates the frame's visible fields, encoded as a frame with no ciphertext, and the
// transport binding.
fn frame_associated_data(
    frame: &SealedFrame,
    transport_binding: &TransportBinding,
) -> Result<Vec<u8>, SealedFrameError> {
    let binding = transport_binding.as_bytes();
    let mut associated_data = postcard::to_stdvec(&SealedFrameWire::new(frame, &[]))
        .map_err(|_| SealedFrameError::Encode)?;
    associated_data.extend_from_slice(EXTERNAL_ASSOCIATED_DATA_CONTEXT);
    // A transport binding holds at most 1,024 bytes.
    associated_data.extend_from_slice(&(binding.len() as u32).to_be_bytes());
    associated_data.extend_from_slice(binding);
    Ok(associated_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery_key::generate_discovery_key;
    use crate::keys::{KeyPair, generate_signing_key_pair};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn recipient_discovery_key(seed: u8) -> DiscoveryKey {
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        let signing_key = generate_signing_key_pair(&mut rng);
        generate_discovery_key(&mut rng, &signing_key, 1, 1_700_000_000).unwrap()
    }

    fn binding(bytes: &[u8]) -> TransportBinding {
        TransportBinding::new(bytes.to_vec()).unwrap()
    }

    fn prekey_reference() -> SealedFramePreKeyReference {
        SealedFramePreKeyReference {
            discovery_epoch: 7,
            signed_prekey_public_key: [0x51; 32],
            one_time_prekey: Some(OneTimePreKeyReference {
                id: 9,
                public_key: [0x61; 32],
            }),
        }
    }

    #[test]
    fn frame_key_and_nonce_change_with_the_secret() {
        let (key, nonce) = expand_frame_secret(&[0x01; 32]).unwrap();
        let (other_key, other_nonce) = expand_frame_secret(&[0x02; 32]).unwrap();
        assert_ne!(*other_key, *key);
        assert_ne!(other_nonce, nonce);
    }

    #[test]
    fn sealed_frame_round_trip_with_prekey_reference() {
        let mut rng = ChaCha20Rng::from_seed([0x11; 32]);
        let recipient = recipient_discovery_key(0x42);
        let frame = seal_frame_with_associated_data(
            &mut rng,
            recipient.public_key(),
            Some(prekey_reference()),
            b"sealed payload",
            &binding(b"binding"),
        )
        .unwrap();
        let encoded = frame.to_bytes().unwrap();
        let decoded = SealedFrame::from_bytes(&encoded).unwrap();

        assert_eq!(
            decoded.recipient_public_key,
            *recipient.public_key().as_bytes()
        );
        assert_eq!(decoded.prekey_reference, Some(prekey_reference()));
        assert_ne!(decoded.ephemeral_public_key, [0u8; 32]);
        assert_eq!(
            open_frame_for_discovery_key_with_associated_data(
                &recipient,
                &decoded,
                &binding(b"binding")
            )
            .unwrap()
            .as_slice(),
            b"sealed payload"
        );
    }

    #[test]
    fn sealed_frame_aad_binds_transport_visible_fields() {
        let mut rng = ChaCha20Rng::from_seed([0x12; 32]);
        let recipient = recipient_discovery_key(0x42);
        let other_recipient = recipient_discovery_key(0x44);
        let frame = seal_frame_with_associated_data(
            &mut rng,
            recipient.public_key(),
            None,
            b"metadata-bound",
            &binding(b"binding"),
        )
        .unwrap();

        let mut wrong_recipient = frame.clone();
        wrong_recipient.recipient_public_key = *other_recipient.public_key().as_bytes();
        let mut wrong_ephemeral = frame.clone();
        wrong_ephemeral.ephemeral_public_key =
            *KeyPair::from_secret_bytes(&[0x45; 32]).public.as_bytes();
        let mut wrong_prekey = frame.clone();
        wrong_prekey.prekey_reference = Some(prekey_reference());

        assert!(matches!(
            open_frame_for_discovery_key_with_associated_data(
                &other_recipient,
                &wrong_recipient,
                &binding(b"binding")
            ),
            Err(SealedFrameError::Aead)
        ));
        for tampered in [wrong_ephemeral, wrong_prekey] {
            assert!(matches!(
                open_frame_for_discovery_key_with_associated_data(
                    &recipient,
                    &tampered,
                    &binding(b"binding")
                ),
                Err(SealedFrameError::Aead)
            ));
        }
    }

    #[test]
    fn sealed_frame_from_bytes_rejects_oversized_before_decode() {
        let bytes = vec![0u8; SealedFrame::MAX_ENCODED_LEN + 1];
        assert!(matches!(
            SealedFrame::from_bytes(&bytes),
            Err(SealedFrameError::FrameTooLong { len, max: SealedFrame::MAX_ENCODED_LEN })
                if len == bytes.len()
        ));
    }

    #[test]
    fn sealed_frame_from_bytes_rejects_an_unknown_version_before_decoding() {
        let unknown = SEALED_FRAME_VERSION + 1;
        assert!(matches!(
            SealedFrame::from_bytes(&[unknown]),
            Err(SealedFrameError::UnsupportedVersion { version }) if version == unknown
        ));
    }

    #[test]
    fn sealed_frame_from_bytes_rejects_trailing_bytes() {
        let mut rng = ChaCha20Rng::from_seed([0x15; 32]);
        let recipient = recipient_discovery_key(0x42);
        let frame = seal_frame_with_associated_data(
            &mut rng,
            recipient.public_key(),
            None,
            b"payload",
            &binding(b"binding"),
        )
        .unwrap();
        let mut bytes = frame.to_bytes().unwrap();
        bytes.push(0);

        assert!(matches!(
            SealedFrame::from_bytes(&bytes),
            Err(SealedFrameError::TrailingBytes { len: 1 })
        ));
    }

    #[test]
    fn sealed_frame_rejects_invalid_public_keys() {
        let mut frame = SealedFrame {
            recipient_public_key: [0u8; 32],
            prekey_reference: None,
            ephemeral_public_key: [0x42; 32],
            ciphertext: vec![0x51; 16],
        };

        assert!(matches!(
            frame.to_bytes(),
            Err(SealedFrameError::InvalidPublicKey)
        ));

        frame.recipient_public_key = *recipient_discovery_key(0x42).public_key().as_bytes();
        frame.ephemeral_public_key = [0u8; 32];
        assert!(matches!(
            frame.to_bytes(),
            Err(SealedFrameError::InvalidPublicKey)
        ));
    }
}
