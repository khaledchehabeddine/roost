//! Implements the X3DH handshake that bootstraps Double Ratchet sessions.

use crate::discovery_key::{DiscoveryKey, DiscoveryKeyBundle, verify_discovery_key_bundle};
use crate::double_ratchet::{Header, RatchetState};
use crate::error::CryptoError;
use crate::keys::{
    IdentityKeyBundle, KeyPair, PublicKey, SharedSecret, generate_key_pair,
    validate_x25519_public_key, verify_identity_key_bundle,
};
use crate::one_time_prekey::{OneTimePreKey, OneTimePreKeyBundle};
use crate::ratchet::RootKey;
#[cfg(test)]
use crate::sealed_frame::seal_frame_with_ephemeral_key;
use crate::sealed_frame::{
    SealedFrame, SealedFramePreKeyReference, open_frame_for_discovery_key_with_associated_data,
    seal_frame_with_ephemeral_key_and_associated_data,
};
use crate::signed_prekey::{SignedPreKey, SignedPreKeyBundle, verify_signed_prekey_bundle};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// Fixed prefix on the HKDF input. Future incompatible handshake derivations should change these
// bytes so peers fail during the first decrypt.
const F_PREFIX: [u8; 32] = [0xFF; 32];
const HKDF_INFO_WITHOUT_ONE_TIME_PREKEY: &[u8] = b"AetherX3DH-v1:without-opk";
const HKDF_INFO_WITH_ONE_TIME_PREKEY: &[u8] = b"AetherX3DH-v1:with-opk";
/// Current public pre-key bundle format version.
pub const PREKEY_BUNDLE_VERSION: u8 = 1;
/// Additive public-key headroom reserved in a future versioned pre-key bundle.
pub const PREKEY_BUNDLE_ADDITIVE_PUBLIC_KEY_HEADROOM: usize = 1184;
/// Additive shared-secret headroom reserved in future X3DH KDF input.
pub const X3DH_ADDITIVE_SHARED_SECRET_HEADROOM: usize = 32;
/// The outer sealed-frame version. Must track `SEALED_FRAME_VERSION`, which is
/// what actually rejects a frame on decode; this constant is the handshake's
/// own assertion about the envelope it produces.
const HANDSHAKE_ENVELOPE_VERSION: u8 = 1;

/// The version of the plaintext *inside* the sealed frame, which is a separate
/// format from the frame carrying it — the two were previously the same constant
/// and agreed only because both were 1.
///
/// Version 2 carries the initiator's Identity Key so a responder can open a
/// first message from a sender it has never seen. Version 1 is not accepted:
/// nothing has shipped, and supporting it would mean keeping a path on which a
/// stranger's message is permanently unopenable.
const HANDSHAKE_FRAME_PLAINTEXT_VERSION: u8 = 2;
const MAX_HANDSHAKE_ENVELOPE_LEN: usize = 16 * 1024;
const MAX_HANDSHAKE_CIPHERTEXT_LEN: usize = 8 * 1024;
const XCHACHA20_POLY1305_TAG_LEN: usize = 16;
const SEALED_SENDER_ENVELOPE_VERSION: u8 = 1;
const SENDER_PROOF_LEN: usize = 32;
const SEALED_SENDER_ENCODING_OVERHEAD_CAP: usize = 64;
const MAX_HANDSHAKE_SEALED_SENDER_ENVELOPE_LEN: usize =
    MAX_HANDSHAKE_CIPHERTEXT_LEN - XCHACHA20_POLY1305_TAG_LEN;
const MAX_HANDSHAKE_SEALED_SENDER_CONTENT_LEN: usize = MAX_HANDSHAKE_SEALED_SENDER_ENVELOPE_LEN
    - 32
    - SENDER_PROOF_LEN
    - SEALED_SENDER_ENCODING_OVERHEAD_CAP;
const MAX_SENDER_CERTIFICATE_LEN: usize = 16 * 1024;
const MAX_SENDER_SIGNATURE_LEN: usize = 4 * 1024;

/// Public pre-key material used by the initiator to start an X3DH session.
#[derive(Clone, Debug)]
pub struct PreKeyBundle {
    /// Version of the public pre-key bundle format.
    pub version: u8,
    /// Responder discovery key verified by the responder's identity key.
    pub discovery_key: DiscoveryKeyBundle,
    /// Responder signed pre-key verified by the discovery key.
    pub signed_prekey: SignedPreKeyBundle,
    /// Optional one-time pre-key bound to the same discovery-key epoch.
    pub one_time_prekey: Option<OneTimePreKeyBundle>,
}

/// Sender identity material decoded only after first-message ciphertext authentication succeeds.
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
    /// Opaque sender certificate bytes for future validation.
    pub certificate: Vec<u8>,
    /// Opaque sender signature bytes for future validation.
    pub signature: Vec<u8>,
}

/// Plaintext and sender material for an outbound X3DH first message.
pub struct InitialPlaintext<'a> {
    /// Opaque sender certificate bytes sealed into the first message.
    pub sender_certificate: &'a [u8],
    /// Opaque sender signature bytes sealed into the first message.
    pub sender_signature: &'a [u8],
    /// First application plaintext bytes.
    pub plaintext: &'a [u8],
}

/// Decrypted X3DH first message and sealed sender material.
pub struct AcceptedInitialMessage {
    /// Decrypted first-message plaintext bytes.
    pub plaintext: Zeroizing<Vec<u8>>,
    /// Opaque sender identity material decoded from the sealed-sender envelope.
    pub sender_identity: SenderIdentityMaterial,
}

/// A serialized handshake request from an initiator to a responder.
#[derive(Clone, Debug)]
pub struct HandshakeEnvelope {
    /// Sealed-frame wire version.
    pub version: u8,
    /// Recipient Discovery Key X25519 public key.
    pub recipient_public_key: [u8; 32],
    /// X3DH prekey reference targeted by the initiator.
    pub prekey_reference: Option<SealedFramePreKeyReference>,
    /// Initiator's X25519 ephemeral public key.
    pub ephemeral_public_key: [u8; 32],
    /// AEAD ciphertext for the sealed initial ratchet payload.
    pub ciphertext: Vec<u8>,
}

#[derive(Serialize)]
struct HandshakeFramePlaintextWire<'a> {
    version: u8,
    sender_identity_key: [u8; 32],
    sender_identity_verifying_key: [u8; 32],
    sender_identity_binding_signature: &'a [u8],
    ratchet_public_key: [u8; 32],
    previous_chain_length: u32,
    message_number: u32,
    ciphertext: &'a [u8],
}

#[derive(Deserialize)]
struct DecodedHandshakeFramePlaintextWire {
    version: u8,
    sender_identity_key: [u8; 32],
    sender_identity_verifying_key: [u8; 32],
    sender_identity_binding_signature: Vec<u8>,
    ratchet_public_key: [u8; 32],
    previous_chain_length: u32,
    message_number: u32,
    ciphertext: Vec<u8>,
}

struct DecodedHandshakeFramePlaintext {
    header: Header,
    ciphertext: Vec<u8>,
    /// The initiator's Identity Key, carried in the layer sealed to the
    /// responder's Discovery Key so a recipient who has never seen this sender
    /// can still derive the root key (AE-KEY-04 binding checked on decode).
    ///
    /// Unauthenticated at this layer — a sender may claim anything. A false
    /// claim derives the wrong root key and fails the AEAD, and the sealed
    /// envelope's own copy is compared against it after decryption, so the hint
    /// can only ever select which key is tried, never what is believed.
    sender_identity_hint: IdentityKeyBundle,
}

impl HandshakeEnvelope {
    /// Serializes this handshake envelope for transport.
    ///
    /// # Errors
    /// - [`CryptoError::HandshakeEnvelopeEncode`] when postcard rejects the envelope wire form.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        if self.ciphertext.len() > MAX_HANDSHAKE_CIPHERTEXT_LEN {
            return Err(CryptoError::HandshakeEnvelopeEncode);
        }
        let frame = self.to_frame();
        if frame.prekey_reference.is_none() {
            return Err(CryptoError::HandshakeEnvelopeEncode);
        }
        let bytes = frame
            .to_bytes()
            .map_err(|_| CryptoError::HandshakeEnvelopeEncode)?;
        if bytes.len() > MAX_HANDSHAKE_ENVELOPE_LEN {
            return Err(CryptoError::HandshakeEnvelopeEncode);
        }
        Ok(bytes)
    }

    /// Restores a handshake envelope from bytes produced by [`Self::to_bytes`].
    ///
    /// This validates only structural decoding. [`accept`] authenticates the envelope against
    /// verified discovery and pre-key material.
    ///
    /// # Errors
    /// - [`CryptoError::HandshakeEnvelopeDecode`] when the bytes are malformed or oversized.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() > MAX_HANDSHAKE_ENVELOPE_LEN {
            return Err(CryptoError::HandshakeEnvelopeDecode);
        }

        let frame =
            SealedFrame::from_bytes(bytes).map_err(|_| CryptoError::HandshakeEnvelopeDecode)?;
        if frame.ciphertext.len() > MAX_HANDSHAKE_CIPHERTEXT_LEN {
            return Err(CryptoError::HandshakeEnvelopeDecode);
        }
        validate_envelope_public_fields(&frame)?;
        Ok(Self::from_frame(frame))
    }

    fn from_frame(frame: SealedFrame) -> Self {
        Self {
            version: frame.version,
            recipient_public_key: frame.recipient_public_key,
            prekey_reference: frame.prekey_reference,
            ephemeral_public_key: frame.ephemeral_public_key,
            ciphertext: frame.ciphertext,
        }
    }

    fn to_frame(&self) -> SealedFrame {
        SealedFrame {
            version: self.version,
            recipient_public_key: self.recipient_public_key,
            prekey_reference: self.prekey_reference,
            ephemeral_public_key: self.ephemeral_public_key,
            ciphertext: self.ciphertext.clone(),
        }
    }
}

/// Starts a handshake as the initiator and encrypts the first message.
///
/// The initiator's ephemeral key and first ratchet key are drawn from `rng`.
///
/// Pass both parties' permanent identity key bundles. They bind the X25519 and Ed25519 halves and
/// are included in the X3DH root-key derivation.
///
/// # Errors
/// - [`CryptoError::Aead`] when first-message encryption fails.
/// - [`CryptoError::HandshakeEnvelopeEncode`] when the sealed first message or handshake envelope
///   fails to encode or exceeds local caps.
/// - [`CryptoError::HkdfExpand`] when the HKDF run for root-key derivation fails.
/// - [`CryptoError::InvalidState`] when ratchet seeding produces an invalid initial state.
/// - [`CryptoError::NonContributorySharedSecret`] when an X25519 peer key produces a
///   non-contributory shared secret.
/// - [`CryptoError::SignatureInvalid`] when the responder discovery key or signed pre-key
///   signature does not verify.
/// - [`CryptoError::StalePreKey`] when bundled pre-keys do not match the discovery-key epoch.
/// - [`CryptoError::UnsupportedPreKeyBundleVersion`] when the bundle format version is not
///   supported by this implementation.
pub fn initiate<R: RngCore + CryptoRng>(
    rng: &mut R,
    initiator_discovery_key: &DiscoveryKey,
    initiator_identity_key: &IdentityKeyBundle,
    responder_identity_key: &IdentityKeyBundle,
    responder_prekey_bundle: &PreKeyBundle,
    message: InitialPlaintext<'_>,
) -> Result<(RatchetState, HandshakeEnvelope), CryptoError> {
    initiate_with_associated_data(
        rng,
        initiator_discovery_key,
        initiator_identity_key,
        responder_identity_key,
        responder_prekey_bundle,
        message,
        &[],
    )
}

/// Starts a handshake and authenticates caller-supplied transport associated data in the outer
/// sealed frame.
///
/// The responder must pass identical bytes to [`accept_with_associated_data`] or
/// [`initiator_identity_hint_with_associated_data`].
///
/// # Errors
/// - [`CryptoError::Aead`] when first-message or outer-frame encryption fails.
/// - [`CryptoError::HandshakeEnvelopeEncode`] when the first-message content or envelope exceeds
///   local caps or fails to encode.
/// - [`CryptoError::HkdfExpand`] when a root, ratchet, frame, or proof derivation fails.
/// - [`CryptoError::InvalidHmacKey`] when the ratchet chain-key derivation rejects its input.
/// - [`CryptoError::InvalidKeyEncoding`] when either Identity Key bundle is not canonical.
/// - [`CryptoError::InvalidState`] when ratchet seeding or first-message encryption observes an
///   invalid state.
/// - [`CryptoError::NonContributorySharedSecret`] when an X25519 peer key produces a
///   non-contributory shared secret.
/// - [`CryptoError::SealedFrameEncode`] when frame fields, ciphertext, or additional associated
///   data exceed local caps.
/// - [`CryptoError::SignatureInvalid`] when an Identity Key, Discovery Key, or signed-prekey
///   signature does not verify.
/// - [`CryptoError::StalePreKey`] when bundled prekeys do not match the Discovery Key epoch.
/// - [`CryptoError::UnsupportedPreKeyBundleVersion`] when the bundle version is unsupported.
pub fn initiate_with_associated_data<R: RngCore + CryptoRng>(
    rng: &mut R,
    initiator_discovery_key: &DiscoveryKey,
    initiator_identity_key: &IdentityKeyBundle,
    responder_identity_key: &IdentityKeyBundle,
    responder_prekey_bundle: &PreKeyBundle,
    message: InitialPlaintext<'_>,
    additional_associated_data: &[u8],
) -> Result<(RatchetState, HandshakeEnvelope), CryptoError> {
    verify_identity_key_bundle(initiator_identity_key)?;
    verify_identity_key_bundle(responder_identity_key)?;
    if responder_prekey_bundle.version != PREKEY_BUNDLE_VERSION {
        return Err(CryptoError::UnsupportedPreKeyBundleVersion(
            responder_prekey_bundle.version,
        ));
    }
    verify_discovery_key_bundle(
        &responder_prekey_bundle.discovery_key,
        &responder_identity_key.verifying_key,
    )?;
    verify_signed_prekey_bundle(
        &responder_prekey_bundle.signed_prekey,
        &responder_prekey_bundle.discovery_key.verifying_key,
    )?;
    validate_bundle_epochs(responder_prekey_bundle)?;

    let initiator_ephemeral_key = generate_key_pair(rng);
    let responder_signed_prekey_public_key = responder_prekey_bundle.signed_prekey.public_key;

    let root_key = derive_root_key_initiator(
        &initiator_ephemeral_key,
        initiator_identity_key,
        responder_identity_key,
        &responder_prekey_bundle.discovery_key.public_key,
        &responder_signed_prekey_public_key,
        responder_prekey_bundle
            .one_time_prekey
            .as_ref()
            .map(|prekey| &prekey.public_key),
    )?;
    let mut state =
        RatchetState::init_initiator(rng, root_key, &responder_signed_prekey_public_key)?;

    let associated_data = initial_associated_data(
        &responder_prekey_bundle.discovery_key.public_key,
        responder_prekey_bundle.discovery_key.epoch,
    );
    let sender_identity_key = *initiator_identity_key.public_key.as_bytes();
    let sender_discovery_key = *initiator_discovery_key.public_key().as_bytes();
    let sender_proof_placeholder = [0u8; SENDER_PROOF_LEN];
    validate_sender_material_lengths(
        &initiator_identity_key.binding_signature.to_bytes(),
        message.sender_certificate,
        message.sender_signature,
        &sender_proof_placeholder,
        message.plaintext,
        CryptoError::HandshakeEnvelopeEncode,
    )?;
    let sender_proof_secret = checked_shared_secret(
        initiator_discovery_key.diffie_hellman(&responder_signed_prekey_public_key),
    )?;
    let sender_proof_transcript = sender_proof_transcript(SenderProofTranscriptInput {
        sender_identity_key: &sender_identity_key,
        sender_identity_verifying_key: initiator_identity_key.verifying_key.as_bytes(),
        sender_discovery_key: &sender_discovery_key,
        sender_certificate: message.sender_certificate,
        sender_signature: message.sender_signature,
        initiator_ephemeral_public_key: &initiator_ephemeral_key.public,
        responder_discovery_public_key: &responder_prekey_bundle.discovery_key.public_key,
        responder_discovery_epoch: responder_prekey_bundle.discovery_key.epoch,
        responder_signed_prekey_public_key: &responder_signed_prekey_public_key,
        responder_one_time_prekey: responder_prekey_bundle.one_time_prekey.as_ref(),
    });
    let sender_proof = derive_sender_proof(&sender_proof_secret, &sender_proof_transcript)?;
    let sealed = encode_sealed_sender_envelope(SealedSenderEnvelopeInput {
        sender_identity_key,
        sender_identity_verifying_key: *initiator_identity_key.verifying_key.as_bytes(),
        sender_identity_binding_signature: initiator_identity_key.binding_signature.to_bytes(),
        sender_discovery_key,
        sender_certificate: message.sender_certificate,
        sender_signature: message.sender_signature,
        sender_proof: sender_proof.as_ref(),
        plaintext: message.plaintext,
    })?;
    let (header, ciphertext) = state.ratchet_encrypt(&sealed, &associated_data)?;
    let frame_plaintext =
        encode_handshake_frame_plaintext(&header, &ciphertext, initiator_identity_key)?;
    let prekey_reference = SealedFramePreKeyReference {
        discovery_epoch: responder_prekey_bundle.discovery_key.epoch,
        signed_prekey_public_key: *responder_signed_prekey_public_key.as_bytes(),
        one_time_prekey_id: responder_prekey_bundle
            .one_time_prekey
            .as_ref()
            .map(|prekey| prekey.id),
        one_time_prekey_public_key: responder_prekey_bundle
            .one_time_prekey
            .as_ref()
            .map(|prekey| *prekey.public_key.as_bytes()),
    };
    let frame = seal_frame_with_ephemeral_key_and_associated_data(
        &initiator_ephemeral_key,
        &responder_prekey_bundle.discovery_key.public_key,
        Some(prekey_reference),
        &frame_plaintext,
        additional_associated_data,
    )?;
    let envelope = HandshakeEnvelope::from_frame(frame);
    envelope.to_bytes()?;

    Ok((state, envelope))
}

/// Reads the initiator's Identity Key out of a handshake envelope, without
/// accepting it.
///
/// This exists because a caller has to know *who* sent a first message before it
/// can accept one: session state is addressed by a key derived from both
/// identities, and [`accept`] takes that address as an input. Calling `accept`
/// speculatively to find out is not an option — it consumes the referenced
/// one-time prekey, so a second call with the right address would fail.
///
/// Opens only the layer sealed to `responder_discovery_key`, so it consumes
/// nothing and reveals nothing to anyone without that key. The binding
/// signature over the two halves is checked here; everything else about the
/// sender is unverified until [`accept`] compares this against the sealed
/// envelope's own copy.
///
/// # Errors
/// - [`CryptoError::HandshakeEnvelopeDecode`] if the frame is not an initial, is
///   not sealed to this Discovery Key, or its plaintext does not decode.
/// - [`CryptoError::InvalidKeyEncoding`] if the named identity is not canonical.
/// - [`CryptoError::SignatureInvalid`] if the identity's own binding signature
///   does not verify.
pub fn initiator_identity_hint(
    envelope: &HandshakeEnvelope,
    responder_discovery_key: &DiscoveryKey,
) -> Result<IdentityKeyBundle, CryptoError> {
    initiator_identity_hint_with_associated_data(envelope, responder_discovery_key, &[])
}

/// Reads the claimed initiator identity while authenticating caller-supplied transport associated
/// data in the outer sealed frame.
///
/// Associated-data authentication does not authenticate the claimed initiator. The returned bundle
/// remains a sender claim until [`accept_with_associated_data`] checks it against the sealed
/// envelope's authenticated copy.
///
/// # Errors
/// - [`CryptoError::Aead`] if the frame or associated data does not authenticate.
/// - [`CryptoError::HandshakeEnvelopeDecode`] if the frame is not an initial or its plaintext is
///   malformed.
/// - [`CryptoError::HkdfExpand`] if frame key derivation fails.
/// - [`CryptoError::InvalidKeyEncoding`] if the named identity is not canonical.
/// - [`CryptoError::NonContributorySharedSecret`] if the ephemeral key yields a low-order
///   agreement.
/// - [`CryptoError::SealedFrameDecode`] if frame fields are malformed, target another Discovery
///   Key, or additional associated data exceeds the local cap.
/// - [`CryptoError::SignatureInvalid`] if the named identity's binding signature does not verify.
pub fn initiator_identity_hint_with_associated_data(
    envelope: &HandshakeEnvelope,
    responder_discovery_key: &DiscoveryKey,
    additional_associated_data: &[u8],
) -> Result<IdentityKeyBundle, CryptoError> {
    validate_envelope_public_fields(&envelope.to_frame())?;
    let frame_plaintext = open_frame_for_discovery_key_with_associated_data(
        responder_discovery_key,
        &envelope.to_frame(),
        additional_associated_data,
    )?;
    let decoded = decode_handshake_frame_plaintext(&frame_plaintext)?;
    verify_identity_key_bundle(&decoded.sender_identity_hint)?;
    Ok(decoded.sender_identity_hint)
}

/// Accepts a handshake envelope and decrypts the first message.
///
/// The responder's first ratchet key is drawn from `rng` during the initial DH ratchet step.
///
/// `responder_discovery_key` is the local responder's current X25519 discovery key.
///
/// `initiator_identity_key` is the initiator identity bundle that was folded into the X3DH root
/// key. The decoded sealed sender identity must match it on both key halves, so the identity the
/// responder verified and the identity returned to the caller are guaranteed to be the same.
///
/// This function checks that the envelope targets `responder_signed_prekey` and verifies the
/// sealed sender key-possession proof, but it does not verify the signed pre-key signature or
/// validate the sender certificate. Sender identity material is returned only after the
/// first-message ciphertext authenticates and decrypts.
///
/// # Errors
/// - [`CryptoError::Aead`] when first-message decryption fails (tampered ciphertext, wrong
///   associated data, or wrong key).
/// - [`CryptoError::HandshakeEnvelopeDecode`] when the sealed first message is malformed,
///   unsupported, or exceeds local caps.
/// - [`CryptoError::HandshakeSignedPreKeyMismatch`] when the envelope pre-key reference does not
///   match `responder_signed_prekey.public()`.
/// - [`CryptoError::HkdfExpand`] when the HKDF run for root-key derivation fails.
/// - [`CryptoError::InvalidState`] when ratchet decryption observes an invalid receiving state.
/// - [`CryptoError::MissingOneTimePreKey`] when the envelope names a one-time pre-key but the
///   caller supplies none.
/// - [`CryptoError::NonContributorySharedSecret`] when an X25519 peer key produces a
///   non-contributory shared secret.
/// - [`CryptoError::OneTimePreKeyMismatch`] when the supplied one-time pre-key does not match the
///   envelope reference.
/// - [`CryptoError::SenderIdentityMismatch`] when the sealed sender identity does not match
///   `initiator_identity_key`.
/// - [`CryptoError::SignatureInvalid`] when the sealed sender key-possession proof does not
///   validate.
/// - [`CryptoError::StalePreKey`] when the envelope or local pre-keys do not match the discovery
///   key epoch.
pub fn accept<R: RngCore + CryptoRng>(
    rng: &mut R,
    envelope: &HandshakeEnvelope,
    expected_initiator_identity_key: Option<&IdentityKeyBundle>,
    responder_identity_key: &IdentityKeyBundle,
    responder_discovery_key: &DiscoveryKey,
    responder_signed_prekey: &SignedPreKey,
    responder_one_time_prekey: Option<OneTimePreKey>,
) -> Result<(RatchetState, AcceptedInitialMessage), CryptoError> {
    accept_with_associated_data(
        rng,
        envelope,
        expected_initiator_identity_key,
        responder_identity_key,
        responder_discovery_key,
        responder_signed_prekey,
        responder_one_time_prekey,
        &[],
    )
}

/// Accepts a handshake while authenticating caller-supplied transport associated data in the
/// outer sealed frame.
///
/// As with [`accept`], this verifies that the envelope targets `responder_signed_prekey` and checks
/// the sender key-possession proof, but it does not verify the signed-prekey signature or validate
/// the sender certificate.
///
/// # Errors
/// - [`CryptoError::Aead`] when outer-frame or first-message authentication fails.
/// - [`CryptoError::HandshakeEnvelopeDecode`] when the sealed first Message is malformed,
///   unsupported, or exceeds local caps.
/// - [`CryptoError::HandshakeSignedPreKeyMismatch`] when the envelope names another signed
///   pre-key.
/// - [`CryptoError::HkdfExpand`] when root, frame, or ratchet derivation fails.
/// - [`CryptoError::InvalidHmacKey`] when ratchet chain-key derivation rejects its input.
/// - [`CryptoError::InvalidKeyEncoding`] when the responder or expected initiator Identity Key is
///   not canonical.
/// - [`CryptoError::InvalidState`] when ratchet decryption observes an invalid state.
/// - [`CryptoError::MaxSkipExceeded`] when the authenticated first Message asks to skip too many
///   ratchet messages.
/// - [`CryptoError::MissingOneTimePreKey`] when the envelope names a one-time pre-key but none is
///   supplied.
/// - [`CryptoError::NonContributorySharedSecret`] when an X25519 peer key yields a low-order
///   agreement.
/// - [`CryptoError::OneTimePreKeyMismatch`] when the supplied one-time pre-key does not match the
///   envelope.
/// - [`CryptoError::SealedFrameDecode`] when frame fields are malformed, target another Discovery
///   Key, or additional associated data exceeds the local cap.
/// - [`CryptoError::SenderIdentityMismatch`] when the sealed sender identity differs from the
///   expected or hinted initiator.
/// - [`CryptoError::SignatureInvalid`] when an Identity Key binding or sender proof fails.
/// - [`CryptoError::StalePreKey`] when the envelope or local prekeys do not match the Discovery Key
///   epoch.
#[expect(
    clippy::too_many_arguments,
    reason = "route binding adds one explicit input to the established X3DH acceptance seam"
)]
pub fn accept_with_associated_data<R: RngCore + CryptoRng>(
    rng: &mut R,
    envelope: &HandshakeEnvelope,
    expected_initiator_identity_key: Option<&IdentityKeyBundle>,
    responder_identity_key: &IdentityKeyBundle,
    responder_discovery_key: &DiscoveryKey,
    responder_signed_prekey: &SignedPreKey,
    responder_one_time_prekey: Option<OneTimePreKey>,
    additional_associated_data: &[u8],
) -> Result<(RatchetState, AcceptedInitialMessage), CryptoError> {
    verify_identity_key_bundle(responder_identity_key)?;
    let prekey_reference = envelope_prekey_reference(envelope)?;
    if prekey_reference.discovery_epoch != responder_discovery_key.epoch()
        || responder_signed_prekey.epoch() != responder_discovery_key.epoch()
    {
        return Err(CryptoError::StalePreKey);
    }
    if envelope.ciphertext.len() > MAX_HANDSHAKE_CIPHERTEXT_LEN {
        return Err(CryptoError::HandshakeEnvelopeDecode);
    }
    let signed_prekey_matches: bool = envelope
        .prekey_reference
        .map(|reference| reference.signed_prekey_public_key)
        .ok_or(CryptoError::HandshakeEnvelopeDecode)?
        .ct_eq(responder_signed_prekey.public().as_bytes())
        .into();
    if !signed_prekey_matches {
        return Err(CryptoError::HandshakeSignedPreKeyMismatch);
    }

    let responder_one_time_prekey =
        validate_envelope_one_time_prekey(envelope, responder_one_time_prekey)?;

    let initiator_ephemeral_public_key = PublicKey::from(envelope.ephemeral_public_key);

    let associated_data = initial_associated_data(
        responder_discovery_key.public_key(),
        responder_discovery_key.epoch(),
    );
    // Opened before the root key is derived, and that ordering is the whole
    // point: this layer is sealed to the responder's own Discovery Key, so it
    // is readable without knowing the sender, and it names the sender the root
    // key needs. Deriving first would require already knowing the answer.
    let frame_plaintext = open_frame_for_discovery_key_with_associated_data(
        responder_discovery_key,
        &envelope.to_frame(),
        additional_associated_data,
    )?;
    let frame_plaintext = decode_handshake_frame_plaintext(&frame_plaintext)?;

    // A caller that names an expected initiator pins it; one that does not —
    // a message request from a stranger — takes the frame's claim. Either way
    // the binding signature is verified here and the sealed envelope's own copy
    // is compared against it after decryption.
    let initiator_identity_key =
        expected_initiator_identity_key.unwrap_or(&frame_plaintext.sender_identity_hint);
    verify_identity_key_bundle(initiator_identity_key)?;

    let root_key = derive_root_key_responder(
        &initiator_ephemeral_public_key,
        initiator_identity_key,
        responder_identity_key,
        responder_discovery_key,
        responder_signed_prekey,
        responder_one_time_prekey.as_ref(),
    )?;
    let signed_prekey_key_pair =
        KeyPair::from_secret_bytes(*responder_signed_prekey.to_secret_bytes());
    let mut state = RatchetState::init_responder(root_key, signed_prekey_key_pair);
    let sealed = state.ratchet_decrypt(
        rng,
        &frame_plaintext.ciphertext,
        &frame_plaintext.header,
        &associated_data,
    )?;
    let decoded = decode_sealed_sender_envelope(&sealed)?;
    let sender_identity = &decoded.message.sender_identity;
    let identity_matches: bool = (sender_identity
        .identity_key
        .ct_eq(initiator_identity_key.public_key.as_bytes())
        & sender_identity
            .identity_verifying_key
            .ct_eq(initiator_identity_key.verifying_key.as_bytes()))
    .into();
    if !identity_matches {
        return Err(CryptoError::SenderIdentityMismatch);
    }
    verify_sender_proof(
        envelope,
        responder_discovery_key.public_key(),
        responder_signed_prekey,
        &decoded.message.sender_identity,
        &decoded.sender_discovery_key,
        &decoded.sender_proof,
    )?;

    Ok((state, decoded.message))
}

fn validate_bundle_epochs(bundle: &PreKeyBundle) -> Result<(), CryptoError> {
    let epoch = bundle.discovery_key.epoch;
    if bundle.signed_prekey.epoch != epoch {
        return Err(CryptoError::StalePreKey);
    }
    if let Some(one_time_prekey) = &bundle.one_time_prekey
        && one_time_prekey.epoch != epoch
    {
        return Err(CryptoError::StalePreKey);
    }
    Ok(())
}

fn validate_envelope_one_time_prekey(
    envelope: &HandshakeEnvelope,
    one_time_prekey: Option<OneTimePreKey>,
) -> Result<Option<OneTimePreKey>, CryptoError> {
    let reference = envelope_prekey_reference(envelope)?;
    match (
        reference.one_time_prekey_id,
        reference.one_time_prekey_public_key,
        one_time_prekey,
    ) {
        (None, None, _) => Ok(None),
        (Some(_), None, _) | (None, Some(_), _) => Err(CryptoError::OneTimePreKeyMismatch),
        (Some(_), Some(_), None) => Err(CryptoError::MissingOneTimePreKey),
        (Some(expected_id), Some(expected_public_key), Some(prekey)) => {
            let public_matches: bool = expected_public_key.ct_eq(prekey.public().as_bytes()).into();
            if prekey.id() != expected_id || !public_matches {
                return Err(CryptoError::OneTimePreKeyMismatch);
            }
            if prekey.epoch() != reference.discovery_epoch {
                return Err(CryptoError::StalePreKey);
            }
            Ok(Some(prekey))
        }
    }
}

fn envelope_prekey_reference(
    envelope: &HandshakeEnvelope,
) -> Result<SealedFramePreKeyReference, CryptoError> {
    envelope
        .prekey_reference
        .ok_or(CryptoError::HandshakeEnvelopeDecode)
}

fn validate_envelope_public_fields(frame: &SealedFrame) -> Result<(), CryptoError> {
    if frame.version != HANDSHAKE_ENVELOPE_VERSION || frame.prekey_reference.is_none() {
        return Err(CryptoError::HandshakeEnvelopeDecode);
    }
    Ok(())
}

fn encode_handshake_frame_plaintext(
    header: &Header,
    ciphertext: &[u8],
    initiator_identity_key: &IdentityKeyBundle,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if ciphertext.len() > MAX_HANDSHAKE_CIPHERTEXT_LEN {
        return Err(CryptoError::HandshakeEnvelopeEncode);
    }
    Ok(Zeroizing::new(
        postcard::to_stdvec(&HandshakeFramePlaintextWire {
            version: HANDSHAKE_FRAME_PLAINTEXT_VERSION,
            sender_identity_key: *initiator_identity_key.public_key.as_bytes(),
            sender_identity_verifying_key: *initiator_identity_key.verifying_key.as_bytes(),
            sender_identity_binding_signature: &initiator_identity_key.binding_signature.to_bytes(),
            ratchet_public_key: *header.public_key.as_bytes(),
            previous_chain_length: header.previous_chain_length,
            message_number: header.message_number,
            ciphertext,
        })
        .map_err(|_| CryptoError::HandshakeEnvelopeEncode)?,
    ))
}

fn decode_handshake_frame_plaintext(
    bytes: &[u8],
) -> Result<DecodedHandshakeFramePlaintext, CryptoError> {
    let (wire, trailing): (DecodedHandshakeFramePlaintextWire, &[u8]) =
        postcard::take_from_bytes(bytes).map_err(|_| CryptoError::HandshakeEnvelopeDecode)?;
    if !trailing.is_empty()
        || wire.version != HANDSHAKE_FRAME_PLAINTEXT_VERSION
        || wire.ciphertext.len() > MAX_HANDSHAKE_CIPHERTEXT_LEN
        || !validate_x25519_public_key(&wire.ratchet_public_key)
    {
        return Err(CryptoError::HandshakeEnvelopeDecode);
    }
    // `from_bytes` rejects non-canonical encodings; the binding signature over
    // the two halves is checked by the caller through `verify_identity_key_bundle`,
    // on whichever bundle it settles on.
    let sender_identity_hint = IdentityKeyBundle::from_bytes(
        &wire.sender_identity_key,
        &wire.sender_identity_verifying_key,
        &wire.sender_identity_binding_signature,
    )
    .map_err(|_| CryptoError::HandshakeEnvelopeDecode)?;
    Ok(DecodedHandshakeFramePlaintext {
        header: Header {
            public_key: PublicKey::from(wire.ratchet_public_key),
            previous_chain_length: wire.previous_chain_length,
            message_number: wire.message_number,
        },
        ciphertext: wire.ciphertext,
        sender_identity_hint,
    })
}

// Derives the initiator-side root key from X3DH Diffie-Hellman outputs plus both IK bundles:
// DH2 = EK_A * DK_B, DH3 = EK_A * SPK_B, DH4 = EK_A * OPK_B.
pub(crate) fn derive_root_key_initiator(
    initiator_ephemeral_key: &KeyPair,
    initiator_identity_key: &IdentityKeyBundle,
    responder_identity_key: &IdentityKeyBundle,
    responder_discovery_public_key: &PublicKey,
    responder_signed_prekey_public_key: &PublicKey,
    responder_one_time_prekey_public_key: Option<&PublicKey>,
) -> Result<RootKey, CryptoError> {
    let dh2 = checked_shared_secret(
        initiator_ephemeral_key.diffie_hellman(responder_discovery_public_key),
    )?;
    let dh3 = checked_shared_secret(
        initiator_ephemeral_key.diffie_hellman(responder_signed_prekey_public_key),
    )?;
    let dh4 = responder_one_time_prekey_public_key
        .map(|public_key| checked_shared_secret(initiator_ephemeral_key.diffie_hellman(public_key)))
        .transpose()?;
    derive_root_key_from_dh_outputs(
        initiator_identity_key,
        responder_identity_key,
        &dh2,
        &dh3,
        dh4.as_ref(),
    )
}

// Derives the responder-side root key from X3DH Diffie-Hellman outputs plus both IK bundles:
// DH2 = DK_B * EK_A, DH3 = SPK_B * EK_A, DH4 = OPK_B * EK_A.
pub(crate) fn derive_root_key_responder(
    initiator_ephemeral_public_key: &PublicKey,
    initiator_identity_key: &IdentityKeyBundle,
    responder_identity_key: &IdentityKeyBundle,
    responder_discovery_key: &DiscoveryKey,
    responder_signed_prekey: &SignedPreKey,
    responder_one_time_prekey: Option<&OneTimePreKey>,
) -> Result<RootKey, CryptoError> {
    let dh2 = checked_shared_secret(
        responder_discovery_key.diffie_hellman(initiator_ephemeral_public_key),
    )?;
    let dh3 = checked_shared_secret(
        responder_signed_prekey.diffie_hellman(initiator_ephemeral_public_key),
    )?;
    let dh4 = responder_one_time_prekey
        .map(|prekey| checked_shared_secret(prekey.diffie_hellman(initiator_ephemeral_public_key)))
        .transpose()?;
    derive_root_key_from_dh_outputs(
        initiator_identity_key,
        responder_identity_key,
        &dh2,
        &dh3,
        dh4.as_ref(),
    )
}

fn checked_shared_secret(secret: SharedSecret) -> Result<SharedSecret, CryptoError> {
    if !secret.was_contributory() {
        return Err(CryptoError::NonContributorySharedSecret);
    }
    Ok(secret)
}

// Concatenates F_PREFIX || IK_A || IK_B || DH outputs and runs HKDF-SHA256 once.
fn derive_root_key_from_dh_outputs(
    initiator_identity_key: &IdentityKeyBundle,
    responder_identity_key: &IdentityKeyBundle,
    dh2: &SharedSecret,
    dh3: &SharedSecret,
    dh4: Option<&SharedSecret>,
) -> Result<RootKey, CryptoError> {
    let initiator_identity_encoding = initiator_identity_key.canonical_encoding();
    let responder_identity_encoding = responder_identity_key.canonical_encoding();
    let capacity = F_PREFIX.len()
        + initiator_identity_encoding.len()
        + responder_identity_encoding.len()
        + 32
        + 32
        + dh4.map_or(0, |_| 32);
    let mut input_keying_material: Zeroizing<Vec<u8>> =
        Zeroizing::new(Vec::with_capacity(capacity));
    input_keying_material.extend_from_slice(&F_PREFIX);
    input_keying_material.extend_from_slice(&initiator_identity_encoding);
    input_keying_material.extend_from_slice(&responder_identity_encoding);
    input_keying_material.extend_from_slice(dh2.as_bytes());
    input_keying_material.extend_from_slice(dh3.as_bytes());
    if let Some(dh4) = dh4 {
        input_keying_material.extend_from_slice(dh4.as_bytes());
        derive_root_key_from_input_keying_material(
            &input_keying_material,
            HKDF_INFO_WITH_ONE_TIME_PREKEY,
        )
    } else {
        derive_root_key_from_input_keying_material(
            &input_keying_material,
            HKDF_INFO_WITHOUT_ONE_TIME_PREKEY,
        )
    }
}

struct SenderProofTranscriptInput<'a> {
    sender_identity_key: &'a [u8; 32],
    sender_identity_verifying_key: &'a [u8; 32],
    sender_discovery_key: &'a [u8; 32],
    sender_certificate: &'a [u8],
    sender_signature: &'a [u8],
    initiator_ephemeral_public_key: &'a PublicKey,
    responder_discovery_public_key: &'a PublicKey,
    responder_discovery_epoch: u32,
    responder_signed_prekey_public_key: &'a PublicKey,
    responder_one_time_prekey: Option<&'a OneTimePreKeyBundle>,
}

fn sender_proof_transcript(input: SenderProofTranscriptInput<'_>) -> Zeroizing<Vec<u8>> {
    let one_time_prekey_len = input.responder_one_time_prekey.map_or(1, |_| 1 + 8 + 32);
    let mut transcript = Zeroizing::new(Vec::with_capacity(
        b"AetherX3DH-v1:sender-proof:".len()
            + 32
            + 4
            + 32
            + 32
            + one_time_prekey_len
            + 32
            + 32
            + 32
            + 4
            + input.sender_certificate.len()
            + 4
            + input.sender_signature.len(),
    ));
    transcript.extend_from_slice(b"AetherX3DH-v1:sender-proof:");
    transcript.extend_from_slice(input.initiator_ephemeral_public_key.as_bytes());
    transcript.extend_from_slice(input.responder_discovery_public_key.as_bytes());
    transcript.extend_from_slice(&input.responder_discovery_epoch.to_be_bytes());
    transcript.extend_from_slice(input.responder_signed_prekey_public_key.as_bytes());
    if let Some(one_time_prekey) = input.responder_one_time_prekey {
        transcript.push(1);
        transcript.extend_from_slice(&one_time_prekey.id.to_be_bytes());
        transcript.extend_from_slice(one_time_prekey.public_key.as_bytes());
    } else {
        transcript.push(0);
    }
    transcript.extend_from_slice(input.sender_identity_key);
    transcript.extend_from_slice(input.sender_identity_verifying_key);
    transcript.extend_from_slice(input.sender_discovery_key);
    extend_len_prefixed(&mut transcript, input.sender_certificate);
    extend_len_prefixed(&mut transcript, input.sender_signature);
    transcript
}

fn extend_len_prefixed(transcript: &mut Vec<u8>, bytes: &[u8]) {
    transcript.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    transcript.extend_from_slice(bytes);
}

fn envelope_sender_proof_transcript(
    envelope: &HandshakeEnvelope,
    responder_discovery_public_key: &PublicKey,
    sender_identity: &SenderIdentityMaterial,
    sender_discovery_key: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let reference = envelope_prekey_reference(envelope)?;
    let one_time_prekey = reference
        .one_time_prekey_id
        .zip(reference.one_time_prekey_public_key)
        .map(|(id, public_key)| OneTimePreKeyBundle {
            id,
            public_key: PublicKey::from(public_key),
            epoch: reference.discovery_epoch,
            created_at: 0,
        });
    let initiator_ephemeral_public_key = PublicKey::from(envelope.ephemeral_public_key);
    let responder_signed_prekey_public_key = PublicKey::from(reference.signed_prekey_public_key);
    Ok(sender_proof_transcript(SenderProofTranscriptInput {
        sender_identity_key: &sender_identity.identity_key,
        sender_identity_verifying_key: &sender_identity.identity_verifying_key,
        sender_discovery_key,
        sender_certificate: &sender_identity.certificate,
        sender_signature: &sender_identity.signature,
        initiator_ephemeral_public_key: &initiator_ephemeral_public_key,
        responder_discovery_public_key,
        responder_discovery_epoch: reference.discovery_epoch,
        responder_signed_prekey_public_key: &responder_signed_prekey_public_key,
        responder_one_time_prekey: one_time_prekey.as_ref(),
    }))
}

fn derive_sender_proof(
    sender_proof_secret: &SharedSecret,
    transcript: &[u8],
) -> Result<Zeroizing<[u8; SENDER_PROOF_LEN]>, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, sender_proof_secret.as_bytes());
    let mut proof = Zeroizing::new([0u8; SENDER_PROOF_LEN]);
    hkdf.expand(transcript, proof.as_mut())
        .map_err(|_| CryptoError::HkdfExpand)?;
    Ok(proof)
}

fn verify_sender_proof(
    envelope: &HandshakeEnvelope,
    responder_discovery_public_key: &PublicKey,
    responder_signed_prekey: &SignedPreKey,
    sender_identity: &SenderIdentityMaterial,
    sender_discovery_key: &[u8; 32],
    actual_proof: &[u8],
) -> Result<(), CryptoError> {
    if actual_proof.len() != SENDER_PROOF_LEN {
        return Err(CryptoError::HandshakeEnvelopeDecode);
    }
    let sender_identity_key = PublicKey::from(*sender_discovery_key);
    let sender_proof_secret =
        checked_shared_secret(responder_signed_prekey.diffie_hellman(&sender_identity_key))?;
    let transcript = envelope_sender_proof_transcript(
        envelope,
        responder_discovery_public_key,
        sender_identity,
        sender_discovery_key,
    )?;
    let expected_proof = derive_sender_proof(&sender_proof_secret, &transcript)?;
    let proof_matches: bool = expected_proof.as_ref().ct_eq(actual_proof).into();
    if !proof_matches {
        return Err(CryptoError::SignatureInvalid);
    }
    Ok(())
}

/// Returns the associated data for the first ratcheted message.
///
/// The bytes are the responder discovery public key and responder discovery-key epoch in
/// big-endian order.
#[must_use]
pub fn initial_associated_data(
    responder_discovery_public_key: &PublicKey,
    responder_discovery_epoch: u32,
) -> [u8; 36] {
    let mut associated_data = [0u8; 36];
    associated_data[..32].copy_from_slice(responder_discovery_public_key.as_bytes());
    associated_data[32..].copy_from_slice(&responder_discovery_epoch.to_be_bytes());
    associated_data
}

#[derive(Serialize)]
struct SealedSenderEnvelopeWire<'a> {
    version: u8,
    sender_identity_key: [u8; 32],
    sender_identity_verifying_key: [u8; 32],
    sender_identity_binding_signature: &'a [u8],
    sender_discovery_key: [u8; 32],
    sender_certificate: &'a [u8],
    sender_signature: &'a [u8],
    sender_proof: &'a [u8],
    plaintext: &'a [u8],
}

#[derive(Deserialize)]
struct DecodedSealedSenderEnvelopeWire {
    version: u8,
    sender_identity_key: [u8; 32],
    sender_identity_verifying_key: [u8; 32],
    sender_identity_binding_signature: Vec<u8>,
    sender_discovery_key: [u8; 32],
    sender_certificate: Vec<u8>,
    sender_signature: Vec<u8>,
    sender_proof: Vec<u8>,
    plaintext: Vec<u8>,
}

struct DecodedSealedSenderEnvelope {
    message: AcceptedInitialMessage,
    sender_discovery_key: [u8; 32],
    sender_proof: Zeroizing<Vec<u8>>,
}

struct SealedSenderEnvelopeInput<'a> {
    sender_identity_key: [u8; 32],
    sender_identity_verifying_key: [u8; 32],
    sender_identity_binding_signature: [u8; 64],
    sender_discovery_key: [u8; 32],
    sender_certificate: &'a [u8],
    sender_signature: &'a [u8],
    sender_proof: &'a [u8],
    plaintext: &'a [u8],
}

fn encode_sealed_sender_envelope(
    input: SealedSenderEnvelopeInput<'_>,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if input.sender_proof.len() != SENDER_PROOF_LEN {
        return Err(CryptoError::HandshakeEnvelopeEncode);
    }
    validate_sender_material_lengths(
        &input.sender_identity_binding_signature,
        input.sender_certificate,
        input.sender_signature,
        input.sender_proof,
        input.plaintext,
        CryptoError::HandshakeEnvelopeEncode,
    )?;
    let sealed = Zeroizing::new(
        postcard::to_stdvec(&SealedSenderEnvelopeWire {
            version: SEALED_SENDER_ENVELOPE_VERSION,
            sender_identity_key: input.sender_identity_key,
            sender_identity_verifying_key: input.sender_identity_verifying_key,
            sender_identity_binding_signature: &input.sender_identity_binding_signature,
            sender_discovery_key: input.sender_discovery_key,
            sender_certificate: input.sender_certificate,
            sender_signature: input.sender_signature,
            sender_proof: input.sender_proof,
            plaintext: input.plaintext,
        })
        .map_err(|_| CryptoError::HandshakeEnvelopeEncode)?,
    );
    if sealed.len() > MAX_HANDSHAKE_SEALED_SENDER_ENVELOPE_LEN {
        return Err(CryptoError::HandshakeEnvelopeEncode);
    }
    Ok(sealed)
}

fn decode_sealed_sender_envelope(bytes: &[u8]) -> Result<DecodedSealedSenderEnvelope, CryptoError> {
    let (wire, trailing): (DecodedSealedSenderEnvelopeWire, &[u8]) =
        postcard::take_from_bytes(bytes).map_err(|_| CryptoError::HandshakeEnvelopeDecode)?;
    let plaintext = Zeroizing::new(wire.plaintext);
    let sender_proof = Zeroizing::new(wire.sender_proof);
    let sender_identity = SenderIdentityMaterial {
        identity_key: wire.sender_identity_key,
        identity_verifying_key: wire.sender_identity_verifying_key,
        identity_binding_signature: wire.sender_identity_binding_signature,
        certificate: wire.sender_certificate,
        signature: wire.sender_signature,
    };
    if !trailing.is_empty()
        || wire.version != SEALED_SENDER_ENVELOPE_VERSION
        || !validate_x25519_public_key(&wire.sender_discovery_key)
    {
        return Err(CryptoError::HandshakeEnvelopeDecode);
    }
    if sender_proof.len() != SENDER_PROOF_LEN {
        return Err(CryptoError::HandshakeEnvelopeDecode);
    }
    validate_sender_identity(&sender_identity)?;
    validate_sender_material_lengths(
        &sender_identity.identity_binding_signature,
        &sender_identity.certificate,
        &sender_identity.signature,
        &sender_proof,
        &plaintext,
        CryptoError::HandshakeEnvelopeDecode,
    )?;
    Ok(DecodedSealedSenderEnvelope {
        message: AcceptedInitialMessage {
            plaintext,
            sender_identity,
        },
        sender_discovery_key: wire.sender_discovery_key,
        sender_proof,
    })
}

fn validate_sender_identity(sender_identity: &SenderIdentityMaterial) -> Result<(), CryptoError> {
    let bundle = IdentityKeyBundle::from_bytes(
        &sender_identity.identity_key,
        &sender_identity.identity_verifying_key,
        &sender_identity.identity_binding_signature,
    )
    .map_err(|_| CryptoError::HandshakeEnvelopeDecode)?;
    verify_identity_key_bundle(&bundle).map_err(|_| CryptoError::HandshakeEnvelopeDecode)?;
    if !validate_x25519_public_key(&sender_identity.identity_key) {
        return Err(CryptoError::HandshakeEnvelopeDecode);
    }
    validate_sender_material_lengths(
        &sender_identity.identity_binding_signature,
        &sender_identity.certificate,
        &sender_identity.signature,
        &[],
        &[],
        CryptoError::HandshakeEnvelopeDecode,
    )
}

fn validate_sender_material_lengths(
    identity_binding_signature: &[u8],
    certificate: &[u8],
    signature: &[u8],
    proof: &[u8],
    plaintext: &[u8],
    error: CryptoError,
) -> Result<(), CryptoError> {
    let content_len = certificate
        .len()
        .checked_add(identity_binding_signature.len())
        .and_then(|len| len.checked_add(signature.len()))
        .and_then(|len| len.checked_add(proof.len()))
        .and_then(|len| len.checked_add(plaintext.len()));
    if identity_binding_signature.len() != 64
        || certificate.len() > MAX_SENDER_CERTIFICATE_LEN
        || signature.len() > MAX_SENDER_SIGNATURE_LEN
        || content_len.is_none_or(|len| len > MAX_HANDSHAKE_SEALED_SENDER_CONTENT_LEN)
    {
        return Err(error);
    }
    Ok(())
}

// Derives the 32-byte ratchet root key from identity-bound X3DH input keying material.
//
// Using no salt means the RFC 5869 zero salt. That is acceptable here because the input keying
// material is already uniformly random and the info string provides domain separation.
fn derive_root_key_from_input_keying_material(
    input_keying_material: &[u8],
    info: &[u8],
) -> Result<RootKey, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, input_keying_material);
    let mut output_keying_material = Zeroizing::new([0u8; 32]);
    hkdf.expand(info, output_keying_material.as_mut())
        .map_err(|_| CryptoError::HkdfExpand)?;
    Ok(RootKey::from_bytes(*output_keying_material))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery_key::{
        DiscoveryKey, generate_discovery_key, generate_signed_prekey_for_discovery_key,
    };
    use crate::keys::{
        IdentityKeyBundle, KeyPair, SigningKeyPair, generate_key_pair, generate_signing_key_pair,
        sign_identity_key_binding,
    };
    use crate::one_time_prekey::{OneTimePreKey, generate_one_time_prekey};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    const FIXED_TS: u64 = 1_700_000_000;

    struct FullX3dhSetup {
        alice_identity_key: IdentityKeyBundle,
        alice_discovery_key: DiscoveryKey,
        bob_identity_key: IdentityKeyBundle,
        bob_discovery_key: DiscoveryKey,
        bob_signed_prekey: SignedPreKey,
        bob_one_time_prekey: OneTimePreKey,
    }

    fn full_x3dh_setup() -> (FullX3dhSetup, ChaCha20Rng) {
        let mut rng = ChaCha20Rng::from_seed([0x42u8; 32]);
        let alice_identity = generate_signing_key_pair(&mut rng);
        let alice_identity_key = generated_identity_key_bundle(&mut rng, &alice_identity);
        let alice_discovery_key = generate_discovery_key(&mut rng, &alice_identity, 2, FIXED_TS);
        let bob_identity = generate_signing_key_pair(&mut rng);
        let bob_identity_key = generated_identity_key_bundle(&mut rng, &bob_identity);
        let bob_discovery_key = generate_discovery_key(&mut rng, &bob_identity, 3, FIXED_TS);
        let bob_signed_prekey =
            generate_signed_prekey_for_discovery_key(&mut rng, &bob_discovery_key, 0, FIXED_TS);
        let bob_one_time_prekey =
            generate_one_time_prekey(&mut rng, 9, bob_discovery_key.epoch(), FIXED_TS);
        let setup = FullX3dhSetup {
            alice_identity_key,
            alice_discovery_key,
            bob_identity_key,
            bob_discovery_key,
            bob_signed_prekey,
            bob_one_time_prekey,
        };
        (setup, rng)
    }

    fn full_prekey_bundle(setup: &FullX3dhSetup, include_one_time: bool) -> PreKeyBundle {
        PreKeyBundle {
            version: PREKEY_BUNDLE_VERSION,
            discovery_key: setup.bob_discovery_key.bundle(),
            signed_prekey: setup.bob_signed_prekey.bundle(),
            one_time_prekey: include_one_time.then(|| setup.bob_one_time_prekey.bundle()),
        }
    }

    fn initial_plaintext(plaintext: &[u8]) -> InitialPlaintext<'_> {
        InitialPlaintext {
            sender_certificate: b"sender certificate",
            sender_signature: b"sender signature",
            plaintext,
        }
    }

    fn generated_identity_key_bundle(
        rng: &mut ChaCha20Rng,
        signing_key: &SigningKeyPair,
    ) -> IdentityKeyBundle {
        let agreement_key = generate_key_pair(rng);
        identity_key_bundle_from_parts(signing_key, agreement_key.public)
    }

    fn identity_key_bundle(rng: &mut ChaCha20Rng, x25519_secret: u8) -> IdentityKeyBundle {
        let signing_key = generate_signing_key_pair(rng);
        let agreement_key = KeyPair::from_secret_bytes([x25519_secret; 32]);
        identity_key_bundle_from_parts(&signing_key, agreement_key.public)
    }

    fn identity_key_bundle_from_parts(
        signing_key: &SigningKeyPair,
        public_key: PublicKey,
    ) -> IdentityKeyBundle {
        let binding_signature = sign_identity_key_binding(signing_key, &public_key).unwrap();
        IdentityKeyBundle {
            public_key,
            verifying_key: signing_key.verifying,
            binding_signature,
        }
    }

    fn envelope_reference(envelope: &HandshakeEnvelope) -> SealedFramePreKeyReference {
        envelope.prekey_reference.unwrap()
    }

    fn test_prekey_reference(
        setup: &FullX3dhSetup,
        signed_prekey_public_key: &PublicKey,
        one_time_prekey: Option<&OneTimePreKey>,
    ) -> SealedFramePreKeyReference {
        SealedFramePreKeyReference {
            discovery_epoch: setup.bob_discovery_key.epoch(),
            signed_prekey_public_key: *signed_prekey_public_key.as_bytes(),
            one_time_prekey_id: one_time_prekey.map(OneTimePreKey::id),
            one_time_prekey_public_key: one_time_prekey.map(|prekey| *prekey.public().as_bytes()),
        }
    }

    fn test_handshake_envelope(
        setup: &FullX3dhSetup,
        initiator_ephemeral_key: &KeyPair,
        responder_signed_prekey_public_key: &PublicKey,
        one_time_prekey: Option<&OneTimePreKey>,
        header: &Header,
        ciphertext: &[u8],
    ) -> HandshakeEnvelope {
        let frame_plaintext =
            encode_handshake_frame_plaintext(header, ciphertext, &setup.alice_identity_key)
                .unwrap();
        let frame = seal_frame_with_ephemeral_key(
            initiator_ephemeral_key,
            setup.bob_discovery_key.public_key(),
            Some(test_prekey_reference(
                setup,
                responder_signed_prekey_public_key,
                one_time_prekey,
            )),
            &frame_plaintext,
        )
        .unwrap();
        HandshakeEnvelope::from_frame(frame)
    }

    /// Known-answer test for full X3DH root-key derivation with an OPK.
    ///
    /// Source: Aether's X25519 constructors and X3DH HKDF ordering
    ///
    /// Inputs:
    /// - `alice_ephemeral_secret = [0x22; 32]`
    /// - `bob_discovery_secret = [0x31; 32]`
    /// - `bob_signed_prekey_secret = [0x41; 32]`
    /// - `bob_one_time_prekey_secret = [0x51; 32]`
    ///
    /// Output: `HKDF(F_PREFIX || IK_A || IK_B || DH2 || DH3 || DH4,
    /// HKDF_INFO_WITH_ONE_TIME_PREKEY)`.
    #[test]
    fn full_x3dh_root_key_known_answer() {
        const EXPECTED_ROOT_KEY: [u8; 32] = [
            224, 196, 164, 213, 182, 189, 132, 157, 182, 16, 163, 115, 188, 215, 67, 15, 240, 101,
            249, 86, 182, 103, 84, 218, 198, 97, 217, 80, 254, 247, 137, 126,
        ];

        let alice_ephemeral_key = KeyPair::from_secret_bytes([0x22u8; 32]);
        let alice_identity = SigningKeyPair::from_signing_bytes([0x12u8; 32]);
        let alice_identity_key = identity_key_bundle_from_parts(
            &alice_identity,
            KeyPair::from_secret_bytes([0x13u8; 32]).public,
        );
        let bob_identity = SigningKeyPair::from_signing_bytes([0x14u8; 32]);
        let bob_identity_key = identity_key_bundle_from_parts(
            &bob_identity,
            KeyPair::from_secret_bytes([0x15u8; 32]).public,
        );
        let bob_discovery_key =
            DiscoveryKey::from_secret_bytes([0x31u8; 32], [0x72u8; 32], 3, FIXED_TS, [0u8; 64]);
        let bob_signed_prekey =
            SignedPreKey::from_secret_bytes([0x41u8; 32], [0u8; 64], 0, 3, FIXED_TS);
        let bob_one_time_prekey = OneTimePreKey::from_secret_bytes(9, [0x51u8; 32], 3, FIXED_TS);

        let initiator_root_key = derive_root_key_initiator(
            &alice_ephemeral_key,
            &alice_identity_key,
            &bob_identity_key,
            bob_discovery_key.public_key(),
            bob_signed_prekey.public(),
            Some(bob_one_time_prekey.public()),
        )
        .unwrap();
        let responder_root_key = derive_root_key_responder(
            &alice_ephemeral_key.public,
            &alice_identity_key,
            &bob_identity_key,
            &bob_discovery_key,
            &bob_signed_prekey,
            Some(&bob_one_time_prekey),
        )
        .unwrap();

        assert_eq!(initiator_root_key.as_bytes(), responder_root_key.as_bytes());
        assert_eq!(initiator_root_key.as_bytes(), &EXPECTED_ROOT_KEY);
    }

    #[test]
    fn versioned_prekey_bundle_reserves_ml_kem_768_headroom() {
        // Source: NIST FIPS 203, Table 3.
        const ML_KEM_768_ENCAPSULATION_KEY_LEN: usize = 1184;
        const ML_KEM_768_SHARED_SECRET_LEN: usize = 32;

        let (setup, _) = full_x3dh_setup();
        let bundle = full_prekey_bundle(&setup, true);

        assert_eq!(bundle.version, PREKEY_BUNDLE_VERSION);
        const {
            assert!(ML_KEM_768_ENCAPSULATION_KEY_LEN <= PREKEY_BUNDLE_ADDITIVE_PUBLIC_KEY_HEADROOM);
            assert!(ML_KEM_768_SHARED_SECRET_LEN <= X3DH_ADDITIVE_SHARED_SECRET_HEADROOM);
        }
    }

    #[test]
    fn full_x3dh_associated_data_binds_responder_discovery_key_and_epoch() {
        let (setup, _) = full_x3dh_setup();
        let associated_data = initial_associated_data(
            setup.bob_discovery_key.public_key(),
            setup.bob_discovery_key.epoch(),
        );
        assert_eq!(
            &associated_data[..32],
            setup.bob_discovery_key.public_key().as_bytes()
        );
        assert_eq!(
            &associated_data[32..],
            &setup.bob_discovery_key.epoch().to_be_bytes()
        );
    }

    #[test]
    fn initiate_accept_round_trip_with_one_time_prekey() {
        let (setup, mut rng) = full_x3dh_setup();
        let plaintext = b"hello full x3dh";
        let bundle = full_prekey_bundle(&setup, true);
        let (_, envelope) = initiate(
            &mut rng,
            &setup.alice_discovery_key,
            &setup.alice_identity_key,
            &setup.bob_identity_key,
            &bundle,
            initial_plaintext(plaintext),
        )
        .unwrap();
        assert_eq!(
            envelope_reference(&envelope).one_time_prekey_id,
            Some(setup.bob_one_time_prekey.id())
        );
        let (_, decrypted) = accept(
            &mut rng,
            &envelope,
            Some(&setup.alice_identity_key),
            &setup.bob_identity_key,
            &setup.bob_discovery_key,
            &setup.bob_signed_prekey,
            Some(setup.bob_one_time_prekey),
        )
        .unwrap();
        assert_eq!(decrypted.plaintext.as_slice(), plaintext);
    }

    #[test]
    fn handshake_envelope_does_not_expose_initiator_discovery_key() {
        let (setup, mut rng) = full_x3dh_setup();
        let bundle = full_prekey_bundle(&setup, true);
        let (_, envelope) = initiate(
            &mut rng,
            &setup.alice_discovery_key,
            &setup.alice_identity_key,
            &setup.bob_identity_key,
            &bundle,
            initial_plaintext(b"hello sealed x3dh"),
        )
        .unwrap();

        let bytes = envelope.to_bytes().unwrap();

        assert!(
            !bytes
                .windows(setup.alice_discovery_key.public_key().as_bytes().len())
                .any(|window| window == setup.alice_discovery_key.public_key().as_bytes())
        );
    }

    #[test]
    fn accept_exposes_sender_identity_after_decrypt() {
        let (setup, mut rng) = full_x3dh_setup();
        let plaintext = b"hello sealed identity";
        let bundle = full_prekey_bundle(&setup, true);
        let (_, envelope) = initiate(
            &mut rng,
            &setup.alice_discovery_key,
            &setup.alice_identity_key,
            &setup.bob_identity_key,
            &bundle,
            initial_plaintext(b"hello sealed identity"),
        )
        .unwrap();
        let (_, decrypted) = accept(
            &mut rng,
            &envelope,
            Some(&setup.alice_identity_key),
            &setup.bob_identity_key,
            &setup.bob_discovery_key,
            &setup.bob_signed_prekey,
            Some(setup.bob_one_time_prekey),
        )
        .unwrap();

        assert_eq!(decrypted.plaintext.as_slice(), plaintext);
        assert_eq!(
            decrypted.sender_identity.identity_key,
            *setup.alice_identity_key.public_key.as_bytes()
        );
        assert_eq!(
            decrypted.sender_identity.identity_verifying_key,
            setup.alice_identity_key.verifying_key.to_bytes()
        );
    }

    /// The hint is readable *before* accepting, and that ordering is what makes
    /// it usable at all.
    ///
    /// A caller addresses session state by a key derived from both identities,
    /// so it has to know who sent a message before it can accept one — and
    /// `accept` consumes the referenced one-time prekey, so it cannot be called
    /// speculatively to find out. Reading the hint costs nothing and consumes
    /// nothing: it opens only the layer sealed to the responder's own Discovery
    /// Key.
    #[test]
    fn the_initiator_identity_is_readable_before_accepting() {
        let (setup, mut rng) = full_x3dh_setup();
        let bundle = full_prekey_bundle(&setup, true);
        let (_, envelope) = initiate(
            &mut rng,
            &setup.alice_discovery_key,
            &setup.alice_identity_key,
            &setup.bob_identity_key,
            &bundle,
            initial_plaintext(b"hello stranger"),
        )
        .unwrap();

        let hint = initiator_identity_hint(&envelope, &setup.bob_discovery_key).unwrap();

        assert_eq!(
            hint.public_key.as_bytes(),
            setup.alice_identity_key.public_key.as_bytes()
        );
        assert_eq!(
            hint.verifying_key.to_bytes(),
            setup.alice_identity_key.verifying_key.to_bytes()
        );

        // Nothing was consumed: the accept that follows still finds its
        // one-time prekey, which is the whole point of peeking separately.
        let (_, decrypted) = accept(
            &mut rng,
            &envelope,
            None,
            &setup.bob_identity_key,
            &setup.bob_discovery_key,
            &setup.bob_signed_prekey,
            Some(setup.bob_one_time_prekey),
        )
        .unwrap();
        assert_eq!(decrypted.plaintext.as_slice(), b"hello stranger");
    }

    /// A message request. The responder has never seen this initiator and holds
    /// nothing to guess with, so it supplies no expected identity and reads the
    /// sender from the frame instead.
    ///
    /// Sealed sender puts the sender inside the layer that needs the sender to
    /// open — `derive_root_key_responder` wants the initiator's X25519 half
    /// before any ciphertext can be touched. So without a hint in the layer the
    /// recipient can already open with its own Discovery Key, a first message
    /// from a stranger is unopenable, and every X3DH initial stays queued.
    #[test]
    fn accept_opens_a_first_message_from_an_unknown_initiator() {
        let (setup, mut rng) = full_x3dh_setup();
        let plaintext = b"hello stranger";
        let bundle = full_prekey_bundle(&setup, true);
        let (_, envelope) = initiate(
            &mut rng,
            &setup.alice_discovery_key,
            &setup.alice_identity_key,
            &setup.bob_identity_key,
            &bundle,
            initial_plaintext(plaintext),
        )
        .unwrap();

        let (_, decrypted) = accept(
            &mut rng,
            &envelope,
            None,
            &setup.bob_identity_key,
            &setup.bob_discovery_key,
            &setup.bob_signed_prekey,
            Some(setup.bob_one_time_prekey),
        )
        .unwrap();

        assert_eq!(decrypted.plaintext.as_slice(), plaintext);
        assert_eq!(
            decrypted.sender_identity.identity_key,
            *setup.alice_identity_key.public_key.as_bytes()
        );
        assert_eq!(
            decrypted.sender_identity.identity_verifying_key,
            setup.alice_identity_key.verifying_key.to_bytes()
        );
    }

    #[test]
    fn initiate_accept_round_trip_without_one_time_prekey() {
        let (setup, mut rng) = full_x3dh_setup();
        let plaintext = b"hello signed prekey only";
        let bundle = full_prekey_bundle(&setup, false);
        let (_, envelope) = initiate(
            &mut rng,
            &setup.alice_discovery_key,
            &setup.alice_identity_key,
            &setup.bob_identity_key,
            &bundle,
            initial_plaintext(plaintext),
        )
        .unwrap();
        assert_eq!(envelope_reference(&envelope).one_time_prekey_id, None);
        let (_, decrypted) = accept(
            &mut rng,
            &envelope,
            Some(&setup.alice_identity_key),
            &setup.bob_identity_key,
            &setup.bob_discovery_key,
            &setup.bob_signed_prekey,
            None,
        )
        .unwrap();
        assert_eq!(decrypted.plaintext.as_slice(), plaintext);
    }

    #[test]
    fn accept_rejects_missing_one_time_prekey() {
        let (setup, mut rng) = full_x3dh_setup();
        let bundle = full_prekey_bundle(&setup, true);
        let (_, envelope) = initiate(
            &mut rng,
            &setup.alice_discovery_key,
            &setup.alice_identity_key,
            &setup.bob_identity_key,
            &bundle,
            initial_plaintext(b"payload"),
        )
        .unwrap();
        assert!(matches!(
            accept(
                &mut rng,
                &envelope,
                Some(&setup.alice_identity_key),
                &setup.bob_identity_key,
                &setup.bob_discovery_key,
                &setup.bob_signed_prekey,
                None,
            ),
            Err(CryptoError::MissingOneTimePreKey)
        ));
    }

    #[test]
    fn accept_rejects_mismatched_one_time_prekey() {
        let (setup, mut rng) = full_x3dh_setup();
        let wrong_one_time_prekey =
            generate_one_time_prekey(&mut rng, 10, setup.bob_discovery_key.epoch(), FIXED_TS);
        let bundle = full_prekey_bundle(&setup, true);
        let (_, envelope) = initiate(
            &mut rng,
            &setup.alice_discovery_key,
            &setup.alice_identity_key,
            &setup.bob_identity_key,
            &bundle,
            initial_plaintext(b"payload"),
        )
        .unwrap();
        assert!(matches!(
            accept(
                &mut rng,
                &envelope,
                Some(&setup.alice_identity_key),
                &setup.bob_identity_key,
                &setup.bob_discovery_key,
                &setup.bob_signed_prekey,
                Some(wrong_one_time_prekey),
            ),
            Err(CryptoError::OneTimePreKeyMismatch)
        ));
    }

    #[test]
    fn initiate_rejects_stale_one_time_prekey_epoch() {
        let (setup, mut rng) = full_x3dh_setup();
        let stale_one_time_prekey =
            generate_one_time_prekey(&mut rng, 10, setup.bob_discovery_key.epoch() + 1, FIXED_TS);
        let bundle = PreKeyBundle {
            version: PREKEY_BUNDLE_VERSION,
            discovery_key: setup.bob_discovery_key.bundle(),
            signed_prekey: setup.bob_signed_prekey.bundle(),
            one_time_prekey: Some(stale_one_time_prekey.bundle()),
        };
        assert!(matches!(
            initiate(
                &mut rng,
                &setup.alice_discovery_key,
                &setup.alice_identity_key,
                &setup.bob_identity_key,
                &bundle,
                initial_plaintext(b"payload"),
            ),
            Err(CryptoError::StalePreKey)
        ));
    }

    #[test]
    fn initiate_rejects_unsupported_prekey_bundle_version() {
        let (setup, mut rng) = full_x3dh_setup();
        let bundle = PreKeyBundle {
            version: PREKEY_BUNDLE_VERSION + 1,
            discovery_key: setup.bob_discovery_key.bundle(),
            signed_prekey: setup.bob_signed_prekey.bundle(),
            one_time_prekey: Some(setup.bob_one_time_prekey.bundle()),
        };

        assert!(matches!(
            initiate(
                &mut rng,
                &setup.alice_discovery_key,
                &setup.alice_identity_key,
                &setup.bob_identity_key,
                &bundle,
                initial_plaintext(b"payload"),
            ),
            Err(CryptoError::UnsupportedPreKeyBundleVersion(version))
                if version == PREKEY_BUNDLE_VERSION + 1
        ));
    }

    #[test]
    fn initiate_rejects_oversized_sealed_first_message() {
        let (setup, mut rng) = full_x3dh_setup();
        let bundle = full_prekey_bundle(&setup, true);
        let oversized_plaintext = vec![0u8; MAX_HANDSHAKE_SEALED_SENDER_CONTENT_LEN + 1];

        let result = initiate(
            &mut rng,
            &setup.alice_discovery_key,
            &setup.alice_identity_key,
            &setup.bob_identity_key,
            &bundle,
            initial_plaintext(&oversized_plaintext),
        );

        assert!(matches!(result, Err(CryptoError::HandshakeEnvelopeEncode)));
    }

    #[test]
    fn initiator_and_responder_derive_identical_root_key() {
        let (setup, mut rng) = full_x3dh_setup();
        let alice_identity_key = identity_key_bundle(&mut rng, 0x91);
        let bob_identity_key = identity_key_bundle(&mut rng, 0x92);
        let alice_ephemeral_key = generate_key_pair(&mut rng);
        let initiator_root_key = derive_root_key_initiator(
            &alice_ephemeral_key,
            &alice_identity_key,
            &bob_identity_key,
            setup.bob_discovery_key.public_key(),
            setup.bob_signed_prekey.public(),
            Some(setup.bob_one_time_prekey.public()),
        )
        .unwrap();
        let responder_root_key = derive_root_key_responder(
            &alice_ephemeral_key.public,
            &alice_identity_key,
            &bob_identity_key,
            &setup.bob_discovery_key,
            &setup.bob_signed_prekey,
            Some(&setup.bob_one_time_prekey),
        )
        .unwrap();
        assert_eq!(initiator_root_key.as_bytes(), responder_root_key.as_bytes());
    }

    #[test]
    fn x3dh_root_changes_when_identity_binding_changes() {
        let (setup, mut rng) = full_x3dh_setup();
        let alice_identity_key = identity_key_bundle(&mut rng, 0x93);
        let bob_identity_key = identity_key_bundle(&mut rng, 0x94);
        let other_bob_identity_key = identity_key_bundle(&mut rng, 0x95);
        let alice_ephemeral_key = generate_key_pair(&mut rng);

        let root_key = derive_root_key_initiator(
            &alice_ephemeral_key,
            &alice_identity_key,
            &bob_identity_key,
            setup.bob_discovery_key.public_key(),
            setup.bob_signed_prekey.public(),
            Some(setup.bob_one_time_prekey.public()),
        )
        .unwrap();
        let rebound_root_key = derive_root_key_initiator(
            &alice_ephemeral_key,
            &alice_identity_key,
            &other_bob_identity_key,
            setup.bob_discovery_key.public_key(),
            setup.bob_signed_prekey.public(),
            Some(setup.bob_one_time_prekey.public()),
        )
        .unwrap();

        assert_ne!(root_key.as_bytes(), rebound_root_key.as_bytes());
    }

    #[test]
    fn root_derivation_rejects_non_contributory_peer_key() {
        let (setup, _) = full_x3dh_setup();
        let low_order_public_key = PublicKey::from([0u8; 32]);

        assert!(matches!(
            derive_root_key_responder(
                &low_order_public_key,
                &setup.alice_identity_key,
                &setup.bob_identity_key,
                &setup.bob_discovery_key,
                &setup.bob_signed_prekey,
                Some(&setup.bob_one_time_prekey),
            ),
            Err(CryptoError::NonContributorySharedSecret)
        ));
    }

    #[test]
    fn initiate_rejects_bundle_under_wrong_verifying_key() {
        let (setup, mut rng) = full_x3dh_setup();
        let wrong_signing_key = generate_signing_key_pair(&mut rng);
        let wrong_identity_key = generated_identity_key_bundle(&mut rng, &wrong_signing_key);
        let bundle = full_prekey_bundle(&setup, true);
        let result = initiate(
            &mut rng,
            &setup.alice_discovery_key,
            &setup.alice_identity_key,
            &wrong_identity_key,
            &bundle,
            initial_plaintext(b"payload"),
        );
        assert!(matches!(result, Err(CryptoError::SignatureInvalid)));
    }

    #[test]
    fn accept_rejects_mismatched_signed_prekey_public_key() {
        let (setup, mut rng) = full_x3dh_setup();
        let bundle = full_prekey_bundle(&setup, false);
        let (_, mut envelope) = initiate(
            &mut rng,
            &setup.alice_discovery_key,
            &setup.alice_identity_key,
            &setup.bob_identity_key,
            &bundle,
            initial_plaintext(b"payload"),
        )
        .unwrap();
        envelope
            .prekey_reference
            .as_mut()
            .unwrap()
            .signed_prekey_public_key[0] ^= 0x01;
        assert!(matches!(
            accept(
                &mut rng,
                &envelope,
                Some(&setup.alice_identity_key),
                &setup.bob_identity_key,
                &setup.bob_discovery_key,
                &setup.bob_signed_prekey,
                None,
            ),
            Err(CryptoError::HandshakeSignedPreKeyMismatch)
        ));
    }

    #[test]
    fn accept_rejects_tampered_ciphertext() {
        let (setup, mut rng) = full_x3dh_setup();
        let bundle = full_prekey_bundle(&setup, false);
        let (_, mut envelope) = initiate(
            &mut rng,
            &setup.alice_discovery_key,
            &setup.alice_identity_key,
            &setup.bob_identity_key,
            &bundle,
            initial_plaintext(b"tamper me"),
        )
        .unwrap();
        envelope.ciphertext[0] ^= 0xFF;
        assert!(matches!(
            accept(
                &mut rng,
                &envelope,
                Some(&setup.alice_identity_key),
                &setup.bob_identity_key,
                &setup.bob_discovery_key,
                &setup.bob_signed_prekey,
                None,
            ),
            Err(CryptoError::Aead)
        ));
    }

    #[test]
    fn accept_rejects_malformed_sealed_sender_envelope() {
        let (setup, mut rng) = full_x3dh_setup();
        let initiator_ephemeral_key = generate_key_pair(&mut rng);
        let responder_signed_prekey_public_key = setup.bob_signed_prekey.public();
        let root_key = derive_root_key_initiator(
            &initiator_ephemeral_key,
            &setup.alice_identity_key,
            &setup.bob_identity_key,
            setup.bob_discovery_key.public_key(),
            responder_signed_prekey_public_key,
            None,
        )
        .unwrap();
        let mut state =
            RatchetState::init_initiator(&mut rng, root_key, responder_signed_prekey_public_key)
                .unwrap();
        let associated_data = initial_associated_data(
            setup.bob_discovery_key.public_key(),
            setup.bob_discovery_key.epoch(),
        );
        let (header, ciphertext) = state
            .ratchet_encrypt(b"not a sealed-sender envelope", &associated_data)
            .unwrap();
        let envelope = test_handshake_envelope(
            &setup,
            &initiator_ephemeral_key,
            responder_signed_prekey_public_key,
            None,
            &header,
            &ciphertext,
        );

        assert!(matches!(
            accept(
                &mut rng,
                &envelope,
                Some(&setup.alice_identity_key),
                &setup.bob_identity_key,
                &setup.bob_discovery_key,
                &setup.bob_signed_prekey,
                None,
            ),
            Err(CryptoError::HandshakeEnvelopeDecode)
        ));
    }

    #[test]
    fn accept_rejects_sender_identity_without_matching_proof() {
        let (setup, mut rng) = full_x3dh_setup();
        let initiator_ephemeral_key = generate_key_pair(&mut rng);
        let responder_signed_prekey_public_key = setup.bob_signed_prekey.public();
        let root_key = derive_root_key_initiator(
            &initiator_ephemeral_key,
            &setup.alice_identity_key,
            &setup.bob_identity_key,
            setup.bob_discovery_key.public_key(),
            responder_signed_prekey_public_key,
            None,
        )
        .unwrap();
        let mut state =
            RatchetState::init_initiator(&mut rng, root_key, responder_signed_prekey_public_key)
                .unwrap();
        let associated_data = initial_associated_data(
            setup.bob_discovery_key.public_key(),
            setup.bob_discovery_key.epoch(),
        );
        let bogus_sender_proof = [0u8; 32];
        let sealed = postcard::to_stdvec(&SealedSenderEnvelopeWire {
            version: SEALED_SENDER_ENVELOPE_VERSION,
            sender_identity_key: *setup.alice_identity_key.public_key.as_bytes(),
            sender_identity_verifying_key: setup.alice_identity_key.verifying_key.to_bytes(),
            sender_identity_binding_signature: &setup
                .alice_identity_key
                .binding_signature
                .to_bytes(),
            sender_discovery_key: *setup.alice_discovery_key.public_key().as_bytes(),
            sender_certificate: b"sender certificate",
            sender_signature: b"sender signature",
            sender_proof: &bogus_sender_proof,
            plaintext: b"payload",
        })
        .unwrap();
        let (header, ciphertext) = state.ratchet_encrypt(&sealed, &associated_data).unwrap();
        let envelope = test_handshake_envelope(
            &setup,
            &initiator_ephemeral_key,
            responder_signed_prekey_public_key,
            None,
            &header,
            &ciphertext,
        );

        assert!(matches!(
            accept(
                &mut rng,
                &envelope,
                Some(&setup.alice_identity_key),
                &setup.bob_identity_key,
                &setup.bob_discovery_key,
                &setup.bob_signed_prekey,
                None,
            ),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn accept_rejects_non_contributory_sender_identity_key() {
        let (setup, mut rng) = full_x3dh_setup();
        let initiator_ephemeral_key = generate_key_pair(&mut rng);
        let responder_signed_prekey_public_key = setup.bob_signed_prekey.public();
        let root_key = derive_root_key_initiator(
            &initiator_ephemeral_key,
            &setup.alice_identity_key,
            &setup.bob_identity_key,
            setup.bob_discovery_key.public_key(),
            responder_signed_prekey_public_key,
            None,
        )
        .unwrap();
        let mut state =
            RatchetState::init_initiator(&mut rng, root_key, responder_signed_prekey_public_key)
                .unwrap();
        let associated_data = initial_associated_data(
            setup.bob_discovery_key.public_key(),
            setup.bob_discovery_key.epoch(),
        );
        let bogus_sender_proof = [0u8; 32];
        let sealed = postcard::to_stdvec(&SealedSenderEnvelopeWire {
            version: SEALED_SENDER_ENVELOPE_VERSION,
            sender_identity_key: [0u8; 32],
            sender_identity_verifying_key: setup.alice_identity_key.verifying_key.to_bytes(),
            sender_identity_binding_signature: &setup
                .alice_identity_key
                .binding_signature
                .to_bytes(),
            sender_discovery_key: *setup.alice_discovery_key.public_key().as_bytes(),
            sender_certificate: b"sender certificate",
            sender_signature: b"sender signature",
            sender_proof: &bogus_sender_proof,
            plaintext: b"payload",
        })
        .unwrap();
        let (header, ciphertext) = state.ratchet_encrypt(&sealed, &associated_data).unwrap();
        let envelope = test_handshake_envelope(
            &setup,
            &initiator_ephemeral_key,
            responder_signed_prekey_public_key,
            None,
            &header,
            &ciphertext,
        );

        assert!(matches!(
            accept(
                &mut rng,
                &envelope,
                Some(&setup.alice_identity_key),
                &setup.bob_identity_key,
                &setup.bob_discovery_key,
                &setup.bob_signed_prekey,
                None,
            ),
            Err(CryptoError::HandshakeEnvelopeDecode)
        ));
    }

    #[test]
    fn sender_proof_transcript_commits_to_identity_verifying_key() {
        let (setup, _) = full_x3dh_setup();
        let ephemeral = KeyPair::from_secret_bytes([0x77u8; 32]);
        let sender_identity_key = [0x21u8; 32];
        let sender_discovery_key = [0x22u8; 32];
        let verifying_key_a = [0x31u8; 32];
        let verifying_key_b = [0x32u8; 32];

        let transcript_a = sender_proof_transcript(SenderProofTranscriptInput {
            sender_identity_key: &sender_identity_key,
            sender_identity_verifying_key: &verifying_key_a,
            sender_discovery_key: &sender_discovery_key,
            sender_certificate: b"cert",
            sender_signature: b"sig",
            initiator_ephemeral_public_key: &ephemeral.public,
            responder_discovery_public_key: setup.bob_discovery_key.public_key(),
            responder_discovery_epoch: setup.bob_discovery_key.epoch(),
            responder_signed_prekey_public_key: setup.bob_signed_prekey.public(),
            responder_one_time_prekey: None,
        });
        let transcript_b = sender_proof_transcript(SenderProofTranscriptInput {
            sender_identity_key: &sender_identity_key,
            sender_identity_verifying_key: &verifying_key_b,
            sender_discovery_key: &sender_discovery_key,
            sender_certificate: b"cert",
            sender_signature: b"sig",
            initiator_ephemeral_public_key: &ephemeral.public,
            responder_discovery_public_key: setup.bob_discovery_key.public_key(),
            responder_discovery_epoch: setup.bob_discovery_key.epoch(),
            responder_signed_prekey_public_key: setup.bob_signed_prekey.public(),
            responder_one_time_prekey: None,
        });

        assert_ne!(transcript_a.as_slice(), transcript_b.as_slice());
    }

    #[test]
    fn accept_rejects_sealed_identity_not_bound_to_root() {
        let (setup, mut rng) = full_x3dh_setup();
        // The identity folded into the X3DH root, which the responder verifies as the peer.
        let root_bound_identity_key = setup.alice_identity_key.clone();
        // A self-consistent identity the malicious initiator seals in place of the root-bound one.
        let impersonated_identity_key = identity_key_bundle(&mut rng, 0xA7);
        let attacker_signing = generate_signing_key_pair(&mut rng);
        let attacker_discovery_key =
            generate_discovery_key(&mut rng, &attacker_signing, 5, FIXED_TS);

        let initiator_ephemeral_key = generate_key_pair(&mut rng);
        let responder_signed_prekey_public_key = setup.bob_signed_prekey.public();
        let root_key = derive_root_key_initiator(
            &initiator_ephemeral_key,
            &root_bound_identity_key,
            &setup.bob_identity_key,
            setup.bob_discovery_key.public_key(),
            responder_signed_prekey_public_key,
            None,
        )
        .unwrap();
        let mut state =
            RatchetState::init_initiator(&mut rng, root_key, responder_signed_prekey_public_key)
                .unwrap();
        let associated_data = initial_associated_data(
            setup.bob_discovery_key.public_key(),
            setup.bob_discovery_key.epoch(),
        );

        // Seal the impersonated identity behind a valid key-possession proof for the attacker's
        // own discovery key, so decode and sender-proof verification both succeed.
        let sender_identity_key = *impersonated_identity_key.public_key.as_bytes();
        let sender_discovery_key = *attacker_discovery_key.public_key().as_bytes();
        let sender_proof_secret = checked_shared_secret(
            attacker_discovery_key.diffie_hellman(responder_signed_prekey_public_key),
        )
        .unwrap();
        let transcript = sender_proof_transcript(SenderProofTranscriptInput {
            sender_identity_key: &sender_identity_key,
            sender_identity_verifying_key: impersonated_identity_key.verifying_key.as_bytes(),
            sender_discovery_key: &sender_discovery_key,
            sender_certificate: b"sender certificate",
            sender_signature: b"sender signature",
            initiator_ephemeral_public_key: &initiator_ephemeral_key.public,
            responder_discovery_public_key: setup.bob_discovery_key.public_key(),
            responder_discovery_epoch: setup.bob_discovery_key.epoch(),
            responder_signed_prekey_public_key,
            responder_one_time_prekey: None,
        });
        let sender_proof = derive_sender_proof(&sender_proof_secret, &transcript).unwrap();
        let sealed = encode_sealed_sender_envelope(SealedSenderEnvelopeInput {
            sender_identity_key,
            sender_identity_verifying_key: *impersonated_identity_key.verifying_key.as_bytes(),
            sender_identity_binding_signature: impersonated_identity_key
                .binding_signature
                .to_bytes(),
            sender_discovery_key,
            sender_certificate: b"sender certificate",
            sender_signature: b"sender signature",
            sender_proof: sender_proof.as_ref(),
            plaintext: b"impersonation attempt",
        })
        .unwrap();
        let (header, ciphertext) = state.ratchet_encrypt(&sealed, &associated_data).unwrap();
        let envelope = test_handshake_envelope(
            &setup,
            &initiator_ephemeral_key,
            responder_signed_prekey_public_key,
            None,
            &header,
            &ciphertext,
        );

        assert!(matches!(
            accept(
                &mut rng,
                &envelope,
                Some(&root_bound_identity_key),
                &setup.bob_identity_key,
                &setup.bob_discovery_key,
                &setup.bob_signed_prekey,
                None,
            ),
            Err(CryptoError::SenderIdentityMismatch)
        ));
    }

    #[test]
    fn envelope_survives_wire_round_trip() {
        let (setup, mut rng) = full_x3dh_setup();
        let plaintext = b"serialize me";
        let bundle = full_prekey_bundle(&setup, true);
        let (_, envelope) = initiate(
            &mut rng,
            &setup.alice_discovery_key,
            &setup.alice_identity_key,
            &setup.bob_identity_key,
            &bundle,
            initial_plaintext(plaintext),
        )
        .unwrap();
        let bytes = envelope.to_bytes().unwrap();

        let decoded_envelope = HandshakeEnvelope::from_bytes(&bytes).unwrap();
        let (_, decrypted) = accept(
            &mut rng,
            &decoded_envelope,
            Some(&setup.alice_identity_key),
            &setup.bob_identity_key,
            &setup.bob_discovery_key,
            &setup.bob_signed_prekey,
            Some(setup.bob_one_time_prekey),
        )
        .unwrap();
        assert_eq!(decrypted.plaintext.as_slice(), plaintext);
    }

    #[test]
    fn envelope_from_bytes_rejects_trailing_bytes() {
        let (setup, mut rng) = full_x3dh_setup();
        let bundle = full_prekey_bundle(&setup, true);
        let (_, envelope) = initiate(
            &mut rng,
            &setup.alice_discovery_key,
            &setup.alice_identity_key,
            &setup.bob_identity_key,
            &bundle,
            initial_plaintext(b"payload"),
        )
        .unwrap();
        let mut bytes = envelope.to_bytes().unwrap();
        bytes.push(0xFF);

        assert!(matches!(
            HandshakeEnvelope::from_bytes(&bytes),
            Err(CryptoError::HandshakeEnvelopeDecode)
        ));
    }

    #[test]
    fn envelope_from_bytes_rejects_malformed_blob() {
        assert!(matches!(
            HandshakeEnvelope::from_bytes(b"not a postcard envelope"),
            Err(CryptoError::HandshakeEnvelopeDecode)
        ));
    }

    #[test]
    fn envelope_from_bytes_rejects_unsupported_version() {
        let bytes = vec![2];

        assert!(matches!(
            HandshakeEnvelope::from_bytes(&bytes),
            Err(CryptoError::HandshakeEnvelopeDecode)
        ));
    }

    #[test]
    fn envelope_to_bytes_rejects_missing_prekey_reference() {
        let (setup, mut rng) = full_x3dh_setup();
        let bundle = full_prekey_bundle(&setup, true);
        let (_, mut envelope) = initiate(
            &mut rng,
            &setup.alice_discovery_key,
            &setup.alice_identity_key,
            &setup.bob_identity_key,
            &bundle,
            initial_plaintext(b"payload"),
        )
        .unwrap();
        envelope.prekey_reference = None;

        assert!(matches!(
            envelope.to_bytes(),
            Err(CryptoError::HandshakeEnvelopeEncode)
        ));
    }

    #[test]
    fn envelope_from_bytes_rejects_old_sender_visible_layout() {
        #[derive(Serialize)]
        struct SenderVisibleHandshakeEnvelopeWire {
            initiator_discovery_public_key: [u8; 32],
            initiator_ephemeral_public_key: [u8; 32],
            responder_discovery_epoch: u32,
            responder_signed_prekey_public_key: [u8; 32],
            one_time_prekey_id: Option<u64>,
            one_time_prekey_public_key: Option<[u8; 32]>,
            ratchet_public_key: [u8; 32],
            previous_chain_length: u32,
            message_number: u32,
            ciphertext: Vec<u8>,
        }

        let mut initiator_discovery_public_key = [0x42; 32];
        initiator_discovery_public_key[0] = HANDSHAKE_ENVELOPE_VERSION;
        let bytes = postcard::to_stdvec(&SenderVisibleHandshakeEnvelopeWire {
            initiator_discovery_public_key,
            initiator_ephemeral_public_key: [0x11; 32],
            responder_discovery_epoch: 1,
            responder_signed_prekey_public_key: [0x22; 32],
            one_time_prekey_id: None,
            one_time_prekey_public_key: None,
            ratchet_public_key: [0x33; 32],
            previous_chain_length: 0,
            message_number: 0,
            ciphertext: vec![0x44; 16],
        })
        .unwrap();

        assert!(matches!(
            HandshakeEnvelope::from_bytes(&bytes),
            Err(CryptoError::HandshakeEnvelopeDecode)
        ));
    }

    #[test]
    fn envelope_from_bytes_rejects_oversized_blob() {
        let bytes = vec![0u8; MAX_HANDSHAKE_ENVELOPE_LEN + 1];

        assert!(matches!(
            HandshakeEnvelope::from_bytes(&bytes),
            Err(CryptoError::HandshakeEnvelopeDecode)
        ));
    }

    #[test]
    fn envelope_wire_api_rejects_oversized_ciphertext() {
        let (setup, mut rng) = full_x3dh_setup();
        let bundle = full_prekey_bundle(&setup, true);
        let (_, mut envelope) = initiate(
            &mut rng,
            &setup.alice_discovery_key,
            &setup.alice_identity_key,
            &setup.bob_identity_key,
            &bundle,
            initial_plaintext(b"payload"),
        )
        .unwrap();
        envelope.ciphertext = vec![0u8; MAX_HANDSHAKE_CIPHERTEXT_LEN + 1];

        assert!(matches!(
            envelope.to_bytes(),
            Err(CryptoError::HandshakeEnvelopeEncode)
        ));

        let bytes = envelope.to_frame().to_bytes().unwrap();
        assert!(bytes.len() <= MAX_HANDSHAKE_ENVELOPE_LEN);
        assert!(matches!(
            HandshakeEnvelope::from_bytes(&bytes),
            Err(CryptoError::HandshakeEnvelopeDecode)
        ));
    }
}
