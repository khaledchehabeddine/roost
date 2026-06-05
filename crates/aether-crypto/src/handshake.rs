//! Implements the X3DH handshake that bootstraps Double Ratchet sessions.

use crate::discovery_key::{DiscoveryKey, DiscoveryKeyBundle, verify_discovery_key_bundle};
use crate::double_ratchet::{Header, RatchetState};
use crate::error::CryptoError;
use crate::keys::{KeyPair, PublicKey, SharedSecret, VerifyingKey, generate_key_pair};
use crate::one_time_prekey::{OneTimePreKey, OneTimePreKeyBundle};
use crate::ratchet::RootKey;
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
const INPUT_KEYING_MATERIAL_LEN_WITHOUT_ONE_TIME_PREKEY: usize = 32 * 3;
const INPUT_KEYING_MATERIAL_LEN_WITH_ONE_TIME_PREKEY: usize = 32 * 4;
const HANDSHAKE_ENVELOPE_MAGIC: [u8; 4] = *b"AX3H";
const HANDSHAKE_ENVELOPE_VERSION: u8 = 1;
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
    /// Responder discovery key verified by the responder's identity key.
    pub discovery_key: DiscoveryKeyBundle,
    /// Responder signed pre-key verified by the discovery key.
    pub signed_prekey: SignedPreKeyBundle,
    /// Optional one-time pre-key bound to the same discovery-key epoch.
    pub one_time_prekey: Option<OneTimePreKeyBundle>,
}

/// Sender identity material decoded only after first-message ciphertext authentication succeeds.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SenderIdentityMaterial {
    /// Sender identity key bytes for the current Discovery Key epoch. Always 32 bytes.
    #[zeroize(skip)]
    pub identity_key: [u8; 32],
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
///
/// Holds public handshake material, the first ratchet header fields, and the first ciphertext.
#[derive(Clone, Debug)]
pub struct HandshakeEnvelope {
    /// Initiator's X25519 ephemeral public key (fresh per handshake).
    pub initiator_ephemeral_public_key: [u8; 32],
    /// Responder discovery-key epoch the initiator targeted.
    pub responder_discovery_epoch: u32,
    /// X25519 public key of the responder's signed pre-key the initiator targeted.
    pub responder_signed_prekey_public_key: [u8; 32],
    /// Identifier of the responder one-time pre-key the initiator targeted, when present.
    pub one_time_prekey_id: Option<u64>,
    /// X25519 public key of the responder one-time pre-key the initiator targeted, when present.
    pub one_time_prekey_public_key: Option<[u8; 32]>,
    /// Ratchet public key for the first message.
    pub ratchet_public_key: [u8; 32],
    /// Number of messages sent in the previous chain.
    pub previous_chain_length: u32,
    /// Sequence number of this message in the current chain.
    pub message_number: u32,
    /// Ciphertext for the first handshake message.
    pub ciphertext: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
struct HandshakeEnvelopeWire {
    magic: [u8; 4],
    version: u8,
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

impl HandshakeEnvelope {
    /// Serializes this handshake envelope for transport.
    ///
    /// # Errors
    /// - [`CryptoError::HandshakeEnvelopeEncode`] when postcard rejects the envelope wire form.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        if self.ciphertext.len() > MAX_HANDSHAKE_CIPHERTEXT_LEN {
            return Err(CryptoError::HandshakeEnvelopeEncode);
        }

        let bytes = postcard::to_stdvec(&HandshakeEnvelopeWire {
            magic: HANDSHAKE_ENVELOPE_MAGIC,
            version: HANDSHAKE_ENVELOPE_VERSION,
            initiator_ephemeral_public_key: self.initiator_ephemeral_public_key,
            responder_discovery_epoch: self.responder_discovery_epoch,
            responder_signed_prekey_public_key: self.responder_signed_prekey_public_key,
            one_time_prekey_id: self.one_time_prekey_id,
            one_time_prekey_public_key: self.one_time_prekey_public_key,
            ratchet_public_key: self.ratchet_public_key,
            previous_chain_length: self.previous_chain_length,
            message_number: self.message_number,
            ciphertext: self.ciphertext.clone(),
        })
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
        let magic = bytes
            .get(..HANDSHAKE_ENVELOPE_MAGIC.len())
            .ok_or(CryptoError::HandshakeEnvelopeDecode)?;
        let version = *bytes
            .get(HANDSHAKE_ENVELOPE_MAGIC.len())
            .ok_or(CryptoError::HandshakeEnvelopeDecode)?;
        if magic != HANDSHAKE_ENVELOPE_MAGIC || version != HANDSHAKE_ENVELOPE_VERSION {
            return Err(CryptoError::HandshakeEnvelopeDecode);
        }
        if bytes.len() > MAX_HANDSHAKE_ENVELOPE_LEN {
            return Err(CryptoError::HandshakeEnvelopeDecode);
        }

        let (wire, trailing): (HandshakeEnvelopeWire, &[u8]) =
            postcard::take_from_bytes(bytes).map_err(|_| CryptoError::HandshakeEnvelopeDecode)?;
        if wire.magic != HANDSHAKE_ENVELOPE_MAGIC
            || wire.version != HANDSHAKE_ENVELOPE_VERSION
            || !trailing.is_empty()
            || wire.ciphertext.len() > MAX_HANDSHAKE_CIPHERTEXT_LEN
        {
            return Err(CryptoError::HandshakeEnvelopeDecode);
        }

        Ok(Self {
            initiator_ephemeral_public_key: wire.initiator_ephemeral_public_key,
            responder_discovery_epoch: wire.responder_discovery_epoch,
            responder_signed_prekey_public_key: wire.responder_signed_prekey_public_key,
            one_time_prekey_id: wire.one_time_prekey_id,
            one_time_prekey_public_key: wire.one_time_prekey_public_key,
            ratchet_public_key: wire.ratchet_public_key,
            previous_chain_length: wire.previous_chain_length,
            message_number: wire.message_number,
            ciphertext: wire.ciphertext,
        })
    }
}

/// Starts a handshake as the initiator and encrypts the first message.
///
/// The initiator's ephemeral key and first ratchet key are drawn from `rng`.
///
/// Pass the responder's permanent identity verifying key as `responder_identity_verifying_key`.
/// It verifies the discovery key in `responder_prekey_bundle`.
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
pub fn initiate<R: RngCore + CryptoRng>(
    rng: &mut R,
    initiator_discovery_key: &DiscoveryKey,
    responder_identity_verifying_key: &VerifyingKey,
    responder_prekey_bundle: &PreKeyBundle,
    message: InitialPlaintext<'_>,
) -> Result<(RatchetState, HandshakeEnvelope), CryptoError> {
    verify_discovery_key_bundle(
        &responder_prekey_bundle.discovery_key,
        responder_identity_verifying_key,
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
    let sender_identity_key = *initiator_discovery_key.public_key().as_bytes();
    let sender_proof_placeholder = [0u8; SENDER_PROOF_LEN];
    validate_sender_material_lengths(
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
        sender_certificate: message.sender_certificate,
        sender_signature: message.sender_signature,
        initiator_ephemeral_public_key: &initiator_ephemeral_key.public,
        responder_discovery_public_key: &responder_prekey_bundle.discovery_key.public_key,
        responder_discovery_epoch: responder_prekey_bundle.discovery_key.epoch,
        responder_signed_prekey_public_key: &responder_signed_prekey_public_key,
        responder_one_time_prekey: responder_prekey_bundle.one_time_prekey.as_ref(),
    });
    let sender_proof = derive_sender_proof(&sender_proof_secret, &sender_proof_transcript)?;
    let sealed = encode_sealed_sender_envelope(
        sender_identity_key,
        message.sender_certificate,
        message.sender_signature,
        sender_proof.as_ref(),
        message.plaintext,
    )?;
    let (header, ciphertext) = state.ratchet_encrypt(&sealed, &associated_data)?;

    let envelope = HandshakeEnvelope {
        initiator_ephemeral_public_key: *initiator_ephemeral_key.public.as_bytes(),
        responder_discovery_epoch: responder_prekey_bundle.discovery_key.epoch,
        responder_signed_prekey_public_key: *responder_signed_prekey_public_key.as_bytes(),
        one_time_prekey_id: responder_prekey_bundle
            .one_time_prekey
            .as_ref()
            .map(|prekey| prekey.id),
        one_time_prekey_public_key: responder_prekey_bundle
            .one_time_prekey
            .as_ref()
            .map(|prekey| *prekey.public_key.as_bytes()),
        ratchet_public_key: *header.public_key.as_bytes(),
        previous_chain_length: header.previous_chain_length,
        message_number: header.message_number,
        ciphertext,
    };
    envelope.to_bytes()?;

    Ok((state, envelope))
}

/// Accepts a handshake envelope and decrypts the first message.
///
/// The responder's first ratchet key is drawn from `rng` during the initial DH ratchet step.
///
/// `responder_discovery_key` is the local responder's current X25519 discovery key.
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
/// - [`CryptoError::HandshakeSignedPreKeyMismatch`] when
///   `envelope.responder_signed_prekey_public_key` does not match
///   `responder_signed_prekey.public()`.
/// - [`CryptoError::HkdfExpand`] when the HKDF run for root-key derivation fails.
/// - [`CryptoError::InvalidState`] when ratchet decryption observes an invalid receiving state.
/// - [`CryptoError::MissingOneTimePreKey`] when the envelope names a one-time pre-key but the
///   caller supplies none.
/// - [`CryptoError::NonContributorySharedSecret`] when an X25519 peer key produces a
///   non-contributory shared secret.
/// - [`CryptoError::OneTimePreKeyMismatch`] when the supplied one-time pre-key does not match the
///   envelope reference.
/// - [`CryptoError::SignatureInvalid`] when the sealed sender key-possession proof does not
///   validate.
/// - [`CryptoError::StalePreKey`] when the envelope or local pre-keys do not match the discovery
///   key epoch.
pub fn accept<R: RngCore + CryptoRng>(
    rng: &mut R,
    envelope: &HandshakeEnvelope,
    responder_discovery_key: &DiscoveryKey,
    responder_signed_prekey: &SignedPreKey,
    responder_one_time_prekey: Option<OneTimePreKey>,
) -> Result<(RatchetState, AcceptedInitialMessage), CryptoError> {
    if envelope.responder_discovery_epoch != responder_discovery_key.epoch()
        || responder_signed_prekey.epoch() != responder_discovery_key.epoch()
    {
        return Err(CryptoError::StalePreKey);
    }
    if envelope.ciphertext.len() > MAX_HANDSHAKE_CIPHERTEXT_LEN {
        return Err(CryptoError::HandshakeEnvelopeDecode);
    }
    let signed_prekey_matches: bool = envelope
        .responder_signed_prekey_public_key
        .ct_eq(responder_signed_prekey.public().as_bytes())
        .into();
    if !signed_prekey_matches {
        return Err(CryptoError::HandshakeSignedPreKeyMismatch);
    }

    let responder_one_time_prekey =
        validate_envelope_one_time_prekey(envelope, responder_one_time_prekey)?;

    let initiator_ephemeral_public_key = PublicKey::from(envelope.initiator_ephemeral_public_key);

    let root_key = derive_root_key_responder(
        &initiator_ephemeral_public_key,
        responder_discovery_key,
        responder_signed_prekey,
        responder_one_time_prekey.as_ref(),
    )?;
    let signed_prekey_key_pair =
        KeyPair::from_secret_bytes(*responder_signed_prekey.to_secret_bytes());
    let mut state = RatchetState::init_responder(root_key, signed_prekey_key_pair);

    let header = Header {
        public_key: PublicKey::from(envelope.ratchet_public_key),
        previous_chain_length: envelope.previous_chain_length,
        message_number: envelope.message_number,
    };
    let associated_data = initial_associated_data(
        responder_discovery_key.public_key(),
        responder_discovery_key.epoch(),
    );
    let sealed = state.ratchet_decrypt(rng, &envelope.ciphertext, &header, &associated_data)?;
    let decoded = decode_sealed_sender_envelope(&sealed)?;
    verify_sender_proof(
        envelope,
        responder_discovery_key.public_key(),
        responder_signed_prekey,
        &decoded.message.sender_identity,
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
    match (
        envelope.one_time_prekey_id,
        envelope.one_time_prekey_public_key,
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
            if prekey.epoch() != envelope.responder_discovery_epoch {
                return Err(CryptoError::StalePreKey);
            }
            Ok(Some(prekey))
        }
    }
}

// Derives the initiator-side root key from sender-anonymous X3DH Diffie-Hellman outputs:
// DH2 = EK_A * DK_B, DH3 = EK_A * SPK_B, DH4 = EK_A * OPK_B.
pub(crate) fn derive_root_key_initiator(
    initiator_ephemeral_key: &KeyPair,
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
    derive_root_key_from_dh_outputs(&dh2, &dh3, dh4.as_ref())
}

// Derives the responder-side root key from sender-anonymous X3DH Diffie-Hellman outputs:
// DH2 = DK_B * EK_A, DH3 = SPK_B * EK_A, DH4 = OPK_B * EK_A.
pub(crate) fn derive_root_key_responder(
    initiator_ephemeral_public_key: &PublicKey,
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
    derive_root_key_from_dh_outputs(&dh2, &dh3, dh4.as_ref())
}

fn checked_shared_secret(secret: SharedSecret) -> Result<SharedSecret, CryptoError> {
    if !secret.was_contributory() {
        return Err(CryptoError::NonContributorySharedSecret);
    }
    Ok(secret)
}

// Concatenates F_PREFIX || sender-anonymous DH outputs and runs HKDF-SHA256 once.
fn derive_root_key_from_dh_outputs(
    dh2: &SharedSecret,
    dh3: &SharedSecret,
    dh4: Option<&SharedSecret>,
) -> Result<RootKey, CryptoError> {
    let capacity = if dh4.is_some() {
        INPUT_KEYING_MATERIAL_LEN_WITH_ONE_TIME_PREKEY
    } else {
        INPUT_KEYING_MATERIAL_LEN_WITHOUT_ONE_TIME_PREKEY
    };
    let mut input_keying_material: Zeroizing<Vec<u8>> =
        Zeroizing::new(Vec::with_capacity(capacity));
    input_keying_material.extend_from_slice(&F_PREFIX);
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
) -> Zeroizing<Vec<u8>> {
    let one_time_prekey = envelope
        .one_time_prekey_id
        .zip(envelope.one_time_prekey_public_key)
        .map(|(id, public_key)| OneTimePreKeyBundle {
            id,
            public_key: PublicKey::from(public_key),
            epoch: envelope.responder_discovery_epoch,
            created_at: 0,
        });
    let initiator_ephemeral_public_key = PublicKey::from(envelope.initiator_ephemeral_public_key);
    let responder_signed_prekey_public_key =
        PublicKey::from(envelope.responder_signed_prekey_public_key);
    sender_proof_transcript(SenderProofTranscriptInput {
        sender_identity_key: &sender_identity.identity_key,
        sender_certificate: &sender_identity.certificate,
        sender_signature: &sender_identity.signature,
        initiator_ephemeral_public_key: &initiator_ephemeral_public_key,
        responder_discovery_public_key,
        responder_discovery_epoch: envelope.responder_discovery_epoch,
        responder_signed_prekey_public_key: &responder_signed_prekey_public_key,
        responder_one_time_prekey: one_time_prekey.as_ref(),
    })
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
    actual_proof: &[u8],
) -> Result<(), CryptoError> {
    if actual_proof.len() != SENDER_PROOF_LEN {
        return Err(CryptoError::HandshakeEnvelopeDecode);
    }
    let sender_identity_key = PublicKey::from(sender_identity.identity_key);
    let sender_proof_secret =
        checked_shared_secret(responder_signed_prekey.diffie_hellman(&sender_identity_key))?;
    let transcript =
        envelope_sender_proof_transcript(envelope, responder_discovery_public_key, sender_identity);
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
    sender_certificate: &'a [u8],
    sender_signature: &'a [u8],
    sender_proof: &'a [u8],
    plaintext: &'a [u8],
}

#[derive(Deserialize)]
struct DecodedSealedSenderEnvelopeWire {
    version: u8,
    sender_identity_key: [u8; 32],
    sender_certificate: Vec<u8>,
    sender_signature: Vec<u8>,
    sender_proof: Vec<u8>,
    plaintext: Vec<u8>,
}

struct DecodedSealedSenderEnvelope {
    message: AcceptedInitialMessage,
    sender_proof: Zeroizing<Vec<u8>>,
}

fn encode_sealed_sender_envelope(
    sender_identity_key: [u8; 32],
    sender_certificate: &[u8],
    sender_signature: &[u8],
    sender_proof: &[u8],
    plaintext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if sender_proof.len() != SENDER_PROOF_LEN {
        return Err(CryptoError::HandshakeEnvelopeEncode);
    }
    validate_sender_material_lengths(
        sender_certificate,
        sender_signature,
        sender_proof,
        plaintext,
        CryptoError::HandshakeEnvelopeEncode,
    )?;
    let sealed = Zeroizing::new(
        postcard::to_stdvec(&SealedSenderEnvelopeWire {
            version: SEALED_SENDER_ENVELOPE_VERSION,
            sender_identity_key,
            sender_certificate,
            sender_signature,
            sender_proof,
            plaintext,
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
        certificate: wire.sender_certificate,
        signature: wire.sender_signature,
    };
    if !trailing.is_empty() || wire.version != SEALED_SENDER_ENVELOPE_VERSION {
        return Err(CryptoError::HandshakeEnvelopeDecode);
    }
    if sender_proof.len() != SENDER_PROOF_LEN {
        return Err(CryptoError::HandshakeEnvelopeDecode);
    }
    validate_sender_identity(&sender_identity)?;
    validate_sender_material_lengths(
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
        sender_proof,
    })
}

fn validate_sender_identity(sender_identity: &SenderIdentityMaterial) -> Result<(), CryptoError> {
    validate_sender_material_lengths(
        &sender_identity.certificate,
        &sender_identity.signature,
        &[],
        &[],
        CryptoError::HandshakeEnvelopeDecode,
    )
}

fn validate_sender_material_lengths(
    certificate: &[u8],
    signature: &[u8],
    proof: &[u8],
    plaintext: &[u8],
    error: CryptoError,
) -> Result<(), CryptoError> {
    let content_len = certificate
        .len()
        .checked_add(signature.len())
        .and_then(|len| len.checked_add(proof.len()))
        .and_then(|len| len.checked_add(plaintext.len()));
    if certificate.len() > MAX_SENDER_CERTIFICATE_LEN
        || signature.len() > MAX_SENDER_SIGNATURE_LEN
        || content_len.is_none_or(|len| len > MAX_HANDSHAKE_SEALED_SENDER_CONTENT_LEN)
    {
        return Err(error);
    }
    Ok(())
}

// Derives the 32-byte ratchet root key from F_PREFIX || sender-anonymous X3DH DH outputs.
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
    use crate::keys::{KeyPair, SigningKeyPair, generate_key_pair, generate_signing_key_pair};
    use crate::one_time_prekey::{OneTimePreKey, generate_one_time_prekey};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    const FIXED_TS: u64 = 1_700_000_000;

    struct FullX3dhSetup {
        alice_discovery_key: DiscoveryKey,
        bob_identity: SigningKeyPair,
        bob_discovery_key: DiscoveryKey,
        bob_signed_prekey: SignedPreKey,
        bob_one_time_prekey: OneTimePreKey,
    }

    fn full_x3dh_setup() -> (FullX3dhSetup, ChaCha20Rng) {
        let mut rng = ChaCha20Rng::from_seed([0x42u8; 32]);
        let alice_identity = generate_signing_key_pair(&mut rng);
        let alice_discovery_key = generate_discovery_key(&mut rng, &alice_identity, 2, FIXED_TS);
        let bob_identity = generate_signing_key_pair(&mut rng);
        let bob_discovery_key = generate_discovery_key(&mut rng, &bob_identity, 3, FIXED_TS);
        let bob_signed_prekey =
            generate_signed_prekey_for_discovery_key(&mut rng, &bob_discovery_key, FIXED_TS);
        let bob_one_time_prekey =
            generate_one_time_prekey(&mut rng, 9, bob_discovery_key.epoch(), FIXED_TS);
        let setup = FullX3dhSetup {
            alice_discovery_key,
            bob_identity,
            bob_discovery_key,
            bob_signed_prekey,
            bob_one_time_prekey,
        };
        (setup, rng)
    }

    fn full_prekey_bundle(setup: &FullX3dhSetup, include_one_time: bool) -> PreKeyBundle {
        PreKeyBundle {
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
    /// Output: `HKDF(F_PREFIX || DH2 || DH3 || DH4, HKDF_INFO_WITH_ONE_TIME_PREKEY)`.
    #[test]
    fn full_x3dh_root_key_known_answer() {
        const EXPECTED_ROOT_KEY: [u8; 32] = [
            224, 68, 187, 200, 252, 68, 85, 129, 217, 17, 0, 81, 177, 53, 151, 109, 85, 234, 81,
            58, 130, 15, 204, 186, 124, 200, 217, 188, 74, 187, 185, 34,
        ];

        let alice_ephemeral_key = KeyPair::from_secret_bytes([0x22u8; 32]);
        let bob_discovery_key =
            DiscoveryKey::from_secret_bytes([0x31u8; 32], [0x72u8; 32], 3, FIXED_TS, [0u8; 64]);
        let bob_signed_prekey =
            SignedPreKey::from_secret_bytes([0x41u8; 32], [0u8; 64], 3, FIXED_TS);
        let bob_one_time_prekey = OneTimePreKey::from_secret_bytes(9, [0x51u8; 32], 3, FIXED_TS);

        let initiator_root_key = derive_root_key_initiator(
            &alice_ephemeral_key,
            bob_discovery_key.public_key(),
            bob_signed_prekey.public(),
            Some(bob_one_time_prekey.public()),
        )
        .unwrap();
        let responder_root_key = derive_root_key_responder(
            &alice_ephemeral_key.public,
            &bob_discovery_key,
            &bob_signed_prekey,
            Some(&bob_one_time_prekey),
        )
        .unwrap();

        assert_eq!(initiator_root_key.as_bytes(), responder_root_key.as_bytes());
        assert_eq!(initiator_root_key.as_bytes(), &EXPECTED_ROOT_KEY);
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
            &setup.bob_identity.verifying,
            &bundle,
            initial_plaintext(plaintext),
        )
        .unwrap();
        assert_eq!(
            envelope.one_time_prekey_id,
            Some(setup.bob_one_time_prekey.id())
        );
        let (_, decrypted) = accept(
            &mut rng,
            &envelope,
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
            &setup.bob_identity.verifying,
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
            &setup.bob_identity.verifying,
            &bundle,
            initial_plaintext(b"hello sealed identity"),
        )
        .unwrap();
        let (_, decrypted) = accept(
            &mut rng,
            &envelope,
            &setup.bob_discovery_key,
            &setup.bob_signed_prekey,
            Some(setup.bob_one_time_prekey),
        )
        .unwrap();

        assert_eq!(decrypted.plaintext.as_slice(), plaintext);
        assert_eq!(
            decrypted.sender_identity.identity_key,
            *setup.alice_discovery_key.public_key().as_bytes()
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
            &setup.bob_identity.verifying,
            &bundle,
            initial_plaintext(plaintext),
        )
        .unwrap();
        assert_eq!(envelope.one_time_prekey_id, None);
        let (_, decrypted) = accept(
            &mut rng,
            &envelope,
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
            &setup.bob_identity.verifying,
            &bundle,
            initial_plaintext(b"payload"),
        )
        .unwrap();
        assert!(matches!(
            accept(
                &mut rng,
                &envelope,
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
            &setup.bob_identity.verifying,
            &bundle,
            initial_plaintext(b"payload"),
        )
        .unwrap();
        assert!(matches!(
            accept(
                &mut rng,
                &envelope,
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
            discovery_key: setup.bob_discovery_key.bundle(),
            signed_prekey: setup.bob_signed_prekey.bundle(),
            one_time_prekey: Some(stale_one_time_prekey.bundle()),
        };
        assert!(matches!(
            initiate(
                &mut rng,
                &setup.alice_discovery_key,
                &setup.bob_identity.verifying,
                &bundle,
                initial_plaintext(b"payload"),
            ),
            Err(CryptoError::StalePreKey)
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
            &setup.bob_identity.verifying,
            &bundle,
            initial_plaintext(&oversized_plaintext),
        );

        assert!(matches!(result, Err(CryptoError::HandshakeEnvelopeEncode)));
    }

    #[test]
    fn initiator_and_responder_derive_identical_root_key() {
        let (setup, mut rng) = full_x3dh_setup();
        let alice_ephemeral_key = generate_key_pair(&mut rng);
        let initiator_root_key = derive_root_key_initiator(
            &alice_ephemeral_key,
            setup.bob_discovery_key.public_key(),
            setup.bob_signed_prekey.public(),
            Some(setup.bob_one_time_prekey.public()),
        )
        .unwrap();
        let responder_root_key = derive_root_key_responder(
            &alice_ephemeral_key.public,
            &setup.bob_discovery_key,
            &setup.bob_signed_prekey,
            Some(&setup.bob_one_time_prekey),
        )
        .unwrap();
        assert_eq!(initiator_root_key.as_bytes(), responder_root_key.as_bytes());
    }

    #[test]
    fn root_derivation_rejects_non_contributory_peer_key() {
        let (setup, _) = full_x3dh_setup();
        let low_order_public_key = PublicKey::from([0u8; 32]);

        assert!(matches!(
            derive_root_key_responder(
                &low_order_public_key,
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
        let bundle = full_prekey_bundle(&setup, true);
        let result = initiate(
            &mut rng,
            &setup.alice_discovery_key,
            &wrong_signing_key.verifying,
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
            &setup.bob_identity.verifying,
            &bundle,
            initial_plaintext(b"payload"),
        )
        .unwrap();
        envelope.responder_signed_prekey_public_key[0] ^= 0x01;
        assert!(matches!(
            accept(
                &mut rng,
                &envelope,
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
            &setup.bob_identity.verifying,
            &bundle,
            initial_plaintext(b"tamper me"),
        )
        .unwrap();
        envelope.ciphertext[0] ^= 0xFF;
        assert!(matches!(
            accept(
                &mut rng,
                &envelope,
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
        let envelope = HandshakeEnvelope {
            initiator_ephemeral_public_key: *initiator_ephemeral_key.public.as_bytes(),
            responder_discovery_epoch: setup.bob_discovery_key.epoch(),
            responder_signed_prekey_public_key: *responder_signed_prekey_public_key.as_bytes(),
            one_time_prekey_id: None,
            one_time_prekey_public_key: None,
            ratchet_public_key: *header.public_key.as_bytes(),
            previous_chain_length: header.previous_chain_length,
            message_number: header.message_number,
            ciphertext,
        };

        assert!(matches!(
            accept(
                &mut rng,
                &envelope,
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
            sender_identity_key: *setup.alice_discovery_key.public_key().as_bytes(),
            sender_certificate: b"sender certificate",
            sender_signature: b"sender signature",
            sender_proof: &bogus_sender_proof,
            plaintext: b"payload",
        })
        .unwrap();
        let (header, ciphertext) = state.ratchet_encrypt(&sealed, &associated_data).unwrap();
        let envelope = HandshakeEnvelope {
            initiator_ephemeral_public_key: *initiator_ephemeral_key.public.as_bytes(),
            responder_discovery_epoch: setup.bob_discovery_key.epoch(),
            responder_signed_prekey_public_key: *responder_signed_prekey_public_key.as_bytes(),
            one_time_prekey_id: None,
            one_time_prekey_public_key: None,
            ratchet_public_key: *header.public_key.as_bytes(),
            previous_chain_length: header.previous_chain_length,
            message_number: header.message_number,
            ciphertext,
        };

        assert!(matches!(
            accept(
                &mut rng,
                &envelope,
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
            sender_certificate: b"sender certificate",
            sender_signature: b"sender signature",
            sender_proof: &bogus_sender_proof,
            plaintext: b"payload",
        })
        .unwrap();
        let (header, ciphertext) = state.ratchet_encrypt(&sealed, &associated_data).unwrap();
        let envelope = HandshakeEnvelope {
            initiator_ephemeral_public_key: *initiator_ephemeral_key.public.as_bytes(),
            responder_discovery_epoch: setup.bob_discovery_key.epoch(),
            responder_signed_prekey_public_key: *responder_signed_prekey_public_key.as_bytes(),
            one_time_prekey_id: None,
            one_time_prekey_public_key: None,
            ratchet_public_key: *header.public_key.as_bytes(),
            previous_chain_length: header.previous_chain_length,
            message_number: header.message_number,
            ciphertext,
        };

        assert!(matches!(
            accept(
                &mut rng,
                &envelope,
                &setup.bob_discovery_key,
                &setup.bob_signed_prekey,
                None,
            ),
            Err(CryptoError::NonContributorySharedSecret)
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
            &setup.bob_identity.verifying,
            &bundle,
            initial_plaintext(plaintext),
        )
        .unwrap();
        let bytes = envelope.to_bytes().unwrap();

        let decoded_envelope = HandshakeEnvelope::from_bytes(&bytes).unwrap();
        let (_, decrypted) = accept(
            &mut rng,
            &decoded_envelope,
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
            &setup.bob_identity.verifying,
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
        let mut bytes = HANDSHAKE_ENVELOPE_MAGIC.to_vec();
        bytes.push(2);

        assert!(matches!(
            HandshakeEnvelope::from_bytes(&bytes),
            Err(CryptoError::HandshakeEnvelopeDecode)
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
            &setup.bob_identity.verifying,
            &bundle,
            initial_plaintext(b"payload"),
        )
        .unwrap();
        envelope.ciphertext = vec![0u8; MAX_HANDSHAKE_CIPHERTEXT_LEN + 1];

        assert!(matches!(
            envelope.to_bytes(),
            Err(CryptoError::HandshakeEnvelopeEncode)
        ));

        let bytes = postcard::to_stdvec(&HandshakeEnvelopeWire {
            magic: HANDSHAKE_ENVELOPE_MAGIC,
            version: HANDSHAKE_ENVELOPE_VERSION,
            initiator_ephemeral_public_key: envelope.initiator_ephemeral_public_key,
            responder_discovery_epoch: envelope.responder_discovery_epoch,
            responder_signed_prekey_public_key: envelope.responder_signed_prekey_public_key,
            one_time_prekey_id: envelope.one_time_prekey_id,
            one_time_prekey_public_key: envelope.one_time_prekey_public_key,
            ratchet_public_key: envelope.ratchet_public_key,
            previous_chain_length: envelope.previous_chain_length,
            message_number: envelope.message_number,
            ciphertext: envelope.ciphertext,
        })
        .unwrap();
        assert!(bytes.len() <= MAX_HANDSHAKE_ENVELOPE_LEN);
        assert!(matches!(
            HandshakeEnvelope::from_bytes(&bytes),
            Err(CryptoError::HandshakeEnvelopeDecode)
        ));
    }
}
