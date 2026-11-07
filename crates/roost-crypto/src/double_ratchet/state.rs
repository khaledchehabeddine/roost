use super::aead::{decrypt, encrypt};
use super::header::Header;
use super::kdf::{
    ChainKey, MessageKey, RootKey, derive_chain_and_message_keys, derive_root_and_chain_keys,
};
use crate::keys::{KeyPair, PublicKey, generate_key_pair};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

// Limits how many message keys one header can force this session to derive.
const MAX_SKIP: u32 = 100;
// Caps all cached skipped-message keys, so repeated DH steps cannot exhaust memory.
const MAX_SKIPPED_KEYS_TOTAL: usize = 500;

/// A Double Ratchet session state between two peers.
///
/// Implements the state variables of the
/// [Double Ratchet specification](https://signal.org/docs/specifications/doubleratchet/). Field
/// comments name each variable as the specification writes it.
///
/// After each successful encrypt or decrypt, callers that persist session states must replace the
/// old stored blob with a new one from [`Self::to_bytes`].
pub struct RatchetState {
    // Sending ratchet key pair (`DHs`).
    sending_ratchet_key_pair: KeyPair,
    // Receiving ratchet public key (`DHr`). `None` until the first message arrives.
    receiving_ratchet_public_key: Option<PublicKey>,
    // Root key (`RK`). Evolves with each DH ratchet step.
    root_key: RootKey,
    // Sending chain key (`CKs`). `None` before the responder receives the first message.
    sending_chain_key: Option<ChainKey>,
    // Receiving chain key (`CKr`). `None` until the first message is received.
    receiving_chain_key: Option<ChainKey>,
    // Number of messages sent in the current sending chain (`Ns`).
    sending_message_number: u32,
    // Number of messages received in the current receiving chain (`Nr`).
    receiving_message_number: u32,
    // Number of messages sent in the previous sending chain (`PN`).
    previous_chain_length: u32,
    // Cached keys for out-of-order messages (`MKSKIPPED`), keyed by sender public key bytes and
    // message number.
    // `BTreeMap` keeps lookup and serialized snapshots deterministic.
    skipped_message_keys: BTreeMap<([u8; 32], u32), MessageKey>,
}

#[derive(Serialize)]
struct RatchetStateWire<'a> {
    sending_ratchet_secret_key: &'a [u8; 32],
    receiving_ratchet_public_key: Option<[u8; 32]>,
    root_key: &'a [u8; 32],
    sending_chain_key: Option<&'a [u8; 32]>,
    receiving_chain_key: Option<&'a [u8; 32]>,
    sending_message_number: u32,
    receiving_message_number: u32,
    previous_chain_length: u32,
    skipped_message_keys: BTreeMap<([u8; 32], u32), &'a [u8; 32]>,
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(Serialize))]
struct DecodedRatchetStateWire {
    sending_ratchet_secret_key: Zeroizing<[u8; 32]>,
    receiving_ratchet_public_key: Option<[u8; 32]>,
    root_key: Zeroizing<[u8; 32]>,
    sending_chain_key: Option<Zeroizing<[u8; 32]>>,
    receiving_chain_key: Option<Zeroizing<[u8; 32]>>,
    sending_message_number: u32,
    receiving_message_number: u32,
    previous_chain_length: u32,
    skipped_message_keys: BTreeMap<([u8; 32], u32), Zeroizing<[u8; 32]>>,
}

impl RatchetState {
    // Initializes the initiator side with its first sending chain ready.
    pub(crate) fn init_initiator<R: RngCore + CryptoRng>(
        rng: &mut R,
        root_key: RootKey,
        receiving_ratchet_public_key: &PublicKey,
    ) -> Result<Self, RatchetError> {
        let sending_ratchet_key_pair = generate_key_pair(rng);
        let dh_output = sending_ratchet_key_pair
            .diffie_hellman(receiving_ratchet_public_key)
            .ok_or(RatchetError::NonContributorySharedSecret)?;
        let (next_root_key, sending_chain_key) = derive_root_and_chain_keys(&root_key, &dh_output)?;
        Ok(Self {
            sending_ratchet_key_pair,
            receiving_ratchet_public_key: Some(*receiving_ratchet_public_key),
            root_key: next_root_key,
            sending_chain_key: Some(sending_chain_key),
            receiving_chain_key: None,
            sending_message_number: 0,
            receiving_message_number: 0,
            previous_chain_length: 0,
            skipped_message_keys: BTreeMap::new(),
        })
    }

    // Initializes the responder side without chain keys until the first message arrives.
    pub(crate) fn init_responder(root_key: RootKey, sending_ratchet_key_pair: KeyPair) -> Self {
        Self {
            sending_ratchet_key_pair,
            receiving_ratchet_public_key: None,
            root_key,
            sending_chain_key: None,
            receiving_chain_key: None,
            sending_message_number: 0,
            receiving_message_number: 0,
            previous_chain_length: 0,
            skipped_message_keys: BTreeMap::new(),
        }
    }

    /// Encrypts `plaintext`, advances the sending chain, and returns the header and ciphertext.
    ///
    /// The returned [`Header`] must be sent with `ciphertext`. `associated_data` must be the same
    /// byte sequence the receiver passes to [`Self::ratchet_decrypt`].
    ///
    /// A failed call leaves the state unchanged. A responder can encrypt only after decrypting its
    /// first incoming message.
    pub fn ratchet_encrypt(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(Header, Vec<u8>), RatchetError> {
        let sending_chain_key =
            self.sending_chain_key
                .as_ref()
                .ok_or(RatchetError::InvalidState(
                    "sending chain key not initialized",
                ))?;
        let next_sending_message_number =
            self.sending_message_number
                .checked_add(1)
                .ok_or(RatchetError::InvalidState(
                    "sending message number exhausted",
                ))?;
        let (next_sending_chain_key, message_key) =
            derive_chain_and_message_keys(sending_chain_key)?;
        let header = Header {
            public_key: self.sending_ratchet_key_pair.public,
            previous_chain_length: self.previous_chain_length,
            message_number: self.sending_message_number,
        };
        let ciphertext = encrypt(plaintext, associated_data, &header, &message_key)?;

        self.sending_chain_key = Some(next_sending_chain_key);
        self.sending_message_number = next_sending_message_number;
        Ok((header, ciphertext))
    }

    /// Decrypts `ciphertext`, advances the receiving chain, and returns the plaintext.
    ///
    /// `associated_data` must match the value provided at encryption time. If authentication
    /// fails, the session state is restored to its previous value.
    ///
    /// When `header` carries a new ratchet public key, a Diffie-Hellman ratchet step draws a fresh
    /// key pair from `rng`. On authentication failure the session state rolls back, but `rng` has
    /// already advanced.
    ///
    /// Decryption handles three cases in order:
    /// 1. Out-of-order message: looks up a previously skipped key.
    /// 2. New ratchet public key: advances the DH ratchet before decrypting.
    /// 3. Normal in-order message: advances the receiving chain.
    pub fn ratchet_decrypt<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        ciphertext: &[u8],
        header: &Header,
        associated_data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, RatchetError> {
        if let Some(plaintext) =
            self.decrypt_with_skipped_message_key(ciphertext, header, associated_data)?
        {
            return Ok(plaintext);
        }

        let mut state = self.snapshot();
        if Some(header.public_key) != state.receiving_ratchet_public_key {
            state.skip_message_keys(header.previous_chain_length)?;
            state.dh_ratchet_step(rng, header)?;
        }
        state.skip_message_keys(header.message_number)?;
        let receiving_chain_key =
            state
                .receiving_chain_key
                .as_ref()
                .ok_or(RatchetError::InvalidState(
                    "receiving chain key not set after DH ratchet",
                ))?;
        let (next_receiving_chain_key, message_key) =
            derive_chain_and_message_keys(receiving_chain_key)?;
        state.receiving_chain_key = Some(next_receiving_chain_key);
        state.receiving_message_number =
            state
                .receiving_message_number
                .checked_add(1)
                .ok_or(RatchetError::InvalidState(
                    "receiving message number exhausted",
                ))?;

        let plaintext = decrypt(ciphertext, associated_data, header, &message_key)?;
        *self = state;
        Ok(plaintext)
    }

    /// Serializes the session state for persistent storage as an opaque blob.
    ///
    /// Callers must overwrite the previously stored blob rather than append a new entry alongside
    /// it. Forward secrecy depends on stale states being destroyed after every state change.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, RatchetStateError> {
        let sending_ratchet_secret_key = self.sending_ratchet_key_pair.to_secret_bytes();
        let wire = RatchetStateWire {
            sending_ratchet_secret_key: &sending_ratchet_secret_key,
            receiving_ratchet_public_key: self
                .receiving_ratchet_public_key
                .map(|public_key| *public_key.as_bytes()),
            root_key: self.root_key.as_bytes(),
            sending_chain_key: self.sending_chain_key.as_ref().map(ChainKey::as_bytes),
            receiving_chain_key: self.receiving_chain_key.as_ref().map(ChainKey::as_bytes),
            sending_message_number: self.sending_message_number,
            receiving_message_number: self.receiving_message_number,
            previous_chain_length: self.previous_chain_length,
            skipped_message_keys: self
                .skipped_message_keys
                .iter()
                .map(|(key, message_key)| (*key, message_key.as_bytes()))
                .collect(),
        };
        // Sized up front so the encoder writes into zeroizing memory and never grows a buffer that
        // could leave secret copies behind.
        let len = postcard::experimental::serialized_size(&wire)
            .map_err(|_| RatchetStateError::Encode)?;
        let mut bytes = Zeroizing::new(vec![0; len]);
        let written = postcard::to_slice(&wire, &mut bytes)
            .map_err(|_| RatchetStateError::Encode)?
            .len();
        if written != len {
            return Err(RatchetStateError::Encode);
        }
        Ok(bytes)
    }

    /// Restores a session state from a blob produced by [`Self::to_bytes`].
    ///
    /// Persisted blobs are treated as external input, so tampered storage cannot bypass the
    /// skipped-key cache cap.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RatchetStateError> {
        let (wire, rest): (DecodedRatchetStateWire, &[u8]) =
            postcard::take_from_bytes(bytes).map_err(|_| RatchetStateError::Decode)?;
        if !rest.is_empty() {
            return Err(RatchetStateError::TrailingBytes { len: rest.len() });
        }
        let len = wire.skipped_message_keys.len();
        if len > MAX_SKIPPED_KEYS_TOTAL {
            return Err(RatchetStateError::MaxSkippedKeysExceeded {
                len,
                max: MAX_SKIPPED_KEYS_TOTAL,
            });
        }
        Ok(Self {
            sending_ratchet_key_pair: KeyPair::from_secret_bytes(&wire.sending_ratchet_secret_key),
            receiving_ratchet_public_key: wire.receiving_ratchet_public_key.map(PublicKey::from),
            root_key: RootKey::from_bytes(&wire.root_key),
            sending_chain_key: wire.sending_chain_key.as_deref().map(ChainKey::from_bytes),
            receiving_chain_key: wire
                .receiving_chain_key
                .as_deref()
                .map(ChainKey::from_bytes),
            sending_message_number: wire.sending_message_number,
            receiving_message_number: wire.receiving_message_number,
            previous_chain_length: wire.previous_chain_length,
            skipped_message_keys: wire
                .skipped_message_keys
                .iter()
                .map(|(key, message_key)| (*key, MessageKey::from_bytes(message_key)))
                .collect(),
        })
    }

    // Keeps rollback local without exposing `Clone` on a secret-bearing type.
    fn snapshot(&self) -> Self {
        Self {
            sending_ratchet_key_pair: KeyPair::from_secret_bytes(
                &self.sending_ratchet_key_pair.to_secret_bytes(),
            ),
            receiving_ratchet_public_key: self.receiving_ratchet_public_key,
            root_key: self.root_key.clone(),
            sending_chain_key: self.sending_chain_key.clone(),
            receiving_chain_key: self.receiving_chain_key.clone(),
            sending_message_number: self.sending_message_number,
            receiving_message_number: self.receiving_message_number,
            previous_chain_length: self.previous_chain_length,
            skipped_message_keys: self.skipped_message_keys.clone(),
        }
    }

    // Deletes a skipped key only after its message authenticates, so a tampered copy can't burn it.
    fn decrypt_with_skipped_message_key(
        &mut self,
        ciphertext: &[u8],
        header: &Header,
        associated_data: &[u8],
    ) -> Result<Option<Zeroizing<Vec<u8>>>, RatchetError> {
        let key = (*header.public_key.as_bytes(), header.message_number);
        let Some(message_key) = self.skipped_message_keys.get(&key) else {
            return Ok(None);
        };
        let plaintext = decrypt(ciphertext, associated_data, header, message_key)?;
        self.skipped_message_keys.remove(&key);
        Ok(Some(plaintext))
    }

    // Advances the receiving chain and caches skipped message keys up to `until_message_number`.
    fn skip_message_keys(&mut self, until_message_number: u32) -> Result<(), RatchetError> {
        // A duplicate can name a message number behind the receiving chain. Treat it as already
        // processed so the subtraction below can't underflow.
        if until_message_number < self.receiving_message_number {
            return Ok(());
        }
        let count = until_message_number - self.receiving_message_number;
        if count > MAX_SKIP {
            return Err(RatchetError::MaxSkipExceeded {
                count,
                max: MAX_SKIP,
            });
        }

        if let Some(ref receiving_chain_key) = self.receiving_chain_key {
            let receiving_ratchet_public_key =
                self.receiving_ratchet_public_key
                    .ok_or(RatchetError::InvalidState(
                        "receiving ratchet public key not set when skipping message keys",
                    ))?;
            let mut current_chain_key = receiving_chain_key.clone();
            while self.receiving_message_number < until_message_number {
                let (next_chain_key, message_key) =
                    derive_chain_and_message_keys(&current_chain_key)?;
                self.insert_skipped_message_key(
                    (
                        *receiving_ratchet_public_key.as_bytes(),
                        self.receiving_message_number,
                    ),
                    message_key,
                )?;
                current_chain_key = next_chain_key;
                self.receiving_message_number += 1;
            }
            self.receiving_chain_key = Some(current_chain_key);
        }

        Ok(())
    }

    fn insert_skipped_message_key(
        &mut self,
        key: ([u8; 32], u32),
        message_key: MessageKey,
    ) -> Result<(), RatchetError> {
        if !self.skipped_message_keys.contains_key(&key)
            && self.skipped_message_keys.len() >= MAX_SKIPPED_KEYS_TOTAL
        {
            return Err(RatchetError::MaxSkippedKeysExceeded {
                max: MAX_SKIPPED_KEYS_TOTAL,
            });
        }
        self.skipped_message_keys.insert(key, message_key);
        Ok(())
    }

    // Performs a DH ratchet step and derives new receiving and sending chains.
    fn dh_ratchet_step<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        header: &Header,
    ) -> Result<(), RatchetError> {
        self.previous_chain_length = self.sending_message_number;
        self.sending_message_number = 0;
        self.receiving_message_number = 0;
        self.receiving_ratchet_public_key = Some(header.public_key);

        let receiving_dh_output = self
            .sending_ratchet_key_pair
            .diffie_hellman(&header.public_key)
            .ok_or(RatchetError::NonContributorySharedSecret)?;
        let (next_root_key, receiving_chain_key) =
            derive_root_and_chain_keys(&self.root_key, &receiving_dh_output)?;
        self.root_key = next_root_key;
        self.receiving_chain_key = Some(receiving_chain_key);

        self.sending_ratchet_key_pair = generate_key_pair(rng);
        let sending_dh_output = self
            .sending_ratchet_key_pair
            .diffie_hellman(&header.public_key)
            .ok_or(RatchetError::NonContributorySharedSecret)?;
        let (next_root_key, sending_chain_key) =
            derive_root_and_chain_keys(&self.root_key, &sending_dh_output)?;
        self.root_key = next_root_key;
        self.sending_chain_key = Some(sending_chain_key);

        Ok(())
    }
}

/// An error returned while encrypting or decrypting with a [`RatchetState`].
#[derive(Debug, thiserror::Error)]
pub enum RatchetError {
    /// XChaCha20-Poly1305 encryption or decryption failed.
    #[error("xchacha20-poly1305 encryption or decryption failed")]
    Aead,
    /// HKDF-SHA256 rejected the requested output length.
    #[error("hkdf-sha256 expand exceeded output limit")]
    HkdfExpand,
    /// HMAC-SHA256 rejected a chain-key input.
    #[error("hmac-sha256 rejected the provided key")]
    InvalidHmacKey,
    /// Ratchet state violated an internal invariant.
    #[error("ratchet state invariant violated: {0}")]
    InvalidState(&'static str),
    /// A message header skips more messages than one chain may.
    #[error("message header skips {count} messages, more than {max}")]
    MaxSkipExceeded {
        /// Messages the header skips.
        count: u32,
        /// Most messages one header may skip.
        max: u32,
    },
    /// The skipped message key cache is full.
    #[error("skipped message key cache already holds {max} keys")]
    MaxSkippedKeysExceeded {
        /// Most skipped message keys a session caches.
        max: usize,
    },
    /// An X25519 exchange produced a non-contributory shared secret.
    #[error("x25519 shared secret was non-contributory")]
    NonContributorySharedSecret,
}

/// An error returned while persisting or restoring a [`RatchetState`].
#[derive(Debug, thiserror::Error)]
pub enum RatchetStateError {
    /// Persisted ratchet state bytes failed to decode.
    #[error("ratchet state bytes failed to decode")]
    Decode,
    /// Ratchet state failed to encode for persistence.
    #[error("ratchet state failed to encode")]
    Encode,
    /// Persisted ratchet state holds more skipped message keys than a session caches.
    #[error("ratchet state holds {len} skipped message keys, more than {max}")]
    MaxSkippedKeysExceeded {
        /// Skipped message keys in the persisted state.
        len: usize,
        /// Most skipped message keys a session caches.
        max: usize,
    },
    /// Persisted ratchet state has bytes left over after decoding.
    #[error("ratchet state has {len} trailing bytes")]
    TrailingBytes {
        /// Number of bytes left over.
        len: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    // Returns a fresh initiator/responder pair, shared associated data, and the seeded RNG that
    // produced their keys. Callers keep drawing ratchet keys from it during decrypt.
    fn setup_pair() -> (RatchetState, RatchetState, Vec<u8>, ChaCha20Rng) {
        let mut rng = ChaCha20Rng::from_seed([0x11u8; 32]);
        let shared_secret = [0x42u8; 32];
        let responder_key_pair = generate_key_pair(&mut rng);
        let responder_public_key = responder_key_pair.public;

        let initiator = RatchetState::init_initiator(
            &mut rng,
            RootKey::from_bytes(&shared_secret),
            &responder_public_key,
        )
        .unwrap();
        let responder =
            RatchetState::init_responder(RootKey::from_bytes(&shared_secret), responder_key_pair);
        let associated_data = b"initiator_identity||responder_identity".to_vec();
        (initiator, responder, associated_data, rng)
    }

    // Restores `state` with one stored field changed, the way tampered storage would.
    fn restored_with(
        state: &RatchetState,
        edit: impl FnOnce(&mut DecodedRatchetStateWire),
    ) -> RatchetState {
        let mut wire: DecodedRatchetStateWire =
            postcard::from_bytes(&state.to_bytes().unwrap()).unwrap();
        edit(&mut wire);
        RatchetState::from_bytes(&postcard::to_stdvec(&wire).unwrap()).unwrap()
    }

    #[test]
    fn encrypt_at_the_last_message_number_fails_without_changing_state() {
        let (initiator, _, associated_data, _) = setup_pair();
        let mut exhausted =
            restored_with(&initiator, |wire| wire.sending_message_number = u32::MAX);
        let before = exhausted.to_bytes().unwrap();

        assert!(matches!(
            exhausted.ratchet_encrypt(b"one too many", &associated_data),
            Err(RatchetError::InvalidState(
                "sending message number exhausted"
            ))
        ));
        assert_eq!(*exhausted.to_bytes().unwrap(), *before);
    }

    #[test]
    fn decrypt_at_the_last_message_number_fails_without_changing_state() {
        let (mut initiator, mut responder, associated_data, mut rng) = setup_pair();
        let (header, ciphertext) = initiator
            .ratchet_encrypt(b"first", &associated_data)
            .unwrap();
        responder
            .ratchet_decrypt(&mut rng, &ciphertext, &header, &associated_data)
            .unwrap();
        let mut exhausted =
            restored_with(&responder, |wire| wire.receiving_message_number = u32::MAX);
        let before = exhausted.to_bytes().unwrap();
        let last = Header {
            message_number: u32::MAX,
            ..header
        };

        assert!(matches!(
            exhausted.ratchet_decrypt(&mut rng, &ciphertext, &last, &associated_data),
            Err(RatchetError::InvalidState(
                "receiving message number exhausted"
            ))
        ));
        assert_eq!(*exhausted.to_bytes().unwrap(), *before);
    }

    #[test]
    fn init_initiator_rejects_non_contributory_peer_key() {
        let mut rng = ChaCha20Rng::from_seed([0x21u8; 32]);
        let low_order_public_key = PublicKey::from([0u8; 32]);

        assert!(matches!(
            RatchetState::init_initiator(
                &mut rng,
                RootKey::from_bytes(&[0x42u8; 32]),
                &low_order_public_key,
            ),
            Err(RatchetError::NonContributorySharedSecret)
        ));
    }

    #[test]
    fn responder_encrypt_before_receiving_fails() {
        let (_, mut responder, associated_data, _) = setup_pair();
        let result = responder.ratchet_encrypt(b"premature send", &associated_data);
        assert!(matches!(
            result,
            Err(RatchetError::InvalidState(
                "sending chain key not initialized"
            ))
        ));
    }

    #[test]
    fn encrypt_then_decrypt_round_trip() {
        let (mut initiator, mut responder, associated_data, mut rng) = setup_pair();
        let message = b"hello responder";
        let (header, ciphertext) = initiator
            .ratchet_encrypt(message, &associated_data)
            .unwrap();
        let plaintext = responder
            .ratchet_decrypt(&mut rng, &ciphertext, &header, &associated_data)
            .unwrap();
        assert_eq!(plaintext.as_slice(), message);
    }

    #[test]
    fn low_order_ratchet_header_is_rejected_before_decrypt() {
        let (_, mut responder, associated_data, mut rng) = setup_pair();
        let header = Header {
            public_key: PublicKey::from([0u8; 32]),
            previous_chain_length: 0,
            message_number: 0,
        };

        assert!(matches!(
            responder.ratchet_decrypt(&mut rng, b"ciphertext", &header, &associated_data),
            Err(RatchetError::NonContributorySharedSecret)
        ));
    }

    #[test]
    fn each_message_has_unique_ciphertext() {
        let (mut initiator, _, associated_data, _) = setup_pair();
        let plaintext = b"same plaintext";
        let (_, first_ciphertext) = initiator
            .ratchet_encrypt(plaintext, &associated_data)
            .unwrap();
        let (_, second_ciphertext) = initiator
            .ratchet_encrypt(plaintext, &associated_data)
            .unwrap();
        assert_ne!(first_ciphertext, second_ciphertext);
    }

    #[test]
    fn alternating_messages_decrypt_in_both_directions() {
        let (mut initiator, mut responder, associated_data, mut rng) = setup_pair();

        let first_message = b"message 1";
        let (first_header, first_ciphertext) = initiator
            .ratchet_encrypt(first_message, &associated_data)
            .unwrap();
        let first_plaintext = responder
            .ratchet_decrypt(&mut rng, &first_ciphertext, &first_header, &associated_data)
            .unwrap();
        assert_eq!(first_plaintext.as_slice(), first_message);

        let second_message = b"message 2";
        let (second_header, second_ciphertext) = responder
            .ratchet_encrypt(second_message, &associated_data)
            .unwrap();
        let second_plaintext = initiator
            .ratchet_decrypt(
                &mut rng,
                &second_ciphertext,
                &second_header,
                &associated_data,
            )
            .unwrap();
        assert_eq!(second_plaintext.as_slice(), second_message);

        let third_message = b"message 3";
        let (third_header, third_ciphertext) = initiator
            .ratchet_encrypt(third_message, &associated_data)
            .unwrap();
        let third_plaintext = responder
            .ratchet_decrypt(&mut rng, &third_ciphertext, &third_header, &associated_data)
            .unwrap();
        assert_eq!(third_plaintext.as_slice(), third_message);

        let fourth_message = b"message 4";
        let (fourth_header, fourth_ciphertext) = responder
            .ratchet_encrypt(fourth_message, &associated_data)
            .unwrap();
        let fourth_plaintext = initiator
            .ratchet_decrypt(
                &mut rng,
                &fourth_ciphertext,
                &fourth_header,
                &associated_data,
            )
            .unwrap();
        assert_eq!(fourth_plaintext.as_slice(), fourth_message);
    }

    #[test]
    fn consecutive_messages_decrypt_in_order() {
        let (mut initiator, mut responder, associated_data, mut rng) = setup_pair();

        let first_message = b"msg 1";
        let second_message = b"msg 2";
        let third_message = b"msg 3";
        let (first_header, first_ciphertext) = initiator
            .ratchet_encrypt(first_message, &associated_data)
            .unwrap();
        let (second_header, second_ciphertext) = initiator
            .ratchet_encrypt(second_message, &associated_data)
            .unwrap();
        let (third_header, third_ciphertext) = initiator
            .ratchet_encrypt(third_message, &associated_data)
            .unwrap();

        let first_plaintext = responder
            .ratchet_decrypt(&mut rng, &first_ciphertext, &first_header, &associated_data)
            .unwrap();
        let second_plaintext = responder
            .ratchet_decrypt(
                &mut rng,
                &second_ciphertext,
                &second_header,
                &associated_data,
            )
            .unwrap();
        let third_plaintext = responder
            .ratchet_decrypt(&mut rng, &third_ciphertext, &third_header, &associated_data)
            .unwrap();
        assert_eq!(first_plaintext.as_slice(), first_message);
        assert_eq!(second_plaintext.as_slice(), second_message);
        assert_eq!(third_plaintext.as_slice(), third_message);
    }

    #[test]
    fn messages_decrypt_out_of_order() {
        let (mut initiator, mut responder, associated_data, mut rng) = setup_pair();

        let first_message = b"msg 1";
        let second_message = b"msg 2";
        let third_message = b"msg 3";
        let (first_header, first_ciphertext) = initiator
            .ratchet_encrypt(first_message, &associated_data)
            .unwrap();
        let (second_header, second_ciphertext) = initiator
            .ratchet_encrypt(second_message, &associated_data)
            .unwrap();
        let (third_header, third_ciphertext) = initiator
            .ratchet_encrypt(third_message, &associated_data)
            .unwrap();

        let third_plaintext = responder
            .ratchet_decrypt(&mut rng, &third_ciphertext, &third_header, &associated_data)
            .unwrap();
        let second_plaintext = responder
            .ratchet_decrypt(
                &mut rng,
                &second_ciphertext,
                &second_header,
                &associated_data,
            )
            .unwrap();
        let first_plaintext = responder
            .ratchet_decrypt(&mut rng, &first_ciphertext, &first_header, &associated_data)
            .unwrap();
        assert_eq!(first_plaintext.as_slice(), first_message);
        assert_eq!(second_plaintext.as_slice(), second_message);
        assert_eq!(third_plaintext.as_slice(), third_message);
    }

    #[test]
    fn max_skipped_keys_total_rejects_without_evicting_retained_keys() {
        let (mut initiator, mut responder, associated_data, mut rng) = setup_pair();

        let fill_steps = MAX_SKIPPED_KEYS_TOTAL as u32 / MAX_SKIP;
        let mut oldest_skipped = None;
        for step in 0..fill_steps {
            let mut messages: Vec<_> = (0..=MAX_SKIP)
                .map(|message_number| {
                    initiator
                        .ratchet_encrypt(
                            format!("step {step} msg {message_number}").as_bytes(),
                            &associated_data,
                        )
                        .unwrap()
                })
                .collect();
            let first_message = messages.remove(0);
            if step == 0 {
                oldest_skipped = Some(first_message);
            }
            let (last_header, last_ciphertext) = messages.last().unwrap();
            responder
                .ratchet_decrypt(&mut rng, last_ciphertext, last_header, &associated_data)
                .unwrap();
        }

        assert_eq!(responder.skipped_message_keys.len(), MAX_SKIPPED_KEYS_TOTAL);

        let overflow_messages: Vec<_> = (0..=MAX_SKIP)
            .map(|message_number| {
                initiator
                    .ratchet_encrypt(
                        format!("overflow msg {message_number}").as_bytes(),
                        &associated_data,
                    )
                    .unwrap()
            })
            .collect();
        let (overflow_header, overflow_ciphertext) = overflow_messages.last().unwrap();
        assert!(matches!(
            responder.ratchet_decrypt(
                &mut rng,
                overflow_ciphertext,
                overflow_header,
                &associated_data
            ),
            Err(RatchetError::MaxSkippedKeysExceeded {
                max: MAX_SKIPPED_KEYS_TOTAL
            })
        ));
        assert_eq!(responder.skipped_message_keys.len(), MAX_SKIPPED_KEYS_TOTAL);

        let (oldest_header, oldest_ciphertext) = oldest_skipped.unwrap();
        let plaintext = responder
            .ratchet_decrypt(
                &mut rng,
                &oldest_ciphertext,
                &oldest_header,
                &associated_data,
            )
            .unwrap();
        assert_eq!(plaintext.as_slice(), b"step 0 msg 0");
    }

    #[test]
    fn restored_skipped_key_cache_at_capacity_rejects_new_skips() {
        let (mut initiator, mut responder, associated_data, mut rng) = setup_pair();

        let fill_steps = MAX_SKIPPED_KEYS_TOTAL as u32 / MAX_SKIP;
        let mut oldest_survivor = None;
        for step in 0..fill_steps {
            let mut messages: Vec<_> = (0..=MAX_SKIP)
                .map(|message_number| {
                    initiator
                        .ratchet_encrypt(
                            format!("fill {step} msg {message_number}").as_bytes(),
                            &associated_data,
                        )
                        .unwrap()
                })
                .collect();
            let first_message = messages.remove(0);
            if step == 0 {
                oldest_survivor = Some(first_message);
            }
            let (last_header, last_ciphertext) = messages.last().unwrap();
            responder
                .ratchet_decrypt(&mut rng, last_ciphertext, last_header, &associated_data)
                .unwrap();
        }
        assert_eq!(responder.skipped_message_keys.len(), MAX_SKIPPED_KEYS_TOTAL);

        let bytes = responder.to_bytes().unwrap();
        let mut restored = RatchetState::from_bytes(&bytes).unwrap();

        let messages: Vec<_> = (0..=MAX_SKIP)
            .map(|message_number| {
                initiator
                    .ratchet_encrypt(
                        format!("after restore msg {message_number}").as_bytes(),
                        &associated_data,
                    )
                    .unwrap()
            })
            .collect();
        let (last_header, last_ciphertext) = messages.last().unwrap();
        assert!(matches!(
            restored.ratchet_decrypt(&mut rng, last_ciphertext, last_header, &associated_data),
            Err(RatchetError::MaxSkippedKeysExceeded {
                max: MAX_SKIPPED_KEYS_TOTAL
            })
        ));
        assert_eq!(restored.skipped_message_keys.len(), MAX_SKIPPED_KEYS_TOTAL);

        let (oldest_header, oldest_ciphertext) = oldest_survivor.unwrap();
        let plaintext = restored
            .ratchet_decrypt(
                &mut rng,
                &oldest_ciphertext,
                &oldest_header,
                &associated_data,
            )
            .unwrap();
        assert_eq!(plaintext.as_slice(), b"fill 0 msg 0");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (mut initiator, mut responder, associated_data, mut rng) = setup_pair();
        let (header, mut ciphertext) = initiator
            .ratchet_encrypt(b"secret", &associated_data)
            .unwrap();
        ciphertext[0] ^= 0xFF;
        let result = responder.ratchet_decrypt(&mut rng, &ciphertext, &header, &associated_data);
        assert!(matches!(result, Err(RatchetError::Aead)));
    }

    #[test]
    fn tampered_associated_data_fails() {
        let (mut initiator, mut responder, associated_data, mut rng) = setup_pair();
        let (header, ciphertext) = initiator
            .ratchet_encrypt(b"secret", &associated_data)
            .unwrap();
        let wrong_associated_data = b"wrong_identity_keys";
        let result =
            responder.ratchet_decrypt(&mut rng, &ciphertext, &header, wrong_associated_data);
        assert!(matches!(result, Err(RatchetError::Aead)));
    }

    // Duplicate current-chain messages must fail without under-flowing the skip calculation.
    #[test]
    fn duplicate_message_under_current_dh_key_fails_without_underflow() {
        let (mut initiator, mut responder, associated_data, mut rng) = setup_pair();
        let (header, ciphertext) = initiator
            .ratchet_encrypt(b"hello", &associated_data)
            .unwrap();
        responder
            .ratchet_decrypt(&mut rng, &ciphertext, &header, &associated_data)
            .unwrap();
        let result = responder.ratchet_decrypt(&mut rng, &ciphertext, &header, &associated_data);
        assert!(matches!(result, Err(RatchetError::Aead)));
    }

    #[test]
    fn failed_decrypt_rolls_back_state() {
        let (mut initiator, mut responder, associated_data, mut rng) = setup_pair();

        let (first_header, first_ciphertext) = initiator
            .ratchet_encrypt(b"msg 1", &associated_data)
            .unwrap();
        responder
            .ratchet_decrypt(&mut rng, &first_ciphertext, &first_header, &associated_data)
            .unwrap();

        let before = responder.to_bytes().unwrap();

        let (second_header, mut second_ciphertext) = initiator
            .ratchet_encrypt(b"msg 2", &associated_data)
            .unwrap();
        second_ciphertext[0] ^= 0xFF;
        let result = responder.ratchet_decrypt(
            &mut rng,
            &second_ciphertext,
            &second_header,
            &associated_data,
        );
        assert!(matches!(result, Err(RatchetError::Aead)));
        assert_eq!(*responder.to_bytes().unwrap(), *before);
    }

    #[test]
    fn to_bytes_round_trip_is_byte_identical() {
        let (initiator, _, _, _) = setup_pair();
        let original_bytes = initiator.to_bytes().unwrap();
        let restored = RatchetState::from_bytes(&original_bytes).unwrap();
        let restored_bytes = restored.to_bytes().unwrap();
        assert_eq!(&*original_bytes, &*restored_bytes);
    }

    #[test]
    fn restored_state_continues_session() {
        let (mut initiator, mut responder, associated_data, mut rng) = setup_pair();

        let (first_header, first_ciphertext) = initiator
            .ratchet_encrypt(b"msg 1", &associated_data)
            .unwrap();
        responder
            .ratchet_decrypt(&mut rng, &first_ciphertext, &first_header, &associated_data)
            .unwrap();

        let bytes = initiator.to_bytes().unwrap();
        let mut restored = RatchetState::from_bytes(&bytes).unwrap();

        let message = b"msg 2";
        let (second_header, second_ciphertext) =
            restored.ratchet_encrypt(message, &associated_data).unwrap();
        let plaintext = responder
            .ratchet_decrypt(
                &mut rng,
                &second_ciphertext,
                &second_header,
                &associated_data,
            )
            .unwrap();
        assert_eq!(plaintext.as_slice(), message);
    }

    #[test]
    fn skipped_message_keys_survive_round_trip() {
        let (mut initiator, mut responder, associated_data, mut rng) = setup_pair();

        let (first_header, first_ciphertext) = initiator
            .ratchet_encrypt(b"msg 1", &associated_data)
            .unwrap();
        let (second_header, second_ciphertext) = initiator
            .ratchet_encrypt(b"msg 2", &associated_data)
            .unwrap();
        let (third_header, third_ciphertext) = initiator
            .ratchet_encrypt(b"msg 3", &associated_data)
            .unwrap();

        responder
            .ratchet_decrypt(&mut rng, &first_ciphertext, &first_header, &associated_data)
            .unwrap();
        responder
            .ratchet_decrypt(&mut rng, &third_ciphertext, &third_header, &associated_data)
            .unwrap();
        assert!(!responder.skipped_message_keys.is_empty());

        let bytes = responder.to_bytes().unwrap();
        let mut restored = RatchetState::from_bytes(&bytes).unwrap();

        let plaintext = restored
            .ratchet_decrypt(
                &mut rng,
                &second_ciphertext,
                &second_header,
                &associated_data,
            )
            .unwrap();
        assert_eq!(plaintext.as_slice(), b"msg 2");
    }

    #[test]
    fn from_bytes_rejects_trailing_bytes() {
        let (initiator, _, _, _) = setup_pair();
        let mut bytes = initiator.to_bytes().unwrap().to_vec();
        bytes.push(0);
        assert!(matches!(
            RatchetState::from_bytes(&bytes),
            Err(RatchetStateError::TrailingBytes { len: 1 })
        ));
    }

    #[test]
    fn from_bytes_rejects_malformed_blob() {
        let (initiator, _, _, _) = setup_pair();
        let bytes = initiator.to_bytes().unwrap();
        let truncated = &bytes[..1];
        assert!(matches!(
            RatchetState::from_bytes(truncated),
            Err(RatchetStateError::Decode)
        ));
    }

    #[test]
    fn from_bytes_rejects_oversized_skipped_key_cache() {
        let oversized = DecodedRatchetStateWire {
            sending_ratchet_secret_key: Zeroizing::new([0; 32]),
            receiving_ratchet_public_key: None,
            root_key: Zeroizing::new([0; 32]),
            sending_chain_key: None,
            receiving_chain_key: None,
            sending_message_number: 0,
            receiving_message_number: 0,
            previous_chain_length: 0,
            skipped_message_keys: (0..=MAX_SKIPPED_KEYS_TOTAL as u32)
                .map(|i| (([0; 32], i), Zeroizing::new([0; 32])))
                .collect(),
        };
        let bytes = postcard::to_stdvec(&oversized).unwrap();
        assert!(matches!(
            RatchetState::from_bytes(&bytes),
            Err(RatchetStateError::MaxSkippedKeysExceeded { len, max: MAX_SKIPPED_KEYS_TOTAL })
                if len == MAX_SKIPPED_KEYS_TOTAL + 1
        ));
    }
}
