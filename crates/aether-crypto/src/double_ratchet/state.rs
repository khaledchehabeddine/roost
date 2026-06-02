//! Maintains Double Ratchet session state, including chain advancement, skipped-message keys, and
//! session restore.

use super::aead::{decrypt, encrypt};
use super::header::Header;
use crate::error::CryptoError;
use crate::keys::{KeyPair, PublicKey, generate_key_pair};
use crate::ratchet::{ChainKey, MessageKey, RootKey, kdf_ck, kdf_rk};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// Limits how many message keys one header can force this session to derive.
const MAX_SKIP: u32 = 100;
// Caps all cached skipped-message keys, so repeated DH steps cannot exhaust memory.
const MAX_SKIPPED_KEYS_TOTAL: usize = 500;
const RATCHET_STATE_VERSION: u8 = 2;

/// A Double Ratchet session state between two peers.
///
/// After each successful encrypt or decrypt, callers that persist session states must replace the
/// old stored blob with a new one from [`Self::to_bytes`].
pub struct RatchetState {
    // Sending ratchet key pair.
    dhs: KeyPair,
    // Receiving ratchet public key. `None` until the first message arrives.
    dhr: Option<PublicKey>,
    // Root key. Evolves with each DH ratchet step.
    rk: RootKey,
    // Sending chain key. `None` before the responder receives the first message.
    cks: Option<ChainKey>,
    // Receiving chain key. `None` until the first message is received.
    ckr: Option<ChainKey>,
    // Number of messages sent in the current sending chain.
    ns: u32,
    // Number of messages received in the current receiving chain.
    nr: u32,
    // Number of messages sent in the previous sending chain.
    pn: u32,
    // Cached keys for out-of-order messages, keyed by sender public key bytes and message number.
    // `BTreeMap` keeps lookup and serialized snapshots deterministic.
    mk_skipped: BTreeMap<([u8; 32], u32), SkippedMessageKey>,
    // Monotonic first-insertion sequence used for deterministic oldest-first eviction.
    next_skipped_key_sequence: u64,
}

// Serde-friendly wire form for `to_bytes` / `from_bytes`.
#[derive(Deserialize, Serialize)]
struct RatchetStateWire {
    version: u8,
    dhs_secret: [u8; 32],
    dhr: Option<[u8; 32]>,
    rk: [u8; 32],
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
    mk_skipped: BTreeMap<([u8; 32], u32), SkippedMessageKeyWire>,
    next_skipped_key_sequence: u64,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct SkippedMessageKey {
    message_key: MessageKey,
    sequence: u64,
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
struct SkippedMessageKeyWire {
    message_key: [u8; 32],
    #[zeroize(skip)]
    sequence: u64,
}

// The tuple key in `mk_skipped` does not implement `Zeroize`, so the secret fields are wiped
// manually instead of deriving `ZeroizeOnDrop`.
impl Drop for RatchetStateWire {
    fn drop(&mut self) {
        self.dhs_secret.zeroize();
        self.rk.zeroize();
        if let Some(ref mut cks) = self.cks {
            cks.zeroize();
        }
        if let Some(ref mut ckr) = self.ckr {
            ckr.zeroize();
        }
        for value in self.mk_skipped.values_mut() {
            value.message_key.zeroize();
        }
    }
}

impl RatchetState {
    // Initializes the initiator side with its first sending chain ready.
    pub(crate) fn init_initiator<R: RngCore + CryptoRng>(
        rng: &mut R,
        rk: RootKey,
        dhr: &PublicKey,
    ) -> Result<Self, CryptoError> {
        let dhs = generate_key_pair(rng);
        let dh_output = dhs.diffie_hellman(dhr);
        let (rk, cks) = kdf_rk(&rk, &dh_output)?;
        Ok(Self {
            dhs,
            dhr: Some(*dhr),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mk_skipped: BTreeMap::new(),
            next_skipped_key_sequence: 0,
        })
    }

    // Initializes the responder side without chain keys until the first message arrives.
    pub(crate) fn init_responder(rk: RootKey, dhs: KeyPair) -> Self {
        Self {
            dhs,
            dhr: None,
            rk,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mk_skipped: BTreeMap::new(),
            next_skipped_key_sequence: 0,
        }
    }

    /// Encrypts `plaintext`, advances the sending chain, and returns the header and ciphertext.
    ///
    /// The returned [`Header`] must be sent with `ciphertext`. `associated_data` must be the same
    /// byte sequence the receiver passes to [`Self::ratchet_decrypt`].
    ///
    /// # Errors
    /// - [`CryptoError::Aead`] if XChaCha20-Poly1305 encryption fails after the sending chain has
    ///   advanced.
    /// - [`CryptoError::InvalidHmacKey`] if the chain-key KDF rejects its input.
    /// - [`CryptoError::InvalidState`] if the sending chain key is not yet initialized
    ///   (responder calling encrypt before any incoming message has driven the DH ratchet).
    pub fn ratchet_encrypt(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(Header, Vec<u8>), CryptoError> {
        let cks = self.cks.as_ref().ok_or(CryptoError::InvalidState(
            "sending chain key not initialized",
        ))?;
        let (new_cks, mk) = kdf_ck(cks)?;
        self.cks = Some(new_cks);

        let header = Header {
            public_key: self.dhs.public,
            previous_chain_length: self.pn,
            message_number: self.ns,
        };
        self.ns += 1;

        let ciphertext = encrypt(plaintext, associated_data, &header, &mk)?;
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
    ///
    /// # Errors
    /// - [`CryptoError::Aead`] on tampered ciphertext, wrong associated data, or wrong key.
    /// - [`CryptoError::HkdfExpand`] if the root-key KDF run during a DH ratchet step fails.
    /// - [`CryptoError::InvalidHmacKey`] if the chain-key KDF rejects its input.
    /// - [`CryptoError::InvalidState`] if the receiving chain key is not set after a
    ///   Diffie-Hellman ratchet step (indicates internal invariant violation).
    /// - [`CryptoError::MaxSkipExceeded`] if the header asks to skip more than the per-step
    ///   skip limit.
    /// - [`CryptoError::MaxSkippedKeysExceeded`] if accepting this message pushes the global
    ///   skipped-key cache past the limit.
    pub fn ratchet_decrypt<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        ciphertext: &[u8],
        header: &Header,
        associated_data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if let Some(plaintext) =
            self.try_skipped_message_keys(ciphertext, header, associated_data)?
        {
            return Ok(plaintext);
        }

        let mut state = self.snapshot();
        if Some(header.public_key) != state.dhr {
            state.skip_message_keys(header.previous_chain_length)?;
            state.dh_ratchet_step(rng, header)?;
        }
        state.skip_message_keys(header.message_number)?;
        let ckr = state.ckr.as_ref().ok_or(CryptoError::InvalidState(
            "receiving chain key not set after DH ratchet",
        ))?;
        let (new_ckr, mk) = kdf_ck(ckr)?;
        state.ckr = Some(new_ckr);
        state.nr += 1;

        let plaintext = decrypt(ciphertext, associated_data, header, &mk)?;
        *self = state;
        Ok(plaintext)
    }

    /// Serializes the session state for persistent storage as an opaque blob.
    ///
    /// Callers must overwrite the previously stored blob rather than append a new entry alongside
    /// it. Forward secrecy depends on stale states being destroyed after every state change.
    ///
    /// # Errors
    /// - [`CryptoError::RatchetStateEncode`] if serialization fails.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let wire = RatchetStateWire {
            version: RATCHET_STATE_VERSION,
            dhs_secret: *self.dhs.to_secret_bytes(),
            dhr: self.dhr.map(|pk| *pk.as_bytes()),
            rk: *self.rk.as_bytes(),
            cks: self.cks.as_ref().map(|ck| *ck.as_bytes()),
            ckr: self.ckr.as_ref().map(|ck| *ck.as_bytes()),
            ns: self.ns,
            nr: self.nr,
            pn: self.pn,
            mk_skipped: self
                .mk_skipped
                .iter()
                .map(|(k, v)| {
                    (
                        *k,
                        SkippedMessageKeyWire {
                            message_key: *v.message_key.as_bytes(),
                            sequence: v.sequence,
                        },
                    )
                })
                .collect(),
            next_skipped_key_sequence: self.next_skipped_key_sequence,
        };
        postcard::to_stdvec(&wire)
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::RatchetStateEncode)
    }

    /// Restores a session state from a blob produced by [`Self::to_bytes`].
    ///
    /// Persisted blobs are treated as external input, so tampered storage cannot bypass the
    /// skipped-key cache cap.
    ///
    /// # Errors
    /// - [`CryptoError::MaxSkippedKeysExceeded`] if the skipped-key cache exceeds its cap.
    /// - [`CryptoError::RatchetStateDecode`] if the blob fails structural decode (truncated,
    ///   tampered, or corrupt).
    /// - [`CryptoError::UnsupportedRatchetVersion`] if the version byte is not the format
    ///   this build understands.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let version = *bytes.first().ok_or(CryptoError::RatchetStateDecode)?;
        if version != RATCHET_STATE_VERSION {
            return Err(CryptoError::UnsupportedRatchetVersion(version));
        }
        let wire: RatchetStateWire =
            postcard::from_bytes(bytes).map_err(|_| CryptoError::RatchetStateDecode)?;
        if wire.mk_skipped.len() > MAX_SKIPPED_KEYS_TOTAL {
            return Err(CryptoError::MaxSkippedKeysExceeded);
        }
        let max_sequence = wire
            .mk_skipped
            .values()
            .map(|v| v.sequence)
            .max()
            .unwrap_or(0);
        if !wire.mk_skipped.is_empty() {
            let min_next_sequence = max_sequence
                .checked_add(1)
                .ok_or(CryptoError::RatchetStateDecode)?;
            if wire.next_skipped_key_sequence < min_next_sequence {
                return Err(CryptoError::RatchetStateDecode);
            }
        }
        Ok(Self {
            dhs: KeyPair::from_secret_bytes(wire.dhs_secret),
            dhr: wire.dhr.map(PublicKey::from),
            rk: RootKey::from_bytes(wire.rk),
            cks: wire.cks.map(ChainKey::from_bytes),
            ckr: wire.ckr.map(ChainKey::from_bytes),
            ns: wire.ns,
            nr: wire.nr,
            pn: wire.pn,
            mk_skipped: wire
                .mk_skipped
                .iter()
                .map(|(k, v)| {
                    (
                        *k,
                        SkippedMessageKey {
                            message_key: MessageKey(v.message_key),
                            sequence: v.sequence,
                        },
                    )
                })
                .collect(),
            next_skipped_key_sequence: wire.next_skipped_key_sequence,
        })
    }

    /// Returns the number of cached message keys awaiting out-of-order delivery.
    pub fn skipped_key_count(&self) -> usize {
        self.mk_skipped.len()
    }

    // Keeps rollback local without exposing `Clone` on a secret-bearing type.
    fn snapshot(&self) -> Self {
        Self {
            dhs: KeyPair::from_secret_bytes(*self.dhs.to_secret_bytes()),
            dhr: self.dhr,
            rk: self.rk.clone(),
            cks: self.cks.clone(),
            ckr: self.ckr.clone(),
            ns: self.ns,
            nr: self.nr,
            pn: self.pn,
            mk_skipped: self.mk_skipped.clone(),
            next_skipped_key_sequence: self.next_skipped_key_sequence,
        }
    }

    // Puts the skipped key back when authentication fails, so tampered replays cannot burn it.
    fn try_skipped_message_keys(
        &mut self,
        ciphertext: &[u8],
        header: &Header,
        associated_data: &[u8],
    ) -> Result<Option<Zeroizing<Vec<u8>>>, CryptoError> {
        let key = (*header.public_key.as_bytes(), header.message_number);
        if let Some(skipped) = self.mk_skipped.remove(&key) {
            match decrypt(ciphertext, associated_data, header, &skipped.message_key) {
                Ok(plaintext) => Ok(Some(plaintext)),
                Err(e) => {
                    self.mk_skipped.insert(key, skipped);
                    Err(e)
                }
            }
        } else {
            Ok(None)
        }
    }

    // Advances the receiving chain and caches skipped message keys up to `until_n`.
    fn skip_message_keys(&mut self, until_n: u32) -> Result<(), CryptoError> {
        // Duplicate messages can ask for a message number already behind `self.nr`. Treat them as
        // already processed so `until_n - self.nr` cannot underflow.
        if until_n < self.nr {
            return Ok(());
        }
        if until_n > self.nr + MAX_SKIP {
            return Err(CryptoError::MaxSkipExceeded);
        }

        if let Some(ref ckr) = self.ckr {
            let dhr = self.dhr.ok_or(CryptoError::InvalidState(
                "dhr not set when skipping message keys",
            ))?;
            let mut current_ck = ChainKey::from_bytes(*ckr.as_bytes());
            while self.nr < until_n {
                let (next_ck, mk) = kdf_ck(&current_ck)?;
                self.insert_skipped_message_key((*dhr.as_bytes(), self.nr), mk)?;
                current_ck = next_ck;
                self.nr += 1;
            }
            self.ckr = Some(current_ck);
        }

        Ok(())
    }

    fn insert_skipped_message_key(
        &mut self,
        key: ([u8; 32], u32),
        message_key: MessageKey,
    ) -> Result<(), CryptoError> {
        let sequence = self.next_skipped_key_sequence;
        self.next_skipped_key_sequence = self
            .next_skipped_key_sequence
            .checked_add(1)
            .ok_or(CryptoError::InvalidState("skipped-key sequence exhausted"))?;
        self.mk_skipped.insert(
            key,
            SkippedMessageKey {
                message_key,
                sequence,
            },
        );
        while self.mk_skipped.len() > MAX_SKIPPED_KEYS_TOTAL {
            self.evict_oldest_skipped_message_key();
        }
        Ok(())
    }

    fn evict_oldest_skipped_message_key(&mut self) {
        let oldest_key = self
            .mk_skipped
            .iter()
            .min_by_key(|(key, skipped)| (skipped.sequence, *key))
            .map(|(key, _)| *key);
        if let Some(oldest_key) = oldest_key {
            self.mk_skipped.remove(&oldest_key);
        }
    }

    // Performs a DH ratchet step and derives new receiving and sending chains.
    fn dh_ratchet_step<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        header: &Header,
    ) -> Result<(), CryptoError> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(header.public_key);

        let dh_recv = self.dhs.diffie_hellman(&header.public_key);
        let (rk, ckr) = kdf_rk(&self.rk, &dh_recv)?;
        self.rk = rk;
        self.ckr = Some(ckr);

        self.dhs = generate_key_pair(rng);
        let dh_send = self.dhs.diffie_hellman(&header.public_key);
        let (rk, cks) = kdf_rk(&self.rk, &dh_send)?;
        self.rk = rk;
        self.cks = Some(cks);

        Ok(())
    }
}

impl ZeroizeOnDrop for RatchetStateWire {}

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
            RootKey::from_bytes(shared_secret),
            &responder_public_key,
        )
        .unwrap();
        let responder =
            RatchetState::init_responder(RootKey::from_bytes(shared_secret), responder_key_pair);
        let associated_data = b"initiator_identity||responder_identity".to_vec();
        (initiator, responder, associated_data, rng)
    }

    #[test]
    fn init_initiator_sets_sending_chain() {
        let (initiator, _, _, _) = setup_pair();
        assert!(initiator.dhr.is_some());
        assert!(initiator.cks.is_some());
        assert!(initiator.ckr.is_none());
        assert_eq!(initiator.ns, 0);
        assert_eq!(initiator.nr, 0);
        assert_eq!(initiator.pn, 0);
    }

    #[test]
    fn init_responder_has_no_chains() {
        let (_, responder, _, _) = setup_pair();
        assert!(responder.dhr.is_none());
        assert!(responder.cks.is_none());
        assert!(responder.ckr.is_none());
        assert_eq!(responder.ns, 0);
        assert_eq!(responder.nr, 0);
        assert_eq!(responder.pn, 0);
    }

    #[test]
    fn responder_encrypt_before_receiving_fails() {
        let (_, mut responder, associated_data, _) = setup_pair();

        let result = responder.ratchet_encrypt(b"premature send", &associated_data);
        assert!(matches!(result, Err(CryptoError::InvalidState(_))));
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
    fn ping_pong_exchange() {
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
    fn multiple_messages_same_direction() {
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
    fn out_of_order_delivery() {
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
    fn max_skip_rejects_large_message_gap() {
        let (mut initiator, mut responder, associated_data, mut rng) = setup_pair();

        let (last_header, last_ciphertext) = (0..MAX_SKIP + 2)
            .map(|message_number| {
                initiator
                    .ratchet_encrypt(format!("msg {message_number}").as_bytes(), &associated_data)
                    .unwrap()
            })
            .last()
            .unwrap();

        let result =
            responder.ratchet_decrypt(&mut rng, &last_ciphertext, &last_header, &associated_data);
        assert!(matches!(result, Err(CryptoError::MaxSkipExceeded)));
    }

    #[test]
    fn max_skipped_keys_evicts_oldest_entries() {
        let (mut initiator, mut responder, associated_data, mut rng) = setup_pair();

        let overflow_step = MAX_SKIPPED_KEYS_TOTAL as u32 / MAX_SKIP;
        let mut oldest_skipped = None;
        let mut newest_skipped = None;
        for step in 0..=overflow_step {
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
            } else if step == overflow_step {
                newest_skipped = Some(first_message);
            }
            let (last_header, last_ciphertext) = messages.last().unwrap();
            responder
                .ratchet_decrypt(&mut rng, last_ciphertext, last_header, &associated_data)
                .unwrap();
        }

        assert_eq!(responder.skipped_key_count(), MAX_SKIPPED_KEYS_TOTAL);

        let (oldest_header, oldest_ciphertext) = oldest_skipped.unwrap();
        assert!(matches!(
            responder.ratchet_decrypt(
                &mut rng,
                &oldest_ciphertext,
                &oldest_header,
                &associated_data
            ),
            Err(CryptoError::Aead)
        ));

        let (newest_header, newest_ciphertext) = newest_skipped.unwrap();
        let plaintext = responder
            .ratchet_decrypt(
                &mut rng,
                &newest_ciphertext,
                &newest_header,
                &associated_data,
            )
            .unwrap();
        assert_eq!(plaintext.as_slice(), b"step 5 msg 0");
    }

    #[test]
    fn restored_skipped_key_sequence_evicts_oldest_survivor() {
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
        assert_eq!(responder.skipped_key_count(), MAX_SKIPPED_KEYS_TOTAL);

        let bytes = responder.to_bytes().unwrap();
        let mut restored = RatchetState::from_bytes(&bytes).unwrap();

        let mut messages: Vec<_> = (0..=MAX_SKIP)
            .map(|message_number| {
                initiator
                    .ratchet_encrypt(
                        format!("after restore msg {message_number}").as_bytes(),
                        &associated_data,
                    )
                    .unwrap()
            })
            .collect();
        let newest_survivor = messages.remove(0);
        let (last_header, last_ciphertext) = messages.last().unwrap();
        restored
            .ratchet_decrypt(&mut rng, last_ciphertext, last_header, &associated_data)
            .unwrap();

        let (oldest_header, oldest_ciphertext) = oldest_survivor.unwrap();
        assert!(matches!(
            restored.ratchet_decrypt(
                &mut rng,
                &oldest_ciphertext,
                &oldest_header,
                &associated_data
            ),
            Err(CryptoError::Aead)
        ));

        let (newest_header, newest_ciphertext) = newest_survivor;
        let plaintext = restored
            .ratchet_decrypt(
                &mut rng,
                &newest_ciphertext,
                &newest_header,
                &associated_data,
            )
            .unwrap();
        assert_eq!(plaintext.as_slice(), b"after restore msg 0");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (mut initiator, mut responder, associated_data, mut rng) = setup_pair();

        let (header, mut ciphertext) = initiator
            .ratchet_encrypt(b"secret", &associated_data)
            .unwrap();
        ciphertext[0] ^= 0xFF;

        let result = responder.ratchet_decrypt(&mut rng, &ciphertext, &header, &associated_data);
        assert!(matches!(result, Err(CryptoError::Aead)));
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
        assert!(matches!(result, Err(CryptoError::Aead)));
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
        assert!(matches!(result, Err(CryptoError::Aead)));
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

        let receiving_count_before = responder.nr;
        let sending_count_before = responder.ns;
        let skipped_count_before = responder.mk_skipped.len();

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
        assert!(matches!(result, Err(CryptoError::Aead)));

        assert_eq!(responder.nr, receiving_count_before);
        assert_eq!(responder.ns, sending_count_before);
        assert_eq!(responder.mk_skipped.len(), skipped_count_before);
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
        assert!(!responder.mk_skipped.is_empty());

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
    fn from_bytes_rejects_unsupported_version() {
        let (initiator, _, _, _) = setup_pair();
        let mut bytes = initiator.to_bytes().unwrap().to_vec();
        bytes[0] = 0xFF;
        assert!(matches!(
            RatchetState::from_bytes(&bytes),
            Err(CryptoError::UnsupportedRatchetVersion(0xFF))
        ));
    }

    #[test]
    fn from_bytes_rejects_malformed_blob() {
        let (initiator, _, _, _) = setup_pair();
        let bytes = initiator.to_bytes().unwrap();
        let truncated = &bytes[..1];
        assert!(matches!(
            RatchetState::from_bytes(truncated),
            Err(CryptoError::RatchetStateDecode)
        ));
    }

    #[test]
    fn from_bytes_rejects_oversized_skipped_key_cache() {
        let oversized = RatchetStateWire {
            version: RATCHET_STATE_VERSION,
            dhs_secret: [0; 32],
            dhr: None,
            rk: [0; 32],
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mk_skipped: (0..=MAX_SKIPPED_KEYS_TOTAL as u32)
                .map(|i| {
                    (
                        ([0; 32], i),
                        SkippedMessageKeyWire {
                            message_key: [0; 32],
                            sequence: u64::from(i),
                        },
                    )
                })
                .collect(),
            next_skipped_key_sequence: MAX_SKIPPED_KEYS_TOTAL as u64 + 1,
        };
        let bytes = postcard::to_stdvec(&oversized).unwrap();
        assert!(matches!(
            RatchetState::from_bytes(&bytes),
            Err(CryptoError::MaxSkippedKeysExceeded)
        ));
    }
}
