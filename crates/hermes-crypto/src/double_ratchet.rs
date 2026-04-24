use crate::error::CryptoError;
use crate::keys::{KeyPair, PublicKey, generate_key_pair};
use crate::ratchet::{ChainKey, MessageKey, RootKey, kdf_ck, kdf_rk};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Maximum number of message keys to skip in a single ratchet step.
const MAX_SKIP: u32 = 100;
/// Global cap across all ratchet chains, preventing memory exhaustion from repeated DH steps.
const MAX_SKIPPED_KEYS_TOTAL: usize = 500;
const HKDF_MK_INFO: &[u8] = b"HermesRatchet_MK";
const RATCHET_STATE_VERSION: u8 = 1;

/// Message header transmitted alongside each ciphertext.
pub struct Header {
    pub public_key: PublicKey,
    pub pn: u32,
    pub n: u32,
}

impl Header {
    /// Serializes the header into a fixed 40-byte representation.
    ///
    /// Layout: 32-byte ratchet public key || 4-byte pn (big-endian) || 4-byte n (big-endian).
    pub fn serialize(&self) -> [u8; 40] {
        let mut buf = [0u8; 40];
        buf[..32].copy_from_slice(self.public_key.as_bytes());
        buf[32..36].copy_from_slice(&self.pn.to_be_bytes());
        buf[36..40].copy_from_slice(&self.n.to_be_bytes());
        buf
    }
}

/// Session state for the Double Ratchet algorithm between two peers.
pub struct RatchetState {
    /// Sending ratchet key pair.
    dhs: KeyPair,
    /// Receiving ratchet public key. `None` until the first message arrives.
    dhr: Option<PublicKey>,
    /// Root key — evolves with each DH ratchet step.
    rk: RootKey,
    /// Sending chain key. `None` before the first DH ratchet step on the responder side.
    cks: Option<ChainKey>,
    /// Receiving chain key. `None` until the first message is received.
    ckr: Option<ChainKey>,
    /// Number of messages sent in the current sending chain.
    ns: u32,
    /// Number of messages received in the current receiving chain.
    nr: u32,
    /// Number of messages sent in the previous sending chain.
    pn: u32,
    /// Cached message keys for out-of-order decryption, keyed by (sender public key bytes,
    /// message number). `BTreeMap` is used instead of `HashMap` so serialization order is
    /// deterministic — required to satisfy the byte-identical re-serialization contract on
    /// [`RatchetState::to_bytes`]. O(log n) lookups are negligible at the 500-entry cap.
    mk_skipped: BTreeMap<([u8; 32], u32), MessageKey>,
}

impl RatchetState {
    /// Initializes the ratchet as the initiator.
    ///
    /// Generates a fresh key pair, performs the initial DH exchange with `dhr`, and derives the
    /// first sending chain key. The initiator can send immediately after initialization.
    pub fn init_initiator(rk: RootKey, dhr: &PublicKey) -> Result<Self, CryptoError> {
        let dhs = generate_key_pair();
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
        })
    }

    /// Initializes the ratchet as the responder.
    ///
    /// Stores the pre-existing key pair and root key. All chain keys remain `None` until the
    /// first message is received and triggers the DH ratchet step.
    pub fn init_responder(rk: RootKey, dhs: KeyPair) -> Self {
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
        }
    }

    /// Encrypts `plaintext` and returns the message header and ciphertext.
    ///
    /// `ad` should be the associated data of both parties' identity public keys.
    ///
    /// Returns `InvalidState` if the sending chain key is not yet initialized.
    pub fn ratchet_encrypt(
        &mut self,
        plaintext: &[u8],
        ad: &[u8],
    ) -> Result<(Header, Vec<u8>), CryptoError> {
        let cks = self.cks.as_ref().ok_or(CryptoError::InvalidState(
            "sending chain key not initialized",
        ))?;
        let (new_cks, mk) = kdf_ck(cks)?;
        self.cks = Some(new_cks);

        let header = Header {
            public_key: self.dhs.public,
            pn: self.pn,
            n: self.ns,
        };
        self.ns += 1;

        let ciphertext = encrypt(plaintext, ad, &header, &mk)?;
        Ok((header, ciphertext))
    }

    /// Decrypts `ciphertext` using the provided `header` and associated data.
    ///
    /// `ad` must match the associated data provided at encryption time.
    ///
    /// Handles three cases in order:
    /// 1. Out-of-order message — looks up a previously skipped key
    /// 2. New ratchet public key — advances the DH ratchet before decrypting
    /// 3. Normal in-order message — advances the receiving chain
    ///
    /// All state mutations happen on a clone; the original state is only replaced on successful
    /// decryption.
    pub fn ratchet_decrypt(
        &mut self,
        ciphertext: &[u8],
        header: &Header,
        ad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if let Some(plaintext) = self.try_skipped_message_keys(ciphertext, header, ad)? {
            return Ok(plaintext);
        }

        let mut state = self.snapshot();

        if Some(header.public_key) != state.dhr {
            state.skip_message_keys(header.pn)?;
            state.dh_ratchet_step(header)?;
        }

        state.skip_message_keys(header.n)?;

        let ckr = state.ckr.as_ref().ok_or(CryptoError::InvalidState(
            "receiving chain key not set after DH ratchet",
        ))?;
        let (new_ckr, mk) = kdf_ck(ckr)?;
        state.ckr = Some(new_ckr);
        state.nr += 1;

        let plaintext = decrypt(ciphertext, ad, header, &mk)?;

        *self = state;
        Ok(plaintext)
    }

    /// Serializes the session for persistent storage as an opaque blob.
    ///
    /// Callers MUST overwrite the previously stored blob — never append a new entry alongside an
    /// old one. Forward secrecy depends on past states being destroyed on every state change; a
    /// device compromise that recovers stale blobs exposes past message keys.
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
                .map(|(k, v)| (*k, *v.as_bytes()))
                .collect(),
        };
        postcard::to_stdvec(&wire)
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::RatchetStateEncode)
    }

    /// Restores a session from a blob produced by [`Self::to_bytes`].
    ///
    /// Version mismatches return [`CryptoError::UnsupportedRatchetVersion`], structural decode
    /// failures return [`CryptoError::RatchetStateDecode`], and a blob whose `mk_skipped` exceeds
    /// [`MAX_SKIPPED_KEYS_TOTAL`] returns [`CryptoError::MaxSkippedKeysExceeded`] — persisted
    /// blobs are treated as external input so the in-memory cap can't be bypassed by a tampered
    /// or corrupt store.
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
                .map(|(k, v)| (*k, MessageKey(*v)))
                .collect(),
        })
    }

    /// Test-only observability hook for [`mk_skipped`]. Crate-scoped so the production API stays
    /// minimal while integration tests can still assert skipped-key lifecycle behavior.
    #[cfg(test)]
    pub(crate) fn skipped_key_count(&self) -> usize {
        self.mk_skipped.len()
    }

    /// Private to avoid exposing `Clone` on a type holding secret material.
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
        }
    }

    /// Attempts to decrypt using a previously cached skipped message key.
    ///
    /// Re-inserts the key if decryption fails, preventing an attacker from burning legitimate
    /// skipped keys by replaying headers with tampered ciphertext.
    fn try_skipped_message_keys(
        &mut self,
        ciphertext: &[u8],
        header: &Header,
        ad: &[u8],
    ) -> Result<Option<Zeroizing<Vec<u8>>>, CryptoError> {
        let key = (*header.public_key.as_bytes(), header.n);
        if let Some(mk) = self.mk_skipped.remove(&key) {
            match decrypt(ciphertext, ad, header, &mk) {
                Ok(plaintext) => Ok(Some(plaintext)),
                Err(e) => {
                    self.mk_skipped.insert(key, mk);
                    Err(e)
                }
            }
        } else {
            Ok(None)
        }
    }

    /// Advances the receiving chain and caches skipped message keys up to `until_n`.
    fn skip_message_keys(&mut self, until_n: u32) -> Result<(), CryptoError> {
        if until_n > self.nr + MAX_SKIP {
            return Err(CryptoError::MaxSkipExceeded);
        }

        let keys_to_skip = (until_n - self.nr) as usize;
        if self.mk_skipped.len() + keys_to_skip > MAX_SKIPPED_KEYS_TOTAL {
            return Err(CryptoError::MaxSkippedKeysExceeded);
        }

        if let Some(ref ckr) = self.ckr {
            let dhr = self.dhr.ok_or(CryptoError::InvalidState(
                "dhr not set when skipping message keys",
            ))?;
            let mut current_ck = ChainKey::from_bytes(*ckr.as_bytes());
            while self.nr < until_n {
                let (next_ck, mk) = kdf_ck(&current_ck)?;
                self.mk_skipped.insert((*dhr.as_bytes(), self.nr), mk);
                current_ck = next_ck;
                self.nr += 1;
            }
            self.ckr = Some(current_ck);
        }

        Ok(())
    }

    /// Performs a DH ratchet step: updates the DH keys and derives new receiving and sending chains.
    fn dh_ratchet_step(&mut self, header: &Header) -> Result<(), CryptoError> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(header.public_key);

        let dh_recv = self.dhs.diffie_hellman(&header.public_key);
        let (rk, ckr) = kdf_rk(&self.rk, &dh_recv)?;
        self.rk = rk;
        self.ckr = Some(ckr);

        self.dhs = generate_key_pair();
        let dh_send = self.dhs.diffie_hellman(&header.public_key);
        let (rk, cks) = kdf_rk(&self.rk, &dh_send)?;
        self.rk = rk;
        self.cks = Some(cks);

        Ok(())
    }
}

/// Raw-byte serde mirror of [`RatchetState`] for [`RatchetState::to_bytes`] /
/// [`RatchetState::from_bytes`].
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
    mk_skipped: BTreeMap<([u8; 32], u32), [u8; 32]>,
}

/// Manual Drop instead of deriving `ZeroizeOnDrop` — the tuple key `([u8; 32], u32)` doesn't
/// implement `Zeroize`, which blocks the derive.
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
            value.zeroize();
        }
    }
}

impl ZeroizeOnDrop for RatchetStateWire {}

/// Encrypts plaintext with XChaCha20-Poly1305 using a derived encryption key and nonce.
fn encrypt(
    plaintext: &[u8],
    ad: &[u8],
    header: &Header,
    mk: &MessageKey,
) -> Result<Vec<u8>, CryptoError> {
    let (enc_key, nonce) = expand_message_key(mk)?;
    let cipher = XChaCha20Poly1305::new((&*enc_key).into());
    let full_ad = build_full_ad(ad, header);
    let payload = Payload {
        msg: plaintext,
        aad: &full_ad,
    };
    cipher
        .encrypt(XNonce::from_slice(&nonce), payload)
        .map_err(|_| CryptoError::Aead)
}

/// Decrypts ciphertext with XChaCha20-Poly1305 using a derived encryption key and nonce.
fn decrypt(
    ciphertext: &[u8],
    ad: &[u8],
    header: &Header,
    mk: &MessageKey,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let (enc_key, nonce) = expand_message_key(mk)?;
    let cipher = XChaCha20Poly1305::new((&*enc_key).into());
    let full_ad = build_full_ad(ad, header);
    let payload = Payload {
        msg: ciphertext,
        aad: &full_ad,
    };
    cipher
        .decrypt(XNonce::from_slice(&nonce), payload)
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Aead)
}

/// Expands a message key into a 32-byte encryption key and 24-byte nonce via HKDF-SHA256.
fn expand_message_key(mk: &MessageKey) -> Result<(Zeroizing<[u8; 32]>, [u8; 24]), CryptoError> {
    // MK is already pseudo-random from the chain KDF, so no salt is needed (RFC 5869 §3.1).
    let hkdf = Hkdf::<Sha256>::new(None, mk.as_bytes());
    let mut okm = Zeroizing::new([0u8; 56]);
    hkdf.expand(HKDF_MK_INFO, okm.as_mut())
        .map_err(|_| CryptoError::HkdfExpand)?;

    let mut enc_key = Zeroizing::new([0u8; 32]);
    let mut nonce = [0u8; 24];
    enc_key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..56]);

    Ok((enc_key, nonce))
}

/// Builds the full associated data: caller-provided AD concatenated with the serialized header.
fn build_full_ad(ad: &[u8], header: &Header) -> Vec<u8> {
    let serialized = header.serialize();
    let mut full_ad = Vec::with_capacity(ad.len() + serialized.len());
    full_ad.extend_from_slice(ad);
    full_ad.extend_from_slice(&serialized);
    full_ad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_key_pair;
    use crate::ratchet::RootKey;

    /// The libsodium-reference ciphertext for the fixed AEAD KAT inputs.
    ///
    /// Referenced by both [`aead_encrypt_known_answer`] and [`aead_decrypt_known_answer`], so the
    /// two tests cannot drift silently if one is regenerated without the other.
    const AEAD_KAT_EXPECTED_CIPHERTEXT: [u8; 44] = [
        0x91, 0x16, 0x40, 0xd9, 0xfd, 0xe7, 0xe2, 0xea, 0x55, 0x82, 0xd5, 0x28, 0xd8, 0x6c, 0x14,
        0x7a, 0xab, 0xe0, 0x97, 0x1b, 0xd6, 0x6c, 0xe1, 0x92, 0x0b, 0x2d, 0x98, 0x59, 0x43, 0x13,
        0xe5, 0xbf, 0xd0, 0x8e, 0xdf, 0x7e, 0xec, 0xbf, 0x8a, 0xe2, 0x2a, 0x21, 0x42, 0x9d,
    ];

    /// Returns a fresh initiator/responder pair with shared associated data.
    fn setup_pair() -> (RatchetState, RatchetState, Vec<u8>) {
        let shared_secret = [0x42u8; 32];
        let responder_keypair = generate_key_pair();
        let responder_public = responder_keypair.public;

        let initiator =
            RatchetState::init_initiator(RootKey::from_bytes(shared_secret), &responder_public)
                .unwrap();
        let responder =
            RatchetState::init_responder(RootKey::from_bytes(shared_secret), responder_keypair);
        let ad = b"initiator_identity||responder_identity".to_vec();
        (initiator, responder, ad)
    }

    #[test]
    fn header_serialize_round_trip() {
        let kp = generate_key_pair();
        let header = Header {
            public_key: kp.public,
            pn: 42,
            n: 7,
        };

        let buf = header.serialize();
        assert_eq!(&buf[..32], kp.public.as_bytes());
        assert_eq!(u32::from_be_bytes(buf[32..36].try_into().unwrap()), 42);
        assert_eq!(u32::from_be_bytes(buf[36..40].try_into().unwrap()), 7);
    }

    #[test]
    fn init_initiator_sets_sending_chain() {
        let shared_secret = [0xAA; 32];
        let responder_keypair = generate_key_pair();
        let initiator = RatchetState::init_initiator(
            RootKey::from_bytes(shared_secret),
            &responder_keypair.public,
        )
        .unwrap();

        assert!(initiator.dhr.is_some());
        assert!(initiator.cks.is_some());
        assert!(initiator.ckr.is_none());
        assert_eq!(initiator.ns, 0);
        assert_eq!(initiator.nr, 0);
        assert_eq!(initiator.pn, 0);
    }

    #[test]
    fn init_responder_has_no_chains() {
        let shared_secret = [0xBB; 32];
        let responder_keypair = generate_key_pair();
        let responder =
            RatchetState::init_responder(RootKey::from_bytes(shared_secret), responder_keypair);

        assert!(responder.dhr.is_none());
        assert!(responder.cks.is_none());
        assert!(responder.ckr.is_none());
        assert_eq!(responder.ns, 0);
        assert_eq!(responder.nr, 0);
        assert_eq!(responder.pn, 0);
    }

    #[test]
    fn responder_encrypt_before_receiving_fails() {
        let (_, mut responder, ad) = setup_pair();

        let result = responder.ratchet_encrypt(b"premature send", &ad);
        assert!(matches!(result, Err(CryptoError::InvalidState(_))));
    }

    #[test]
    fn basic_exchange() {
        let (mut initiator, mut responder, ad) = setup_pair();

        let message = b"hello responder";
        let (header, ciphertext) = initiator.ratchet_encrypt(message, &ad).unwrap();
        let plaintext = responder
            .ratchet_decrypt(&ciphertext, &header, &ad)
            .unwrap();
        assert_eq!(plaintext.as_slice(), message);
    }

    #[test]
    fn each_message_has_unique_ciphertext() {
        let (mut initiator, _, ad) = setup_pair();

        let plaintext = b"same plaintext";
        let (_, ct1) = initiator.ratchet_encrypt(plaintext, &ad).unwrap();
        let (_, ct2) = initiator.ratchet_encrypt(plaintext, &ad).unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn ping_pong_exchange() {
        let (mut initiator, mut responder, ad) = setup_pair();

        let m1 = b"message 1";
        let (h1, ct1) = initiator.ratchet_encrypt(m1, &ad).unwrap();
        let pt1 = responder.ratchet_decrypt(&ct1, &h1, &ad).unwrap();
        assert_eq!(pt1.as_slice(), m1);

        let m2 = b"message 2";
        let (h2, ct2) = responder.ratchet_encrypt(m2, &ad).unwrap();
        let pt2 = initiator.ratchet_decrypt(&ct2, &h2, &ad).unwrap();
        assert_eq!(pt2.as_slice(), m2);

        let m3 = b"message 3";
        let (h3, ct3) = initiator.ratchet_encrypt(m3, &ad).unwrap();
        let pt3 = responder.ratchet_decrypt(&ct3, &h3, &ad).unwrap();
        assert_eq!(pt3.as_slice(), m3);

        let m4 = b"message 4";
        let (h4, ct4) = responder.ratchet_encrypt(m4, &ad).unwrap();
        let pt4 = initiator.ratchet_decrypt(&ct4, &h4, &ad).unwrap();
        assert_eq!(pt4.as_slice(), m4);
    }

    #[test]
    fn multiple_messages_same_direction() {
        let (mut initiator, mut responder, ad) = setup_pair();

        let m1 = b"msg 1";
        let m2 = b"msg 2";
        let m3 = b"msg 3";
        let (h1, ct1) = initiator.ratchet_encrypt(m1, &ad).unwrap();
        let (h2, ct2) = initiator.ratchet_encrypt(m2, &ad).unwrap();
        let (h3, ct3) = initiator.ratchet_encrypt(m3, &ad).unwrap();

        let pt1 = responder.ratchet_decrypt(&ct1, &h1, &ad).unwrap();
        let pt2 = responder.ratchet_decrypt(&ct2, &h2, &ad).unwrap();
        let pt3 = responder.ratchet_decrypt(&ct3, &h3, &ad).unwrap();

        assert_eq!(pt1.as_slice(), m1);
        assert_eq!(pt2.as_slice(), m2);
        assert_eq!(pt3.as_slice(), m3);
    }

    #[test]
    fn out_of_order_delivery() {
        let (mut initiator, mut responder, ad) = setup_pair();

        let m1 = b"msg 1";
        let m2 = b"msg 2";
        let m3 = b"msg 3";
        let (h1, ct1) = initiator.ratchet_encrypt(m1, &ad).unwrap();
        let (h2, ct2) = initiator.ratchet_encrypt(m2, &ad).unwrap();
        let (h3, ct3) = initiator.ratchet_encrypt(m3, &ad).unwrap();

        let pt3 = responder.ratchet_decrypt(&ct3, &h3, &ad).unwrap();
        let pt2 = responder.ratchet_decrypt(&ct2, &h2, &ad).unwrap();
        let pt1 = responder.ratchet_decrypt(&ct1, &h1, &ad).unwrap();

        assert_eq!(pt1.as_slice(), m1);
        assert_eq!(pt2.as_slice(), m2);
        assert_eq!(pt3.as_slice(), m3);
    }

    #[test]
    fn max_skip_enforced() {
        let (mut initiator, mut responder, ad) = setup_pair();

        let mut headers_and_cts = Vec::new();
        for i in 0..MAX_SKIP + 2 {
            let (h, ct) = initiator
                .ratchet_encrypt(format!("msg {i}").as_bytes(), &ad)
                .unwrap();
            headers_and_cts.push((h, ct));
        }

        let (ref h, ref ct) = headers_and_cts[(MAX_SKIP + 1) as usize];
        let result = responder.ratchet_decrypt(ct, h, &ad);
        assert!(matches!(result, Err(CryptoError::MaxSkipExceeded)));
    }

    #[test]
    fn max_skipped_keys_enforced() {
        let (mut initiator, mut responder, ad) = setup_pair();

        let overflow_step = MAX_SKIPPED_KEYS_TOTAL as u32 / MAX_SKIP;
        assert_eq!(
            overflow_step as usize * MAX_SKIP as usize,
            MAX_SKIPPED_KEYS_TOTAL,
            "test assumes MAX_SKIPPED_KEYS_TOTAL is an exact multiple of MAX_SKIP"
        );
        for step in 0..=overflow_step {
            let mut headers_and_cts = Vec::new();
            for i in 0..=MAX_SKIP {
                let (h, ct) = initiator
                    .ratchet_encrypt(format!("step {step} msg {i}").as_bytes(), &ad)
                    .unwrap();
                headers_and_cts.push((h, ct));
            }

            let (ref h, ref ct) = headers_and_cts[MAX_SKIP as usize];
            if step == overflow_step {
                assert!(matches!(
                    responder.ratchet_decrypt(ct, h, &ad),
                    Err(CryptoError::MaxSkippedKeysExceeded)
                ));
            } else {
                responder.ratchet_decrypt(ct, h, &ad).unwrap();
                let (rh, rct) = responder.ratchet_encrypt(b"reply", &ad).unwrap();
                initiator.ratchet_decrypt(&rct, &rh, &ad).unwrap();
            }
        }
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (mut initiator, mut responder, ad) = setup_pair();

        let (header, mut ciphertext) = initiator.ratchet_encrypt(b"secret", &ad).unwrap();
        ciphertext[0] ^= 0xFF;

        let result = responder.ratchet_decrypt(&ciphertext, &header, &ad);
        assert!(matches!(result, Err(CryptoError::Aead)));
    }

    #[test]
    fn tampered_ad_fails() {
        let (mut initiator, mut responder, ad) = setup_pair();

        let (header, ciphertext) = initiator.ratchet_encrypt(b"secret", &ad).unwrap();
        let wrong_ad = b"wrong_identity_keys";

        let result = responder.ratchet_decrypt(&ciphertext, &header, wrong_ad);
        assert!(matches!(result, Err(CryptoError::Aead)));
    }

    #[test]
    fn state_rollback_on_failed_decrypt() {
        let (mut initiator, mut responder, ad) = setup_pair();

        let (h1, ct1) = initiator.ratchet_encrypt(b"msg 1", &ad).unwrap();
        responder.ratchet_decrypt(&ct1, &h1, &ad).unwrap();

        let nr_before = responder.nr;
        let ns_before = responder.ns;
        let skipped_count_before = responder.mk_skipped.len();

        let (h2, mut ct2) = initiator.ratchet_encrypt(b"msg 2", &ad).unwrap();
        ct2[0] ^= 0xFF;
        let result = responder.ratchet_decrypt(&ct2, &h2, &ad);
        assert!(matches!(result, Err(CryptoError::Aead)));

        assert_eq!(responder.nr, nr_before);
        assert_eq!(responder.ns, ns_before);
        assert_eq!(responder.mk_skipped.len(), skipped_count_before);

        let m2 = b"msg 2 retry";
        let (h2_real, ct2_real) = initiator.ratchet_encrypt(m2, &ad).unwrap();
        let pt = responder.ratchet_decrypt(&ct2_real, &h2_real, &ad).unwrap();
        assert_eq!(pt.as_slice(), m2);
    }

    #[test]
    fn to_bytes_round_trip_is_byte_identical() {
        let (initiator, _, _) = setup_pair();
        let bytes1 = initiator.to_bytes().unwrap();
        let restored = RatchetState::from_bytes(&bytes1).unwrap();
        let bytes2 = restored.to_bytes().unwrap();
        assert_eq!(&*bytes1, &*bytes2);
    }

    #[test]
    fn restored_state_continues_session() {
        let (mut initiator, mut responder, ad) = setup_pair();

        let (h1, ct1) = initiator.ratchet_encrypt(b"msg 1", &ad).unwrap();
        responder.ratchet_decrypt(&ct1, &h1, &ad).unwrap();

        let bytes = initiator.to_bytes().unwrap();
        drop(initiator);
        let mut restored = RatchetState::from_bytes(&bytes).unwrap();

        let (h2, ct2) = restored.ratchet_encrypt(b"msg 2", &ad).unwrap();
        let pt = responder.ratchet_decrypt(&ct2, &h2, &ad).unwrap();
        assert_eq!(pt.as_slice(), b"msg 2");
    }

    #[test]
    fn mk_skipped_survives_round_trip() {
        let (mut initiator, mut responder, ad) = setup_pair();

        let (h1, ct1) = initiator.ratchet_encrypt(b"msg 1", &ad).unwrap();
        let (h2, ct2) = initiator.ratchet_encrypt(b"msg 2", &ad).unwrap();
        let (h3, ct3) = initiator.ratchet_encrypt(b"msg 3", &ad).unwrap();

        responder.ratchet_decrypt(&ct1, &h1, &ad).unwrap();
        responder.ratchet_decrypt(&ct3, &h3, &ad).unwrap();
        assert!(!responder.mk_skipped.is_empty());

        let bytes = responder.to_bytes().unwrap();
        drop(responder);
        let mut restored = RatchetState::from_bytes(&bytes).unwrap();

        let pt = restored.ratchet_decrypt(&ct2, &h2, &ad).unwrap();
        assert_eq!(pt.as_slice(), b"msg 2");
    }

    #[test]
    fn from_bytes_rejects_unsupported_version() {
        let (initiator, _, _) = setup_pair();
        let mut bytes = initiator.to_bytes().unwrap().to_vec();
        bytes[0] = 0xFF;
        assert!(matches!(
            RatchetState::from_bytes(&bytes),
            Err(CryptoError::UnsupportedRatchetVersion(0xFF))
        ));
    }

    #[test]
    fn from_bytes_rejects_malformed_blob() {
        let (initiator, _, _) = setup_pair();
        let bytes = initiator.to_bytes().unwrap();
        let truncated = &bytes[..1];
        assert!(matches!(
            RatchetState::from_bytes(truncated),
            Err(CryptoError::RatchetStateDecode)
        ));
    }

    #[test]
    fn from_bytes_rejects_oversized_mk_skipped() {
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
                .map(|i| (([0; 32], i), [0; 32]))
                .collect(),
        };
        let bytes = postcard::to_stdvec(&oversized).unwrap();
        assert!(matches!(
            RatchetState::from_bytes(&bytes),
            Err(CryptoError::MaxSkippedKeysExceeded)
        ));
    }

    /// Known-answer test for [`expand_message_key`].
    ///
    /// Inputs: `mk = MessageKey([0; 32])`.
    ///
    /// Algorithm: HKDF-SHA256(salt = None, ikm = mk, info = [`HKDF_MK_INFO`], L = 56).
    /// Output split: `okm[0..32] = enc_key`, `okm[32..56] = nonce` (24-byte XNonce).
    ///
    /// Expected values derived with pyca/cryptography 46 (HKDF-SHA256).
    #[test]
    fn expand_message_key_known_answer() {
        const EXPECTED_ENC_KEY: [u8; 32] = [
            0x59, 0x97, 0xfd, 0xfa, 0x34, 0xf8, 0x50, 0x6f, 0xe9, 0xdd, 0x5a, 0x04, 0x63, 0x2f,
            0x66, 0x23, 0xff, 0xc1, 0x7f, 0x89, 0x80, 0x0b, 0xbc, 0x33, 0x5b, 0xa1, 0xbc, 0xa9,
            0x69, 0x2c, 0x61, 0x5b,
        ];
        const EXPECTED_NONCE: [u8; 24] = [
            0x24, 0xa8, 0xcc, 0x09, 0x24, 0x67, 0xef, 0xa0, 0x06, 0x9e, 0xb9, 0x58, 0x64, 0x4f,
            0x82, 0x58, 0x88, 0x58, 0x95, 0xad, 0x2e, 0x20, 0x1b, 0x80,
        ];

        let mk = MessageKey([0u8; 32]);
        let (enc_key, nonce) = expand_message_key(&mk).unwrap();

        assert_eq!(enc_key.as_slice(), &EXPECTED_ENC_KEY);
        assert_eq!(nonce, EXPECTED_NONCE);
    }

    /// Known-answer test for [`encrypt`] (XChaCha20-Poly1305 with header AD).
    ///
    /// Inputs:
    /// - `mk = MessageKey([0; 32])` (`enc_key` and `nonce` match
    ///   [`expand_message_key_known_answer`]).
    /// - `plaintext = b"Hermes test vector plaintext"` (28 bytes).
    /// - `caller_ad = b"initiator_identity||responder_identity"`.
    /// - `header.public_key = KeyPair::from_secret_bytes([0x99; 32]).public` — the stored public
    ///   is the X25519-clamped scalar multiplication result, not the raw input bytes.
    /// - `header.pn = 0`, `header.n = 0`.
    ///
    /// AD construction: `full_ad = caller_ad || header.serialize()`, where `serialize`
    /// emits `public_key (32) || pn_be (4) || n_be (4)` (big-endian u32 counters; see
    /// [`Header::serialize`]). A byte-order refactor of the header would silently invalidate
    /// this vector.
    ///
    /// Expected ciphertext derived with libsodium (pynacl 1.5's
    /// `crypto_aead_xchacha20poly1305_ietf_encrypt`) — deliberately a different implementation
    /// than the RustCrypto `chacha20poly1305` crate under test.
    ///
    /// The decrypt direction has a paired KAT at [`aead_decrypt_known_answer`].
    #[test]
    fn aead_encrypt_known_answer() {
        let mk = MessageKey([0u8; 32]);
        let plaintext = b"Hermes test vector plaintext";
        let caller_ad = b"initiator_identity||responder_identity";
        let header = Header {
            public_key: KeyPair::from_secret_bytes([0x99u8; 32]).public,
            pn: 0,
            n: 0,
        };

        let ciphertext = encrypt(plaintext, caller_ad, &header, &mk).unwrap();
        assert_eq!(ciphertext.as_slice(), &AEAD_KAT_EXPECTED_CIPHERTEXT);
    }

    /// Known-answer test for [`decrypt`] (XChaCha20-Poly1305 with header AD).
    ///
    /// Inputs: the same `mk`, `caller_ad`, and `header` as [`aead_encrypt_known_answer`], with
    /// [`AEAD_KAT_EXPECTED_CIPHERTEXT`] as the ciphertext input.
    ///
    /// Covers the class of bug where `encrypt` and `decrypt` share a matching fault (e.g., a
    /// future refactor of `build_full_ad` affecting both call sites) — round-trip tests would
    /// pass in that case because both sides agree. This KAT catches the divergence from
    /// libsodium's reference.
    #[test]
    fn aead_decrypt_known_answer() {
        let mk = MessageKey([0u8; 32]);
        let expected_plaintext = b"Hermes test vector plaintext";
        let caller_ad = b"initiator_identity||responder_identity";
        let header = Header {
            public_key: KeyPair::from_secret_bytes([0x99u8; 32]).public,
            pn: 0,
            n: 0,
        };

        let recovered = decrypt(&AEAD_KAT_EXPECTED_CIPHERTEXT, caller_ad, &header, &mk).unwrap();
        assert_eq!(recovered.as_slice(), expected_plaintext);
    }
}
