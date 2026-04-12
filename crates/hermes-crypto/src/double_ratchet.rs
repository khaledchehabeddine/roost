use crate::error::CryptoError;
use crate::keys::{KeyPair, PublicKey, generate_key_pair};
use crate::ratchet::{ChainKey, MessageKey, RootKey, kdf_ck, kdf_rk};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::HashMap;
use zeroize::Zeroizing;

const MAX_SKIP: u32 = 100;
const HKDF_MK_INFO: &[u8] = b"HermesRatchet_MK";

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
///
/// Holds the DH ratchet key pairs, chain keys, message counters, and a cache of skipped message
/// keys for handling out-of-order delivery.
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
    /// Cached message keys for out-of-order decryption, keyed by (sender public key, message number).
    mk_skipped: HashMap<(PublicKey, u32), MessageKey>,
}

impl Clone for RatchetState {
    fn clone(&self) -> Self {
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
}

impl RatchetState {
    /// Initializes the ratchet as the initiator.
    ///
    /// Generates a fresh key pair, performs the initial DH exchange with `dhr`, and derives the
    /// first sending chain key. The initiator can send immediately after init.
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
            mk_skipped: HashMap::new(),
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
            mk_skipped: HashMap::new(),
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
        let cks = self
            .cks
            .as_ref()
            .ok_or(CryptoError::InvalidState("sending chain key not initialized"))?;
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
    ) -> Result<Vec<u8>, CryptoError> {
        if let Some(plaintext) = self.try_skipped_message_keys(ciphertext, header, ad)? {
            return Ok(plaintext);
        }

        let mut state = self.clone();

        if Some(header.public_key) != state.dhr {
            state.skip_message_keys(state.pn)?;
            state.dh_ratchet_step(header)?;
        }

        state.skip_message_keys(header.n)?;

        let ckr = state
            .ckr
            .as_ref()
            .ok_or(CryptoError::InvalidState("receiving chain key not set after DH ratchet"))?;
        let (new_ckr, mk) = kdf_ck(ckr)?;
        state.ckr = Some(new_ckr);
        state.nr += 1;

        let plaintext = decrypt(ciphertext, ad, header, &mk)?;

        *self = state;
        Ok(plaintext)
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
    ) -> Result<Option<Vec<u8>>, CryptoError> {
        let key = (header.public_key, header.n);
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

        if let Some(ref ckr) = self.ckr {
            let dhr = self
                .dhr
                .ok_or(CryptoError::InvalidState("dhr not set when skipping message keys"))?;
            let mut current_ck = ChainKey::from_bytes(*ckr.as_bytes());
            while self.nr < until_n {
                let (next_ck, mk) = kdf_ck(&current_ck)?;
                self.mk_skipped.insert((dhr, self.nr), mk);
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

        let dh_recv = self
            .dhs
            .diffie_hellman(&header.public_key);
        let (rk, ckr) = kdf_rk(&self.rk, &dh_recv)?;
        self.rk = rk;
        self.ckr = Some(ckr);

        self.dhs = generate_key_pair();
        let dh_send = self
            .dhs
            .diffie_hellman(&header.public_key);
        let (rk, cks) = kdf_rk(&self.rk, &dh_send)?;
        self.rk = rk;
        self.cks = Some(cks);

        Ok(())
    }
}

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
) -> Result<Vec<u8>, CryptoError> {
    let (enc_key, nonce) = expand_message_key(mk)?;
    let cipher = XChaCha20Poly1305::new((&*enc_key).into());
    let full_ad = build_full_ad(ad, header);
    let payload = Payload {
        msg: ciphertext,
        aad: &full_ad,
    };
    cipher
        .decrypt(XNonce::from_slice(&nonce), payload)
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

    /// Sets up an initiator/responder pair with a shared secret and returns (initiator, responder, ad).
    fn setup_pair() -> (RatchetState, RatchetState, Vec<u8>) {
        let shared_secret = [0x42u8; 32];
        let responder_keypair = generate_key_pair();
        let responder_public = responder_keypair.public;

        let initiator =
            RatchetState::init_initiator(RootKey::from_bytes(shared_secret), &responder_public).unwrap();
        let responder= RatchetState::init_responder(
            RootKey::from_bytes(shared_secret),
            responder_keypair,
        );

        let ad = b"initiator_identity||responder_identity".to_vec();
        (initiator, responder, ad)
    }

    #[test]
    fn init_initiator_sets_sending_chain() {
        let shared_secret = [0xAA; 32];
        let responder_keypair = generate_key_pair();
        let initiator =
            RatchetState::init_initiator(RootKey::from_bytes(shared_secret), &responder_keypair.public)
                .unwrap();

        assert!(initiator.cks.is_some());
        assert!(initiator.ckr.is_none());
        assert!(initiator.dhr.is_some());
        assert_eq!(initiator.ns, 0);
        assert_eq!(initiator.nr, 0);
        assert_eq!(initiator.pn, 0);
    }

    #[test]
    fn init_responder_has_no_chains() {
        let shared_secret = [0xBB; 32];
        let responder_keypair = generate_key_pair();
        let responder= RatchetState::init_responder(RootKey::from_bytes(shared_secret), responder_keypair);

        assert!(responder.cks.is_none());
        assert!(responder.ckr.is_none());
        assert!(responder.dhr.is_none());
        assert_eq!(responder.ns, 0);
        assert_eq!(responder.nr, 0);
        assert_eq!(responder.pn, 0);
    }

    #[test]
    fn basic_exchange() {
        let (mut initiator, mut responder, ad) = setup_pair();

        let (header, ciphertext) = initiator.ratchet_encrypt(b"hello responder", &ad).unwrap();
        let plaintext = responder.ratchet_decrypt(&ciphertext, &header, &ad).unwrap();
        assert_eq!(plaintext, b"hello responder");
    }

    #[test]
    fn ping_pong_exchange() {
        let (mut initiator, mut responder, ad) = setup_pair();

        // Initiator → Responder
        let (h1, ct1) = initiator.ratchet_encrypt(b"message 1", &ad).unwrap();
        let pt1 = responder.ratchet_decrypt(&ct1, &h1, &ad).unwrap();
        assert_eq!(pt1, b"message 1");

        // Responder → Initiator
        let (h2, ct2) = responder.ratchet_encrypt(b"message 2", &ad).unwrap();
        let pt2 = initiator.ratchet_decrypt(&ct2, &h2, &ad).unwrap();
        assert_eq!(pt2, b"message 2");

        // Initiator → Responder again
        let (h3, ct3) = initiator.ratchet_encrypt(b"message 3", &ad).unwrap();
        let pt3 = responder.ratchet_decrypt(&ct3, &h3, &ad).unwrap();
        assert_eq!(pt3, b"message 3");

        // Responder → Initiator again
        let (h4, ct4) = responder.ratchet_encrypt(b"message 4", &ad).unwrap();
        let pt4 = initiator.ratchet_decrypt(&ct4, &h4, &ad).unwrap();
        assert_eq!(pt4, b"message 4");
    }

    #[test]
    fn multiple_messages_same_direction() {
        let (mut initiator, mut responder, ad) = setup_pair();

        let (h1, ct1) = initiator.ratchet_encrypt(b"msg 1", &ad).unwrap();
        let (h2, ct2) = initiator.ratchet_encrypt(b"msg 2", &ad).unwrap();
        let (h3, ct3) = initiator.ratchet_encrypt(b"msg 3", &ad).unwrap();

        let pt1 = responder.ratchet_decrypt(&ct1, &h1, &ad).unwrap();
        let pt2 = responder.ratchet_decrypt(&ct2, &h2, &ad).unwrap();
        let pt3 = responder.ratchet_decrypt(&ct3, &h3, &ad).unwrap();

        assert_eq!(pt1, b"msg 1");
        assert_eq!(pt2, b"msg 2");
        assert_eq!(pt3, b"msg 3");
    }

    #[test]
    fn out_of_order_delivery() {
        let (mut initiator, mut responder, ad) = setup_pair();

        let (h1, ct1) = initiator.ratchet_encrypt(b"msg 1", &ad).unwrap();
        let (h2, ct2) = initiator.ratchet_encrypt(b"msg 2", &ad).unwrap();
        let (h3, ct3) = initiator.ratchet_encrypt(b"msg 3", &ad).unwrap();

        // Deliver in reverse order
        let pt3 = responder.ratchet_decrypt(&ct3, &h3, &ad).unwrap();
        let pt1 = responder.ratchet_decrypt(&ct1, &h1, &ad).unwrap();
        let pt2 = responder.ratchet_decrypt(&ct2, &h2, &ad).unwrap();

        assert_eq!(pt1, b"msg 1");
        assert_eq!(pt2, b"msg 2");
        assert_eq!(pt3, b"msg 3");
    }

    #[test]
    fn max_skip_exceeded() {
        let (mut initiator, mut responder, ad) = setup_pair();

        // Send MAX_SKIP + 2 messages without responder receiving any
        let mut headers_and_cts = Vec::new();
        for i in 0..MAX_SKIP + 2 {
            let (h, ct) = initiator
                .ratchet_encrypt(format!("msg {i}").as_bytes(), &ad)
                .unwrap();
            headers_and_cts.push((h, ct));
        }

        // Decrypting the last message requires skipping MAX_SKIP + 1 keys → error
        let (ref h, ref ct) = headers_and_cts[(MAX_SKIP + 1) as usize];
        let result = responder.ratchet_decrypt(ct, h, &ad);
        assert!(matches!(result, Err(CryptoError::MaxSkipExceeded)));
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

        // Successful decrypt to establish receiving chain
        let (h1, ct1) = initiator.ratchet_encrypt(b"msg 1", &ad).unwrap();
        responder.ratchet_decrypt(&ct1, &h1, &ad).unwrap();

        // Snapshot responder's counters before failed attempt
        let nr_before = responder.nr;
        let ns_before = responder.ns;
        let skipped_count_before = responder.mk_skipped.len();

        // Tampered ciphertext → should fail and rollback
        let (h2, mut ct2) = initiator.ratchet_encrypt(b"msg 2", &ad).unwrap();
        ct2[0] ^= 0xFF;
        let result = responder.ratchet_decrypt(&ct2, &h2, &ad);
        assert!(matches!(result, Err(CryptoError::Aead)));

        // State must be unchanged
        assert_eq!(responder.nr, nr_before);
        assert_eq!(responder.ns, ns_before);
        assert_eq!(responder.mk_skipped.len(), skipped_count_before);

        // Responder can still decrypt the real message
        let (h2_real, ct2_real) = initiator.ratchet_encrypt(b"msg 2 retry", &ad).unwrap();
        let pt = responder.ratchet_decrypt(&ct2_real, &h2_real, &ad).unwrap();
        assert_eq!(pt, b"msg 2 retry");
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
    fn each_message_has_unique_ciphertext() {
        let (mut initiator, _, ad) = setup_pair();

        let (_, ct1) = initiator.ratchet_encrypt(b"same plaintext", &ad).unwrap();
        let (_, ct2) = initiator.ratchet_encrypt(b"same plaintext", &ad).unwrap();
        assert_ne!(ct1, ct2);
    }
}
