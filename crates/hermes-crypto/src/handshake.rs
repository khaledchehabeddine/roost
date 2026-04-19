use crate::double_ratchet::{Header, RatchetState};
use crate::error::CryptoError;
use crate::keys::{KeyPair, PublicKey, VerifyingKey, generate_key_pair};
use crate::ratchet::RootKey;
use crate::signed_prekey::{PreKeyBundle, SignedPreKey, verify_bundle};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Signal-spec F prefix. Removes any cross-interpretation between curve25519 scalars and
/// Ed25519 encodings at the HKDF input boundary.
const F_PREFIX: [u8; 32] = [0xFF; 32];
/// Domain separator so SK cannot collide with any other HKDF output in this crate.
const HKDF_INFO: &[u8] = b"HermesX3DHLite";
/// `F || DH1 || DH2 || DH3` — 32 bytes each, 128 bytes total.
const IKM_LEN: usize = 32 * 4;
/// SK output length — matches [`RootKey`] width.
const SK_LEN: usize = 32;

/// Wire form of an X3DH-lite handshake initiation. Carries only public material and the
/// first ratcheted ciphertext, so no zeroize derives are needed.
///
/// The ratchet header is represented as its three constituent fields rather than a single
/// 40-byte array — serde's built-in [T; N] impl only covers N ≤ 32.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeEnvelope {
    pub initiator_ik: [u8; 32],
    pub initiator_ek: [u8; 32],
    pub responder_spk_ref: [u8; 32],
    pub ratchet_pk: [u8; 32],
    pub pn: u32,
    pub n: u32,
    pub ciphertext: Vec<u8>,
}

/// Associated data for the first ratcheted message: initiator X25519 IK pubkey, then
/// responder X25519 IK pubkey. Both sides reconstruct the same 64-byte sequence.
#[must_use]
pub fn initial_ad(initiator_ik: &PublicKey, responder_ik: &PublicKey) -> [u8; 64] {
    let mut ad = [0u8; 64];
    ad[..32].copy_from_slice(initiator_ik.as_bytes());
    ad[32..].copy_from_slice(responder_ik.as_bytes());
    ad
}

/// Initiator-side SK derivation. Three DHs composed into one HKDF run:
/// `DH1 = IK_A·SPK_B`, `DH2 = EK_A·IK_B`, `DH3 = EK_A·SPK_B`.
pub fn derive_sk_initiator(
    ik_a: &KeyPair,
    ek_a: &KeyPair,
    ik_b_pub: &PublicKey,
    spk_b_pub: &PublicKey,
) -> Result<RootKey, CryptoError> {
    let dh1 = ik_a.diffie_hellman(spk_b_pub);
    let dh2 = ek_a.diffie_hellman(ik_b_pub);
    let dh3 = ek_a.diffie_hellman(spk_b_pub);

    let mut ikm: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(IKM_LEN));
    ikm.extend_from_slice(&F_PREFIX);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());

    hkdf_sk_from_ikm(&ikm)
}

/// Responder-side SK derivation. Mirrors [`derive_sk_initiator`] with the complementary
/// halves of each DH: `DH1 = SPK_B·IK_A`, `DH2 = IK_B·EK_A`, `DH3 = SPK_B·EK_A`. Must
/// produce identical output for matched inputs.
pub fn derive_sk_responder(
    ik_a_pub: &PublicKey,
    ek_a_pub: &PublicKey,
    ik_b: &KeyPair,
    spk_b: &SignedPreKey,
) -> Result<RootKey, CryptoError> {
    let dh1 = spk_b.diffie_hellman(ik_a_pub);
    let dh2 = ik_b.diffie_hellman(ek_a_pub);
    let dh3 = spk_b.diffie_hellman(ek_a_pub);

    let mut ikm: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(IKM_LEN));
    ikm.extend_from_slice(&F_PREFIX);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());

    hkdf_sk_from_ikm(&ikm)
}

/// Full initiator flow: verify the peer's bundle, derive SK, seed the ratchet, encrypt
/// the first message, and assemble the envelope.
pub fn initiate(
    own_ik: &KeyPair,
    peer_ik_vk: &VerifyingKey,
    peer_ik_x25519: &PublicKey,
    peer_bundle: &PreKeyBundle,
    plaintext: &[u8],
) -> Result<(RatchetState, HandshakeEnvelope), CryptoError> {
    verify_bundle(peer_bundle, peer_ik_vk)?;

    let ek_a = generate_key_pair();
    let spk_b_pub = peer_bundle.public_key;

    let sk = derive_sk_initiator(own_ik, &ek_a, peer_ik_x25519, &spk_b_pub)?;
    let mut state = RatchetState::init_initiator(sk, &spk_b_pub)?;

    let ad = initial_ad(&own_ik.public, peer_ik_x25519);
    let (header, ciphertext) = state.ratchet_encrypt(plaintext, &ad)?;

    let envelope = HandshakeEnvelope {
        initiator_ik: *own_ik.public.as_bytes(),
        initiator_ek: *ek_a.public.as_bytes(),
        responder_spk_ref: *spk_b_pub.as_bytes(),
        ratchet_pk: *header.public_key.as_bytes(),
        pn: header.pn,
        n: header.n,
        ciphertext,
    };

    Ok((state, envelope))
}

/// Full responder flow: constant-time match the envelope's SPK ref, derive SK, seed the
/// ratchet, and decrypt the first message.
pub fn accept(
    envelope: &HandshakeEnvelope,
    own_ik: &KeyPair,
    own_spk: &SignedPreKey,
) -> Result<(RatchetState, Zeroizing<Vec<u8>>), CryptoError> {
    let spk_ref_matches: bool = envelope
        .responder_spk_ref
        .ct_eq(own_spk.public().as_bytes())
        .into();
    if !spk_ref_matches {
        return Err(CryptoError::HandshakeSpkMismatch);
    }

    let initiator_ik_pub = PublicKey::from(envelope.initiator_ik);
    let initiator_ek_pub = PublicKey::from(envelope.initiator_ek);

    let sk = derive_sk_responder(&initiator_ik_pub, &initiator_ek_pub, own_ik, own_spk)?;

    let spk_keypair = KeyPair::from_secret_bytes(*own_spk.to_secret_bytes());
    let mut state = RatchetState::init_responder(sk, spk_keypair);

    let header = Header {
        public_key: PublicKey::from(envelope.ratchet_pk),
        pn: envelope.pn,
        n: envelope.n,
    };
    let ad = initial_ad(&initiator_ik_pub, &own_ik.public);
    let plaintext = state.ratchet_decrypt(&envelope.ciphertext, &header, &ad)?;

    Ok((state, plaintext))
}

/// HKDF-SHA256 over a caller-built IKM (already including the F prefix). No salt —
/// RFC 5869 §2.2 specifies an implicit zero salt, which is appropriate because the
/// IKM is not user-controlled and domain separation is enforced via [`HKDF_INFO`].
fn hkdf_sk_from_ikm(ikm: &[u8]) -> Result<RootKey, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = Zeroizing::new([0u8; SK_LEN]);
    hkdf.expand(HKDF_INFO, okm.as_mut())
        .map_err(|_| CryptoError::HkdfExpand)?;
    Ok(RootKey::from_bytes(*okm))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{SigningKeyPair, generate_key_pair, generate_signing_key_pair};
    use crate::signed_prekey::generate_signed_prekey;

    const FIXED_TS: u64 = 1_700_000_000;

    struct Setup {
        alice_ik: KeyPair,
        bob_ik: KeyPair,
        bob_signing: SigningKeyPair,
        bob_spk: SignedPreKey,
    }

    fn setup() -> Setup {
        let bob_signing = generate_signing_key_pair();
        let bob_spk = generate_signed_prekey(&bob_signing, FIXED_TS);
        Setup {
            alice_ik: generate_key_pair(),
            bob_ik: generate_key_pair(),
            bob_signing,
            bob_spk,
        }
    }

    #[test]
    fn initiator_and_responder_derive_identical_sk() {
        let s = setup();
        let alice_ek = generate_key_pair();

        let sk_init =
            derive_sk_initiator(&s.alice_ik, &alice_ek, &s.bob_ik.public, s.bob_spk.public())
                .unwrap();
        let sk_resp = derive_sk_responder(
            &s.alice_ik.public,
            &alice_ek.public,
            &s.bob_ik,
            &s.bob_spk,
        )
        .unwrap();

        assert_eq!(sk_init.as_bytes(), sk_resp.as_bytes());
    }

    #[test]
    fn initiate_accept_round_trip() {
        let s = setup();
        let plaintext = b"hello from alice";
        let bundle = s.bob_spk.bundle();

        let (_, envelope) = initiate(
            &s.alice_ik,
            &s.bob_signing.verifying,
            &s.bob_ik.public,
            &bundle,
            plaintext,
        )
        .unwrap();

        let (_, decrypted) = accept(&envelope, &s.bob_ik, &s.bob_spk).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn envelope_postcard_round_trip() {
        let s = setup();
        let plaintext = b"serialize me";
        let bundle = s.bob_spk.bundle();

        let (_, envelope) = initiate(
            &s.alice_ik,
            &s.bob_signing.verifying,
            &s.bob_ik.public,
            &bundle,
            plaintext,
        )
        .unwrap();

        let bytes = postcard::to_stdvec(&envelope).unwrap();
        let restored: HandshakeEnvelope = postcard::from_bytes(&bytes).unwrap();

        let (_, decrypted) = accept(&restored, &s.bob_ik, &s.bob_spk).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn accept_rejects_tampered_ciphertext() {
        let s = setup();
        let bundle = s.bob_spk.bundle();

        let (_, mut envelope) = initiate(
            &s.alice_ik,
            &s.bob_signing.verifying,
            &s.bob_ik.public,
            &bundle,
            b"tamper me",
        )
        .unwrap();

        envelope.ciphertext[0] ^= 0xFF;

        assert!(matches!(
            accept(&envelope, &s.bob_ik, &s.bob_spk),
            Err(CryptoError::Aead)
        ));
    }

    #[test]
    fn initiate_rejects_bundle_under_wrong_vk() {
        let s = setup();
        let wrong_signing = generate_signing_key_pair();
        let bundle = s.bob_spk.bundle();

        let result = initiate(
            &s.alice_ik,
            &wrong_signing.verifying,
            &s.bob_ik.public,
            &bundle,
            b"payload",
        );
        assert!(matches!(result, Err(CryptoError::SignatureInvalid)));
    }

    #[test]
    fn accept_rejects_mismatched_spk_ref() {
        let s = setup();
        let bundle = s.bob_spk.bundle();

        let (_, mut envelope) = initiate(
            &s.alice_ik,
            &s.bob_signing.verifying,
            &s.bob_ik.public,
            &bundle,
            b"payload",
        )
        .unwrap();

        envelope.responder_spk_ref[0] ^= 0x01;

        assert!(matches!(
            accept(&envelope, &s.bob_ik, &s.bob_spk),
            Err(CryptoError::HandshakeSpkMismatch)
        ));
    }

    #[test]
    fn initial_ad_layout_is_initiator_then_responder() {
        let a = generate_key_pair();
        let b = generate_key_pair();
        let ad = initial_ad(&a.public, &b.public);

        assert_eq!(&ad[..32], a.public.as_bytes());
        assert_eq!(&ad[32..], b.public.as_bytes());
    }

    #[test]
    fn postcard_wire_length_is_deterministic() {
        let s = setup();
        let bundle = s.bob_spk.bundle();

        let (_, envelope) = initiate(
            &s.alice_ik,
            &s.bob_signing.verifying,
            &s.bob_ik.public,
            &bundle,
            b"payload",
        )
        .unwrap();

        let bytes = postcard::to_stdvec(&envelope).unwrap();
        let ct_len = envelope.ciphertext.len();
        // 4 × 32-byte pubkeys + varint pn + varint n + varint ciphertext length + ciphertext.
        // First message has pn = 0 and n = 0 and ct_len < 128, so every varint is one byte.
        assert!(ct_len < 128);
        assert_eq!(envelope.pn, 0);
        assert_eq!(envelope.n, 0);
        assert_eq!(bytes.len(), 32 * 4 + 1 + 1 + 1 + ct_len);
    }
}
