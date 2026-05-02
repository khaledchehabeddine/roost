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

/// Fixed prefix on the HKDF input. Any future change to the SK derivation should also change
/// these bytes so incompatible peers produce different SKs and fail the handshake immediately.
const F_PREFIX: [u8; 32] = [0xFF; 32];
/// Domain separator so SK cannot collide with any other HKDF output in this crate.
const HKDF_INFO: &[u8] = b"HermesX3DHLite";
/// `F || DH1 || DH2 || DH3` — 32 bytes each, 128 bytes total.
const IKM_LEN: usize = 32 * 4;

/// Wire form of a handshake initiation. Holds only public material — no secret-zeroing derives
/// needed.
///
/// The ratchet header is flattened into its three fields (`ratchet_pk`, `pn`, `n`) instead of
/// being stored as a single `[u8; 40]` array. Serde's auto-derived `Deserialize` only covers
/// arrays up to `[T; 32]`, so storing 40 bytes directly would require the `serde-big-array`
/// crate or handwritten implementation. Flattening sidesteps both.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HandshakeEnvelope {
    pub initiator_ik: [u8; 32],
    pub initiator_ek: [u8; 32],
    pub responder_spk_ref: [u8; 32],
    pub ratchet_pk: [u8; 32],
    pub pn: u32,
    pub n: u32,
    pub ciphertext: Vec<u8>,
}

/// Full initiator flow: verify the peer's bundle, derive SK, seed the ratchet, encrypt the first
/// message, and assemble the envelope.
pub fn initiate(
    ik: &KeyPair,
    peer_ik_vk: &VerifyingKey,
    peer_ik_x25519: &PublicKey,
    peer_bundle: &PreKeyBundle,
    plaintext: &[u8],
) -> Result<(RatchetState, HandshakeEnvelope), CryptoError> {
    verify_bundle(peer_bundle, peer_ik_vk)?;

    let ek = generate_key_pair();
    let spk_b_pub = peer_bundle.public_key;

    let sk = derive_sk_initiator(ik, &ek, peer_ik_x25519, &spk_b_pub)?;
    let mut state = RatchetState::init_initiator(sk, &spk_b_pub)?;

    let ad = initial_ad(&ik.public, peer_ik_x25519);
    let (header, ciphertext) = state.ratchet_encrypt(plaintext, &ad)?;

    let envelope = HandshakeEnvelope {
        initiator_ik: *ik.public.as_bytes(),
        initiator_ek: *ek.public.as_bytes(),
        responder_spk_ref: *spk_b_pub.as_bytes(),
        ratchet_pk: *header.public_key.as_bytes(),
        pn: header.pn,
        n: header.n,
        ciphertext,
    };

    Ok((state, envelope))
}

/// Full responder flow: constant-time match the envelope's SPK ref, derive SK, seed the ratchet,
/// and decrypt the first message.
pub fn accept(
    envelope: &HandshakeEnvelope,
    ik: &KeyPair,
    spk: &SignedPreKey,
) -> Result<(RatchetState, Zeroizing<Vec<u8>>), CryptoError> {
    let spk_ref_matches: bool = envelope
        .responder_spk_ref
        .ct_eq(spk.public().as_bytes())
        .into();
    if !spk_ref_matches {
        return Err(CryptoError::HandshakeSpkMismatch);
    }

    let initiator_ik_pub = PublicKey::from(envelope.initiator_ik);
    let initiator_ek_pub = PublicKey::from(envelope.initiator_ek);

    let sk = derive_sk_responder(&initiator_ik_pub, &initiator_ek_pub, ik, spk)?;

    let spk_keypair = KeyPair::from_secret_bytes(*spk.to_secret_bytes());
    let mut state = RatchetState::init_responder(sk, spk_keypair);

    let header = Header {
        public_key: PublicKey::from(envelope.ratchet_pk),
        pn: envelope.pn,
        n: envelope.n,
    };
    let ad = initial_ad(&initiator_ik_pub, &ik.public);
    let plaintext = state.ratchet_decrypt(&envelope.ciphertext, &header, &ad)?;

    Ok((state, plaintext))
}

/// Initiator-side SK derivation. Three DHs composed into one HKDF run:
/// `DH1 = IK_A·SPK_B`, `DH2 = EK_A·IK_B`, `DH3 = EK_A·SPK_B`.
pub(crate) fn derive_sk_initiator(
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

/// Responder-side SK derivation. Mirrors [`derive_sk_initiator`] with the complementary halves of
/// each DH: `DH1 = SPK_B·IK_A`, `DH2 = IK_B·EK_A`, `DH3 = SPK_B·EK_A`. Must produce identical
/// output for matched inputs.
pub(crate) fn derive_sk_responder(
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

/// Associated data for the first ratcheted message: initiator X25519 IK pubkey, then responder
/// X25519 IK pubkey. Both sides reconstruct the same 64-byte sequence.
#[must_use]
pub fn initial_ad(initiator_ik: &PublicKey, responder_ik: &PublicKey) -> [u8; 64] {
    let mut ad = [0u8; 64];
    ad[..32].copy_from_slice(initiator_ik.as_bytes());
    ad[32..].copy_from_slice(responder_ik.as_bytes());
    ad
}

/// HKDF-SHA256 over the caller's IKM (`F_PREFIX || DH1 || DH2 || DH3`), producing the 32-byte
/// ratchet root key.
///
/// Salt is `None`: RFC 5869 defines this as an implicit zero salt, which is safe here because the
/// IKM is already uniformly random and `HKDF_INFO` provides domain separation.
fn hkdf_sk_from_ikm(ikm: &[u8]) -> Result<RootKey, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
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
    fn envelope_survives_wire_round_trip() {
        let s = setup();
        let plaintext = b"serialize me";

        let (_, envelope) = initiate(
            &s.alice_ik,
            &s.bob_signing.verifying,
            &s.bob_ik.public,
            &s.bob_spk.bundle(),
            plaintext,
        )
        .unwrap();

        let bytes = postcard::to_stdvec(&envelope).unwrap();
        let postcard_envelop: HandshakeEnvelope = postcard::from_bytes(&bytes).unwrap();

        let (_, decrypted) = accept(&postcard_envelop, &s.bob_ik, &s.bob_spk).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn initiate_accept_round_trip() {
        let s = setup();
        let plaintext = b"hello from Alice";

        let (_, envelope) = initiate(
            &s.alice_ik,
            &s.bob_signing.verifying,
            &s.bob_ik.public,
            &s.bob_spk.bundle(),
            plaintext,
        )
        .unwrap();

        let (_, decrypted) = accept(&envelope, &s.bob_ik, &s.bob_spk).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn initiate_rejects_bundle_under_wrong_vk() {
        let s = setup();
        let wrong_signing = generate_signing_key_pair();

        let result = initiate(
            &s.alice_ik,
            &wrong_signing.verifying,
            &s.bob_ik.public,
            &s.bob_spk.bundle(),
            b"payload",
        );
        assert!(matches!(result, Err(CryptoError::SignatureInvalid)));
    }

    #[test]
    fn accept_rejects_tampered_ciphertext() {
        let s = setup();

        let (_, mut envelope) = initiate(
            &s.alice_ik,
            &s.bob_signing.verifying,
            &s.bob_ik.public,
            &s.bob_spk.bundle(),
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
    fn accept_rejects_mismatched_spk_ref() {
        let s = setup();

        let (_, mut envelope) = initiate(
            &s.alice_ik,
            &s.bob_signing.verifying,
            &s.bob_ik.public,
            &s.bob_spk.bundle(),
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
    fn initiator_and_responder_derive_identical_sk() {
        let s = setup();
        let alice_ek = generate_key_pair();

        let sk_init =
            derive_sk_initiator(&s.alice_ik, &alice_ek, &s.bob_ik.public, s.bob_spk.public())
                .unwrap();
        let sk_resp =
            derive_sk_responder(&s.alice_ik.public, &alice_ek.public, &s.bob_ik, &s.bob_spk)
                .unwrap();

        assert_eq!(sk_init.as_bytes(), sk_resp.as_bytes());
    }

    #[test]
    fn initial_ad_layout_is_initiator_then_responder() {
        let a = generate_key_pair();
        let b = generate_key_pair();
        let ad = initial_ad(&a.public, &b.public);

        assert_eq!(&ad[..32], a.public.as_bytes());
        assert_eq!(&ad[32..], b.public.as_bytes());
    }
}
