pub use ed25519_dalek::{Signature, VerifyingKey};

use ed25519_dalek::SigningKey;
use rand::{CryptoRng, RngCore};
use roost_protocol::SignatureError;
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// An Ed25519 key pair for signing.
///
/// Use [`Self::to_signing_bytes`] only when storing the key pair.
#[derive(ZeroizeOnDrop)]
pub struct SigningKeyPair {
    /// The verifying key.
    #[zeroize(skip)]
    pub verifying: VerifyingKey,
    signing: SigningKey,
}

impl SigningKeyPair {
    /// Signs `message` without a domain context.
    ///
    /// Ed25519 signing is deterministic, so identical inputs produce identical signatures. The
    /// caller owns any domain separation.
    pub fn sign(&self, message: &[u8]) -> Signature {
        use ed25519_dalek::Signer;
        self.signing.sign(message)
    }

    /// Signs `message` under a domain `context` with this key pair.
    ///
    /// `context` must be a non-empty domain separator naming the signature purpose. The signed
    /// bytes are the context, the message's big-endian `u32` length, and the message.
    pub fn sign_with_context(
        &self,
        context: &[u8],
        message: &[u8],
    ) -> Result<Signature, SignatureError> {
        Ok(self.sign(&roost_protocol::contextual_message(context, message)?))
    }

    /// Returns this key pair's signing bytes for secure storage.
    pub fn to_signing_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }

    /// Restores a [`SigningKeyPair`] from stored signing key bytes.
    pub fn from_signing_bytes(bytes: &[u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(bytes);
        let verifying = signing.verifying_key();
        SigningKeyPair { verifying, signing }
    }
}

/// Generates a fresh Ed25519 key pair using `rng`.
#[must_use]
pub fn generate_signing_key_pair<R: RngCore + CryptoRng>(rng: &mut R) -> SigningKeyPair {
    let signing = SigningKey::generate(&mut *rng);
    let verifying = signing.verifying_key();
    SigningKeyPair { signing, verifying }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn generated_key_pair() -> SigningKeyPair {
        generate_signing_key_pair(&mut ChaCha20Rng::from_seed([3u8; 32]))
    }

    #[test]
    fn signing_key_pair_round_trip_via_signing_bytes() {
        let key_pair = generated_key_pair();
        let restored = SigningKeyPair::from_signing_bytes(&key_pair.to_signing_bytes());
        assert_eq!(key_pair.verifying.as_bytes(), restored.verifying.as_bytes());
    }

    #[test]
    fn signing_key_pair_zeroizes_on_drop() {
        fn assert_zeroizes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroizes_on_drop::<SigningKeyPair>();
    }
}
