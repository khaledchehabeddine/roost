use super::{
    DIGEST_LEN, ProtocolStateAddress, ProtocolStateBlob, ProtocolStateError, ProtocolStateKey,
    ProtocolStateKind, ProtocolStateSnapshot, ReceiveSettings, decode_blob, deserialize_bounded,
    digest_of, encode_blob, encode_zeroizing, keep_newest, push_bounded,
};
use crate::hardening::{MAX_DEDUPLICATION_CAPACITY, ProtocolHardeningLimits};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{ZeroizeOnDrop, Zeroizing};

const DEDUPLICATION_DIGEST_LABEL: &[u8] = b"RoostDeduplicationDigest-v1:";
const DEDUPLICATION_KEY_LEN: usize = 32;
const DEDUPLICATION_SET_KEY: &[u8] = &[0];

// The deduplication set is the only record of its kind, so its key is fixed.
pub(super) fn deduplication_address() -> ProtocolStateAddress {
    ProtocolStateAddress::new(
        ProtocolStateKind::DeduplicationSet,
        ProtocolStateKey(DEDUPLICATION_SET_KEY.to_vec()),
    )
}

#[derive(ZeroizeOnDrop)]
pub(super) struct LoadedDeduplicationSet {
    // The size the app passed with this receive.
    capacity: usize,
    digest_key: Zeroizing<[u8; DEDUPLICATION_KEY_LEN]>,
    digests: Vec<[u8; DIGEST_LEN]>,
}

impl LoadedDeduplicationSet {
    pub(super) fn digest(
        &self,
        transport_binding: &[u8],
        encoded_message: &[u8],
    ) -> [u8; DIGEST_LEN] {
        deduplication_digest(&self.digest_key, transport_binding, encoded_message)
    }

    pub(super) fn contains(&self, digest: &[u8; DIGEST_LEN]) -> bool {
        super::contains_digest(&self.digests, digest)
    }

    // Records a received message's digest, forgetting the oldest past the set's size.
    pub(super) fn record(&mut self, digest: [u8; DIGEST_LEN]) {
        push_bounded(&mut self.digests, digest, self.capacity);
    }
}

#[derive(Serialize)]
struct DeduplicationSetWire<'a> {
    digest_key: &'a [u8; DEDUPLICATION_KEY_LEN],
    digests: &'a [[u8; DIGEST_LEN]],
}

#[derive(Deserialize, ZeroizeOnDrop)]
struct DecodedDeduplicationSetWire {
    digest_key: [u8; DEDUPLICATION_KEY_LEN],
    #[zeroize(skip)]
    #[serde(deserialize_with = "deserialize_bounded::<_, _, MAX_DEDUPLICATION_CAPACITY>")]
    digests: Vec<[u8; DIGEST_LEN]>,
}

pub(super) fn encode_deduplication_set(
    address: &ProtocolStateAddress,
    state: &LoadedDeduplicationSet,
    limits: ProtocolHardeningLimits,
) -> Result<ProtocolStateBlob, ProtocolStateError> {
    let body = encode_zeroizing(&DeduplicationSetWire {
        digest_key: &state.digest_key,
        digests: &state.digests,
    })
    .map_err(|_| ProtocolStateError::BlobEncode {
        address: address.clone(),
        reason: "deduplication set failed to encode".into(),
    })?;
    encode_blob(address, &body, limits.max_protocol_state_blob_len)
}

// Returns the deduplication set at the size `settings` names, creating it on the first receive and
// evicting the oldest digests when the size shrinks.
pub(super) fn receiving_deduplication_set<R: RngCore + CryptoRng>(
    rng: &mut R,
    snapshot: &ProtocolStateSnapshot,
    settings: ReceiveSettings,
    limits: ProtocolHardeningLimits,
) -> Result<LoadedDeduplicationSet, ProtocolStateError> {
    let address = deduplication_address();
    let capacity = settings.deduplication_capacity;
    let mut set = match snapshot.get(&address) {
        Some(blob) => decode_deduplication_set(&address, blob, capacity, limits)?,
        None => {
            let mut digest_key = Zeroizing::new([0u8; DEDUPLICATION_KEY_LEN]);
            rng.try_fill_bytes(&mut digest_key[..])
                .map_err(ProtocolStateError::Randomness)?;
            LoadedDeduplicationSet {
                capacity,
                digest_key,
                digests: Vec::new(),
            }
        }
    };
    keep_newest(&mut set.digests, capacity);
    Ok(set)
}

fn decode_deduplication_set(
    address: &ProtocolStateAddress,
    blob: &ProtocolStateBlob,
    capacity: usize,
    limits: ProtocolHardeningLimits,
) -> Result<LoadedDeduplicationSet, ProtocolStateError> {
    let mut wire: DecodedDeduplicationSetWire =
        decode_blob(address, blob, limits.max_protocol_state_blob_len)?;
    Ok(LoadedDeduplicationSet {
        capacity,
        digest_key: Zeroizing::new(wire.digest_key),
        digests: std::mem::take(&mut wire.digests),
    })
}

fn deduplication_digest(
    digest_key: &[u8; DEDUPLICATION_KEY_LEN],
    transport_binding: &[u8],
    encoded_message: &[u8],
) -> [u8; DIGEST_LEN] {
    digest_of(
        blake3::Hasher::new_keyed(digest_key),
        DEDUPLICATION_DIGEST_LABEL,
        transport_binding,
        encoded_message,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardening::MIN_DEDUPLICATION_CAPACITY;

    #[test]
    fn deduplication_digest_changes_with_each_input() {
        let key = [1u8; DEDUPLICATION_KEY_LEN];
        let expected = deduplication_digest(&key, b"transport-binding", b"encoded message");

        assert_ne!(
            deduplication_digest(
                &[2u8; DEDUPLICATION_KEY_LEN],
                b"transport-binding",
                b"encoded message"
            ),
            expected
        );
        assert_ne!(
            deduplication_digest(&key, b"other-binding", b"encoded message"),
            expected
        );
        assert_ne!(
            deduplication_digest(&key, b"transport-binding", b"other message"),
            expected
        );
    }

    #[test]
    fn the_deduplication_set_has_one_fixed_address() {
        let address = deduplication_address();
        assert_eq!(address.kind(), ProtocolStateKind::DeduplicationSet);
        assert_eq!(address.key().as_bytes(), [0]);
    }

    #[test]
    fn a_deduplication_set_of_another_version_is_unsupported() {
        let address = deduplication_address();
        let limits = ProtocolHardeningLimits::default();
        let set = LoadedDeduplicationSet {
            capacity: MIN_DEDUPLICATION_CAPACITY,
            digest_key: Zeroizing::new([7u8; DEDUPLICATION_KEY_LEN]),
            digests: Vec::new(),
        };
        let mut bytes = encode_deduplication_set(&address, &set, limits)
            .unwrap()
            .as_bytes()
            .to_vec();
        bytes[0] += 1;

        assert!(matches!(
            decode_deduplication_set(
                &address,
                &ProtocolStateBlob::from_bytes(bytes),
                MIN_DEDUPLICATION_CAPACITY,
                limits
            ),
            Err(ProtocolStateError::UnsupportedBlobVersion { address: actual, version })
                if actual == address && version == super::super::PROTOCOL_STATE_BLOB_VERSION + 1
        ));
    }
}
