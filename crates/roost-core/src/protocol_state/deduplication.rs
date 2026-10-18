use super::{
    DIGEST_LEN, ProtocolStateAddress, ProtocolStateBlob, ProtocolStateError, ProtocolStateKey,
    ProtocolStateKind, ProtocolStateSnapshot, ReceiveSettings, blob_body, digest_of, encode_blob,
    encode_zeroizing, keep_newest, push_bounded,
};
use crate::hardening::{ProtocolHardeningLimits, is_supported_deduplication_capacity};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const DEDUPLICATION_DIGEST_LABEL: &[u8] = b"RoostDeduplicationDigest-v1:";
const DEDUPLICATION_KEY_LEN: usize = 32;
const DEDUPLICATION_SET_KEY: &[u8] = &[0];

// The Deduplication Set is the only record of its kind, so its key is fixed.
pub(super) fn deduplication_address() -> ProtocolStateAddress {
    ProtocolStateAddress::new(
        ProtocolStateKind::DeduplicationSet,
        ProtocolStateKey(DEDUPLICATION_SET_KEY.to_vec()),
    )
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct LoadedDeduplicationSet {
    capacity: usize,
    digest_key: Zeroizing<[u8; DEDUPLICATION_KEY_LEN]>,
    digests: Vec<[u8; DIGEST_LEN]>,
}

impl LoadedDeduplicationSet {
    // Returns the digest that catches a repeated delivery of `encoded_message`.
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

    // Records a received Message's digest, forgetting the oldest past the set's size.
    pub(super) fn record(&mut self, digest: [u8; DIGEST_LEN]) {
        push_bounded(&mut self.digests, digest, self.capacity);
    }
}

#[derive(Serialize)]
struct DeduplicationSetWire<'a> {
    capacity: u16,
    digest_key: &'a [u8; DEDUPLICATION_KEY_LEN],
    digests: &'a [[u8; DIGEST_LEN]],
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct DecodedDeduplicationSetWire {
    capacity: u16,
    digest_key: [u8; DEDUPLICATION_KEY_LEN],
    digests: Vec<[u8; DIGEST_LEN]>,
}

pub(super) fn encode_deduplication_set(
    address: &ProtocolStateAddress,
    state: &LoadedDeduplicationSet,
    limits: ProtocolHardeningLimits,
) -> Result<ProtocolStateBlob, ProtocolStateError> {
    let encode_error = |reason: String| ProtocolStateError::BlobEncode {
        address: address.clone(),
        reason,
    };
    let capacity = u16::try_from(state.capacity).map_err(|_| {
        encode_error(format!(
            "deduplication-set capacity {} doesn't fit its encoding",
            state.capacity
        ))
    })?;
    let body = encode_zeroizing(&DeduplicationSetWire {
        capacity,
        digest_key: &state.digest_key,
        digests: &state.digests,
    })
    .map_err(|_| encode_error("deduplication set failed to encode".into()))?;
    encode_blob(address, &body, limits.max_protocol_state_blob_len)
}

// Returns the Deduplication Set at the size `settings` names, creating it on the first receive and
// evicting the oldest digests when the size shrinks.
pub(super) fn receiving_deduplication_set<R: RngCore + CryptoRng>(
    rng: &mut R,
    snapshot: &ProtocolStateSnapshot,
    settings: ReceiveSettings,
    limits: ProtocolHardeningLimits,
) -> Result<LoadedDeduplicationSet, ProtocolStateError> {
    let address = deduplication_address();
    let mut set = match snapshot.get(&address) {
        Some(blob) => decode_deduplication_set(&address, blob, limits)?,
        None => {
            let mut digest_key = Zeroizing::new([0u8; DEDUPLICATION_KEY_LEN]);
            rng.try_fill_bytes(&mut digest_key[..])
                .map_err(ProtocolStateError::Randomness)?;
            LoadedDeduplicationSet {
                capacity: settings.deduplication_capacity,
                digest_key,
                digests: Vec::new(),
            }
        }
    };
    set.capacity = settings.deduplication_capacity;
    keep_newest(&mut set.digests, set.capacity);
    Ok(set)
}

fn decode_deduplication_set(
    address: &ProtocolStateAddress,
    blob: &ProtocolStateBlob,
    limits: ProtocolHardeningLimits,
) -> Result<LoadedDeduplicationSet, ProtocolStateError> {
    let decode_error = |reason: String| ProtocolStateError::BlobDecode {
        address: address.clone(),
        reason,
    };
    let body = blob_body(address, blob, limits.max_protocol_state_blob_len)?;
    let (mut wire, trailing): (DecodedDeduplicationSetWire, &[u8]) =
        postcard::take_from_bytes(body).map_err(|e| decode_error(e.to_string()))?;
    if !trailing.is_empty() {
        return Err(decode_error("deduplication set has trailing bytes".into()));
    }
    let capacity = usize::from(wire.capacity);
    if !is_supported_deduplication_capacity(capacity) {
        return Err(decode_error(format!(
            "deduplication-set capacity is outside supported range: {capacity}"
        )));
    }
    if wire.digests.len() > capacity {
        return Err(decode_error(format!(
            "deduplication-set digest count exceeds capacity: {}",
            wire.digests.len()
        )));
    }
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
            decode_deduplication_set(&address, &ProtocolStateBlob::from_bytes(bytes), limits),
            Err(ProtocolStateError::UnsupportedBlobVersion { address: actual, version })
                if actual == address && version == super::super::PROTOCOL_STATE_BLOB_VERSION + 1
        ));
    }
}
