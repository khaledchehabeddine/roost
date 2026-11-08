use roost_crypto::Signature;
use serde::de::{Error as DeError, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::marker::PhantomData;
use zeroize::Zeroizing;

const SIGNATURE_LEN: usize = Signature::BYTE_SIZE;
const SIGNATURE_HALF_LEN: usize = SIGNATURE_LEN / 2;

/// A reason a value Roost writes to SecureStorage, an identity backup, or a contact publication
/// can't be encoded or decoded.
#[derive(Debug, thiserror::Error)]
pub enum StoredDataError {
    /// The stored bytes don't decode as the expected value.
    #[error("stored data failed to decode")]
    Decode(#[source] postcard::Error),
    /// The value failed to encode.
    #[error("stored data failed to encode")]
    Encode(#[source] postcard::Error),
    /// Bytes remain after the stored value.
    #[error("stored data has {len} bytes left over")]
    TrailingBytes {
        /// Number of bytes left over.
        len: usize,
    },
    /// The stored bytes use a format version this build doesn't read.
    #[error("unsupported stored data version {version}")]
    UnsupportedVersion {
        /// The version the bytes start with.
        version: u8,
    },
}

// A signature as two halves, since serde encodes arrays of at most 32 elements.
pub(crate) type SignatureWire = [[u8; SIGNATURE_HALF_LEN]; 2];

pub(crate) fn signature_to_wire(signature: &[u8; SIGNATURE_LEN]) -> SignatureWire {
    let mut wire = [[0; SIGNATURE_HALF_LEN]; 2];
    wire.as_flattened_mut().copy_from_slice(signature);
    wire
}

pub(crate) fn signature_from_wire(wire: &SignatureWire) -> [u8; SIGNATURE_LEN] {
    let mut signature = [0; SIGNATURE_LEN];
    signature.copy_from_slice(wire.as_flattened());
    signature
}

// Encodes `wire` after `version`. A tuple encodes its fields in order, so the version comes first.
pub(crate) fn encode_versioned<T: Serialize>(
    version: u8,
    wire: &T,
) -> Result<Zeroizing<Vec<u8>>, StoredDataError> {
    encode_zeroizing(&(version, wire))
}

// Checks that `bytes` start with `version`, then decodes the rest as one `T`.
pub(crate) fn decode_versioned<'a, T: Deserialize<'a>>(
    version: u8,
    bytes: &'a [u8],
) -> Result<T, StoredDataError> {
    let (value, rest) = decode_versioned_prefix(version, bytes)?;
    reject_trailing_bytes(rest)?;
    Ok(value)
}

// Decodes `bytes` as one `T`, for an encoding that only sits inside another one.
pub(crate) fn decode_exact<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, StoredDataError> {
    let (value, rest) = postcard::take_from_bytes(bytes).map_err(StoredDataError::Decode)?;
    reject_trailing_bytes(rest)?;
    Ok(value)
}

fn reject_trailing_bytes(rest: &[u8]) -> Result<(), StoredDataError> {
    if rest.is_empty() {
        Ok(())
    } else {
        Err(StoredDataError::TrailingBytes { len: rest.len() })
    }
}

// Checks that `bytes` start with `version`, then decodes a `T` and returns it with the bytes after.
pub(crate) fn decode_versioned_prefix<'a, T: Deserialize<'a>>(
    version: u8,
    bytes: &'a [u8],
) -> Result<(T, &'a [u8]), StoredDataError> {
    let (&stored_version, body) = bytes.split_first().ok_or(StoredDataError::Decode(
        postcard::Error::DeserializeUnexpectedEnd,
    ))?;
    if stored_version != version {
        return Err(StoredDataError::UnsupportedVersion {
            version: stored_version,
        });
    }
    postcard::take_from_bytes(body).map_err(StoredDataError::Decode)
}

// Encodes `wire` into a buffer sized up front, so secret bytes are never left behind in memory a
// growing `Vec` freed.
pub(crate) fn encode_zeroizing<T: Serialize>(
    wire: &T,
) -> Result<Zeroizing<Vec<u8>>, StoredDataError> {
    let len = postcard::experimental::serialized_size(wire).map_err(StoredDataError::Encode)?;
    let mut bytes = Zeroizing::new(vec![0; len]);
    let written = postcard::to_slice(wire, &mut bytes)
        .map_err(StoredDataError::Encode)?
        .len();
    if written != len {
        return Err(StoredDataError::Encode(
            postcard::Error::SerializeBufferFull,
        ));
    }
    Ok(bytes)
}

// Decodes a list, refusing one longer than `MAX` before it allocates for more.
pub(crate) fn deserialize_bounded<'de, D, T, const MAX: usize>(
    deserializer: D,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedVisitor<T, const MAX: usize>(PhantomData<T>);

    impl<'de, T: Deserialize<'de>, const MAX: usize> Visitor<'de> for BoundedVisitor<T, MAX> {
        type Value = Vec<T>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "at most {MAX} entries")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let too_many = || A::Error::custom(format_args!("more than {MAX} entries"));
            // Postcard gives the exact length, so a list of secrets is allocated once and never
            // grows.
            if seq.size_hint().is_some_and(|len| len > MAX) {
                return Err(too_many());
            }
            let mut entries = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(MAX));
            while let Some(entry) = seq.next_element()? {
                if entries.len() == MAX {
                    return Err(too_many());
                }
                entries.push(entry);
            }
            Ok(entries)
        }
    }

    deserializer.deserialize_seq(BoundedVisitor::<T, MAX>(PhantomData))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_versioned_rejects_another_version_before_decoding() {
        assert!(matches!(
            decode_versioned::<u8>(2, &[3]),
            Err(StoredDataError::UnsupportedVersion { version: 3 })
        ));
    }

    #[test]
    fn decode_versioned_rejects_bytes_left_over() {
        let bytes = encode_versioned(2, &7u8).unwrap();
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert_eq!(decode_versioned::<u8>(2, &bytes).unwrap(), 7);
        assert!(matches!(
            decode_versioned::<u8>(2, &longer),
            Err(StoredDataError::TrailingBytes { len: 1 })
        ));
    }

    #[test]
    fn signature_wire_keeps_every_byte() {
        let signature: [u8; SIGNATURE_LEN] = std::array::from_fn(|index| index as u8);
        assert_eq!(
            signature_from_wire(&signature_to_wire(&signature)),
            signature
        );
    }
}
