//! This operation calculates the unique ID for a given PASERK.
//!
//! <https://github.com/paseto-standard/paserk/blob/master/operations/ID.md>
//!
//! # Local IDs
//! ```
//! use rusty_paserk::id::KeyId;
//! use rusty_paserk::key::{Key, LocalKey};
//! use rusty_paseto::core::V4;
//!
//! let local_key = Key::<V4, LocalKey>::new_random();
//! let kid: KeyId<V4, LocalKey> = local_key.into();
//! // kid.to_string() => "k4.lid.XxPub51WIAEmbVTmrs-lFoFodxTSKk8RuYEJk3gl-DYB"
//! ```
//!
//! # Secret IDs
//! ```
//! use rusty_paserk::id::KeyId;
//! use rusty_paserk::key::{Key, SecretKey};
//! use rusty_paseto::core::V4;
//!
//! let local_key = Key::<V4, SecretKey>::new_random();
//! let kid: KeyId<V4, SecretKey> = local_key.into();
//! // kid.to_string() => "k4.sid.p26RNihDPsk2QbglGMTmwMMqLYyeLY25UOQZXQDXwn61"
//! ```
//!
//! # Public IDs
//! ```
//! use rusty_paserk::id::KeyId;
//! use rusty_paserk::key::{Key, PublicKey};
//! use rusty_paseto::core::V4;
//!
//! let local_key = Key::<V4, PublicKey>::new_random();
//! let kid: KeyId<V4, PublicKey> = local_key.into();
//! // kid.to_string() => "k4.pid.yMgldRRLHBLkhmcp8NG8yZrtyldbYoAjQWPv_Ma1rzRu"
//! ```
use std::{fmt, marker::PhantomData, str::FromStr};

use base64::URL_SAFE_NO_PAD;
use generic_array::{typenum::U33, GenericArray};

use rusty_paseto::core::PasetoError;
#[cfg(feature = "v3")]
use rusty_paseto::core::V3;
#[cfg(feature = "v4")]
use rusty_paseto::core::V4;

use crate::key::{write_b64, Key, KeyType, Version};

pub struct KeyId<V: Version, K: KeyType<V>> {
    id: GenericArray<u8, U33>,
    key: PhantomData<(V, K)>,
}

impl<V: Version, K: KeyType<V>> fmt::Debug for KeyId<V, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl<V: Version, K: KeyType<V>> fmt::Display for KeyId<V, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(V::KEY_HEADER)?;
        f.write_str(K::ID)?;
        write_b64(&self.id, f)
    }
}

impl<V: Version, K: KeyType<V>> FromStr for KeyId<V, K> {
    type Err = PasetoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .strip_prefix(V::KEY_HEADER)
            .ok_or(PasetoError::WrongHeader)?;
        let s = s.strip_prefix(K::ID).ok_or(PasetoError::WrongHeader)?;

        let mut id = GenericArray::<u8, U33>::default();
        let len = base64::decode_config_slice(s, URL_SAFE_NO_PAD, &mut id)?;
        if len != 33 {
            return Err(PasetoError::PayloadBase64Decode {
                source: base64::DecodeError::InvalidLength,
            });
        }

        Ok(KeyId {
            id,
            key: PhantomData,
        })
    }
}

impl<V: Version, K: KeyType<V>> core::cmp::PartialOrd for KeyId<V, K> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<V: Version, K: KeyType<V>> core::cmp::Ord for KeyId<V, K> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}
impl<V: Version, K: KeyType<V>> core::cmp::PartialEq for KeyId<V, K> {
    fn eq(&self, other: &Self) -> bool {
        self.id.eq(&other.id)
    }
}
impl<V: Version, K: KeyType<V>> core::cmp::Eq for KeyId<V, K> {}
impl<V: Version, K: KeyType<V>> Clone for KeyId<V, K> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<V: Version, K: KeyType<V>> Copy for KeyId<V, K> {}

#[cfg(feature = "v3")]
impl<K: KeyType<V3>> From<Key<V3, K>> for KeyId<V3, K> {
    fn from(key: Key<V3, K>) -> Self {
        use base64ct::{Base64UrlUnpadded, Encoding};
        use sha2::digest::Digest;

        // V3 Public keys are 49 bytes, V3 private keys are 48 bytes, symmetric keys are 32 bytes.
        // allocate enough space for 49 bytes base64 encoded which is ~66
        let mut output = [0; 49 * 4 / 3 + 3];
        let p = Base64UrlUnpadded::encode(key.as_ref(), &mut output).unwrap();

        let mut derive_d = sha2::Sha384::new();
        derive_d.update(V3::KEY_HEADER);
        derive_d.update(K::ID);
        derive_d.update(V3::KEY_HEADER);
        derive_d.update(K::HEADER);
        derive_d.update(p);
        let d = derive_d.finalize();
        let id = *GenericArray::from_slice(&d[..33]);

        KeyId {
            id,
            key: PhantomData,
        }
    }
}

#[cfg(feature = "v4")]
impl<K: KeyType<V4>> From<Key<V4, K>> for KeyId<V4, K> {
    fn from(key: Key<V4, K>) -> Self {
        use base64ct::{Base64UrlUnpadded, Encoding};
        use blake2::digest::Digest;

        // V4 Public keys are 64 bytes, symmetric keys are 32 bytes.
        // allocate enough space for 64 bytes base64 encoded
        let mut output = [0; 64 * 4 / 3 + 3];
        let p = Base64UrlUnpadded::encode(key.as_ref(), &mut output).unwrap();

        let mut derive_d = blake2::Blake2b::<U33>::new();
        derive_d.update(V4::KEY_HEADER);
        derive_d.update(K::ID);
        derive_d.update(V4::KEY_HEADER);
        derive_d.update(K::HEADER);
        derive_d.update(p);
        let id = derive_d.finalize();

        KeyId {
            id,
            key: PhantomData,
        }
    }
}
