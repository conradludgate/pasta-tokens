use std::{fmt, str::FromStr};

use base64::URL_SAFE_NO_PAD;
use cipher::Unsigned;
use generic_array::GenericArray;
use rusty_paseto::core::PasetoError;

use crate::{write_b64, Key, KeyType, Version};

/// A key encoded in base64. It is not a secure serialization.
pub struct PlaintextKey<V: Version, K: KeyType<V>>(pub Key<V, K>);

impl<V: Version, K: KeyType<V>> fmt::Display for PlaintextKey<V, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(V::KEY_HEADER)?;
        f.write_str(K::HEADER)?;
        write_b64(&self.0.key, f)
    }
}

impl<V: Version, K: KeyType<V>> FromStr for PlaintextKey<V, K> {
    type Err = PasetoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .strip_prefix(V::KEY_HEADER)
            .ok_or(PasetoError::WrongHeader)?;
        let s = s.strip_prefix(K::HEADER).ok_or(PasetoError::WrongHeader)?;

        let mut key = GenericArray::<u8, K::KeyLen>::default();
        let len = base64::decode_config_slice(s, URL_SAFE_NO_PAD, &mut key)?;
        if len != <K::KeyLen as Unsigned>::USIZE {
            return Err(PasetoError::PayloadBase64Decode {
                source: base64::DecodeError::InvalidLength,
            });
        }

        Ok(PlaintextKey(Key { key }))
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
#[cfg(feature = "serde")]
impl<V: Version, K: KeyType<V>> serde::Serialize for PlaintextKey<V, K> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
#[cfg(feature = "serde")]
impl<'de, V: Version, K: KeyType<V>> serde::Deserialize<'de> for PlaintextKey<V, K> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct FromStrVisitor<V, K>(std::marker::PhantomData<(V, K)>);
        impl<'de, V: Version, K: KeyType<V>> serde::de::Visitor<'de> for FromStrVisitor<V, K> {
            type Value = PlaintextKey<V, K>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "a \"{}{}\" serialized key", V::KEY_HEADER, K::HEADER)
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                v.parse().map_err(E::custom)
            }
        }
        deserializer.deserialize_str(FromStrVisitor(std::marker::PhantomData))
    }
}
