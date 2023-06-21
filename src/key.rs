use std::{fmt, io::Write, str::FromStr};

use base64::{decode_config_slice, write::EncoderStringWriter, URL_SAFE_NO_PAD};
use base64ct::Encoding;
use cipher::Unsigned;
use generic_array::{
    typenum::{U32, U48, U49, U64},
    ArrayLength, GenericArray,
};
use rand::{rngs::OsRng, RngCore};
use rusty_paseto::core::PasetoError;
#[cfg(feature = "v3")]
use rusty_paseto::core::V3;
#[cfg(feature = "v4")]
use rusty_paseto::core::V4;

/// Key encodings
pub trait EncodeKey: Sized {
    fn encode_key(&self) -> String;

    fn decode_key(key: &str) -> Result<Self, PasetoError>;
}

/// local <https://github.com/paseto-standard/paserk/blob/master/types/local.md>
mod local {
    use rusty_paseto::core::{Key, Local, PasetoSymmetricKey};

    use super::*;

    #[cfg(feature = "v3")]
    impl EncodeKey for PasetoSymmetricKey<V3, Local> {
        fn encode_key(&self) -> String {
            encode_b64("k3.local.", self.as_ref())
        }
        fn decode_key(key: &str) -> Result<Self, PasetoError> {
            decode_b64("k3.local.", key)
                .map(Key::from)
                .map(PasetoSymmetricKey::from)
        }
    }

    #[cfg(feature = "v4")]
    impl EncodeKey for PasetoSymmetricKey<V4, Local> {
        fn encode_key(&self) -> String {
            encode_b64("k4.local.", self.as_ref())
        }
        fn decode_key(key: &str) -> Result<Self, PasetoError> {
            decode_b64("k4.local.", key)
                .map(Key::from)
                .map(PasetoSymmetricKey::from)
        }
    }
}

fn encode_b64(header: &str, key: &[u8]) -> String {
    let mut enc = EncoderStringWriter::from(header.to_owned(), base64::URL_SAFE_NO_PAD);
    enc.write_all(key).unwrap();
    enc.into_inner()
}

fn decode_b64(header: &str, key: &str) -> Result<[u8; 32], PasetoError> {
    let key = key.strip_prefix(header).ok_or(PasetoError::WrongHeader)?;
    let mut output = [0; 32];
    if decode_config_slice(key, base64::URL_SAFE_NO_PAD, &mut output)? < 32 {
        return Err(PasetoError::InvalidKey);
    }
    Ok(output)
}

pub trait Version {
    type Local: ArrayLength<u8>;
    type Public: ArrayLength<u8>;
    type Secret: ArrayLength<u8>;
    const TOKEN_HEADER: &'static str;
    const KEY_HEADER: &'static str;
}

#[cfg(feature = "v3")]
impl Version for V3 {
    type Local = U32;
    type Public = U49;
    type Secret = U48;
    const TOKEN_HEADER: &'static str = "v3.";
    const KEY_HEADER: &'static str = "k3.";
}

#[cfg(feature = "v3")]
impl Version for V4 {
    type Local = U32;
    type Public = U32;
    type Secret = U64;
    const TOKEN_HEADER: &'static str = "v4.";
    const KEY_HEADER: &'static str = "k4.";
}

pub struct PublicKey;
pub struct SecretKey;
pub struct LocalKey;

pub trait KeyType<V: Version> {
    type KeyLen: ArrayLength<u8>;
    const HEADER: &'static str;
    const ID: &'static str;
}

impl<V: Version> KeyType<V> for PublicKey {
    type KeyLen = V::Public;
    const HEADER: &'static str = "public.";
    const ID: &'static str = "pid.";
}
impl<V: Version> KeyType<V> for SecretKey {
    type KeyLen = V::Secret;
    const HEADER: &'static str = "secret.";
    const ID: &'static str = "sid.";
}
impl<V: Version> KeyType<V> for LocalKey {
    type KeyLen = V::Local;
    const HEADER: &'static str = "local.";
    const ID: &'static str = "lid.";
}

pub struct Key<V: Version, K: KeyType<V>> {
    key: GenericArray<u8, K::KeyLen>,
}

impl<V: Version, K: KeyType<V>> core::cmp::PartialEq for Key<V, K> {
    fn eq(&self, other: &Self) -> bool {
        self.key.eq(&other.key)
    }
}
impl<V: Version, K: KeyType<V>> core::cmp::Eq for Key<V, K> {}
impl<V: Version, K: KeyType<V>> Clone for Key<V, K> {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
        }
    }
}
impl Copy for Key<V3, LocalKey> {}
impl Copy for Key<V4, LocalKey> {}
impl Copy for Key<V3, PublicKey> {}
impl Copy for Key<V4, PublicKey> {}
impl Copy for Key<V3, SecretKey> {}
impl Copy for Key<V4, SecretKey> {}

impl<V: Version, K: KeyType<V>> fmt::Debug for Key<V, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key").finish_non_exhaustive()
    }
}

impl<V: Version, K: KeyType<V>> TryFrom<&[u8]> for Key<V, K> {
    type Error = PasetoError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != <K::KeyLen as Unsigned>::USIZE {
            return Err(PasetoError::IncorrectSize);
        }
        let mut key: GenericArray<u8, K::KeyLen> = Default::default();
        key.copy_from_slice(value);
        Ok(Key { key })
    }
}
impl<V: Version, K: KeyType<V>> From<GenericArray<u8, K::KeyLen>> for Key<V, K> {
    fn from(key: GenericArray<u8, K::KeyLen>) -> Self {
        Self { key }
    }
}

impl<V: Version, K: KeyType<V>> AsRef<[u8]> for Key<V, K> {
    fn as_ref(&self) -> &[u8] {
        &self.key
    }
}

impl<V: Version, K: KeyType<V>> Key<V, K> {
    pub fn new_random() -> Self {
        let mut key = GenericArray::<u8, K::KeyLen>::default();
        OsRng.fill_bytes(&mut key);
        Self { key }
    }
}

pub struct PlaintextKey<V: Version, K: KeyType<V>>(pub Key<V, K>);

impl<V: Version, K: KeyType<V>> fmt::Display for PlaintextKey<V, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(V::KEY_HEADER)?;
        f.write_str(K::HEADER)?;
        write_b64(&self.0.key, f)
    }
}

pub(crate) fn write_b64<W: fmt::Write>(b: &[u8], w: &mut W) -> fmt::Result {
    let mut buffer = [0; 64];
    for chunk in b.chunks(48) {
        let s = base64ct::Base64UrlUnpadded::encode(chunk, &mut buffer).unwrap();
        w.write_str(s)?;
    }
    Ok(())
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
