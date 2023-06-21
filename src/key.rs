use std::{fmt, str::FromStr};

use base64::URL_SAFE_NO_PAD;
use base64ct::Encoding;
use cipher::Unsigned;
use generic_array::{ArrayLength, GenericArray};
use rand::{rngs::OsRng, RngCore};
use rusty_paseto::core::PasetoError;
#[cfg(feature = "v3")]
use rusty_paseto::core::V3;
#[cfg(feature = "v4")]
use rusty_paseto::core::V4;

/// General information about a PASETO/PASERK version
pub trait Version {
    /// Size of the symmetric local key
    type Local: ArrayLength<u8>;
    /// Size of the asymmetric public key
    type Public: ArrayLength<u8>;
    /// Size of the asymmetric secret key
    type Secret: ArrayLength<u8>;
    /// Header for PASETO
    const TOKEN_HEADER: &'static str;
    /// Header for PASERK
    const KEY_HEADER: &'static str;
}

#[cfg(feature = "v3")]
impl Version for V3 {
    type Local = generic_array::typenum::U32;
    /// P-384 Public Key in compressed format
    type Public = generic_array::typenum::U49;
    /// P-384 Secret Key (384 bits = 48 bytes)
    type Secret = generic_array::typenum::U48;
    const TOKEN_HEADER: &'static str = "v3.";
    const KEY_HEADER: &'static str = "k3.";
}

#[cfg(feature = "v4")]
impl Version for V4 {
    type Local = generic_array::typenum::U32;
    /// Compressed edwards y point
    type Public = generic_array::typenum::U32;
    /// Ed25519 scalar key, concatenated with the public key bytes
    type Secret = generic_array::typenum::U64;
    const TOKEN_HEADER: &'static str = "v4.";
    const KEY_HEADER: &'static str = "k4.";
}

/// Public verifying/encrypting keys
pub struct Public;
/// Secret signing/decrypting keys
pub struct Secret;
/// Local symmetric encryption/decrypting keys
pub struct Local;

/// General information about key types
pub trait KeyType<V: Version> {
    /// Chooses the correct length from the version
    type KeyLen: ArrayLength<u8>;
    const HEADER: &'static str;
    const ID: &'static str;
}

impl<V: Version> KeyType<V> for Public {
    type KeyLen = V::Public;
    const HEADER: &'static str = "public.";
    const ID: &'static str = "pid.";
}
impl<V: Version> KeyType<V> for Secret {
    type KeyLen = V::Secret;
    const HEADER: &'static str = "secret.";
    const ID: &'static str = "sid.";
}
impl<V: Version> KeyType<V> for Local {
    type KeyLen = V::Local;
    const HEADER: &'static str = "local.";
    const ID: &'static str = "lid.";
}

/// A PASETO key.
///
/// It is versioned and typed to ensure that [`Local`], [`Public`] and [`Secret`] keys are not used interchangably.
pub struct Key<V: Version, K: KeyType<V>> {
    pub(crate) key: GenericArray<u8, K::KeyLen>,
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
#[cfg(feature = "v3")]
impl Copy for Key<V3, Local> {}
#[cfg(feature = "v4")]
impl Copy for Key<V4, Local> {}
#[cfg(feature = "v3")]
impl Copy for Key<V3, Public> {}
#[cfg(feature = "v4")]
impl Copy for Key<V4, Public> {}
#[cfg(feature = "v3")]
impl Copy for Key<V3, Secret> {}
#[cfg(feature = "v4")]
impl Copy for Key<V4, Secret> {}

impl<V: Version, K: KeyType<V>> fmt::Debug for Key<V, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key").finish_non_exhaustive()
    }
}

#[cfg(feature = "v3")]
impl Key<V3, Secret> {
    pub fn from_sec1_pem(s: &str) -> Result<Self, PasetoError> {
        let sk = p384::SecretKey::from_sec1_pem(s).map_err(|_| PasetoError::Cryption)?;
        Ok(Self { key: sk.to_bytes() })
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

/// A key encoded in base64. It is not a secure serialization.
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

#[cfg(feature = "v4")]
impl From<Key<V4, Local>>
    for rusty_paseto::core::PasetoSymmetricKey<V4, rusty_paseto::core::Local>
{
    fn from(key: Key<V4, Local>) -> Self {
        let key: [u8; 32] = key.key.into();
        let key: rusty_paseto::core::Key<32> = key.into();
        key.into()
    }
}

#[cfg(feature = "v3")]
impl From<Key<V3, Local>>
    for rusty_paseto::core::PasetoSymmetricKey<V3, rusty_paseto::core::Local>
{
    fn from(key: Key<V3, Local>) -> Self {
        let key: [u8; 32] = key.key.into();
        let key: rusty_paseto::core::Key<32> = key.into();
        key.into()
    }
}

#[cfg(feature = "v4")]
impl From<Key<V4, Public>> for rusty_paseto::core::Key<32> {
    fn from(key: Key<V4, Public>) -> Self {
        let key: [u8; 32] = key.key.into();
        key.into()
    }
}

#[cfg(feature = "v4")]
impl From<Key<V4, Secret>> for rusty_paseto::core::Key<64> {
    fn from(key: Key<V4, Secret>) -> Self {
        let key: [u8; 64] = key.key.into();
        key.into()
    }
}

#[cfg(feature = "v3")]
impl From<Key<V3, Public>> for rusty_paseto::core::Key<49> {
    fn from(key: Key<V3, Public>) -> Self {
        let key: [u8; 49] = key.key.into();
        key.into()
    }
}

#[cfg(feature = "v3")]
impl From<Key<V3, Secret>> for rusty_paseto::core::Key<48> {
    fn from(key: Key<V3, Secret>) -> Self {
        let key: [u8; 48] = key.key.into();
        key.into()
    }
}
