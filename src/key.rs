use std::fmt;

use generic_array::{ArrayLength, GenericArray};

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
#[derive(Debug)]
pub struct Public;
/// Secret signing/decrypting keys
#[derive(Debug)]
pub struct Secret;
/// Local symmetric encryption/decrypting keys
#[derive(Debug)]
pub struct Local;

/// General information about key types
pub trait KeyType<V: Version> {
    /// Chooses the correct length from the version
    type KeyLen: ArrayLength<u8>;
    /// Header for this key type
    const HEADER: &'static str;
    /// ID header for this key type
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

impl<V: Version, K: KeyType<V>> Copy for Key<V, K> where GenericArray<u8, K::KeyLen>: Copy {}

impl<V: Version, K: KeyType<V>> fmt::Debug for Key<V, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_struct("Key");
        if cfg!(fuzzing_repro) {
            f.field("key", &self.key).finish()
        } else {
            f.finish_non_exhaustive()
        }
    }
}

mod convert;

#[cfg(feature = "arbitrary")]
mod arbitrary;

pub mod plaintext;
