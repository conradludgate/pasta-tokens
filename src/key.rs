use std::fmt;

use generic_array::{ArrayLength, GenericArray};

use crate::{PublicVersion, Version, local::{Local, LocalVersion}};

/// Public verifying/encrypting keys
#[derive(Debug, Default)]
pub struct Public;
/// Secret signing/decrypting keys
#[derive(Debug)]
pub struct Secret;

/// General information about key types
pub trait KeyType<V: Version> {
    /// Chooses the correct length from the version
    type KeyLen: ArrayLength<u8>;
    /// Header for this key type
    const HEADER: &'static str;
    /// ID header for this key type
    const ID: &'static str;
}

impl<V: PublicVersion> KeyType<V> for Public {
    type KeyLen = V::Public;
    const HEADER: &'static str = "public.";
    const ID: &'static str = "pid.";
}
impl<V: PublicVersion> KeyType<V> for Secret {
    type KeyLen = V::Secret;
    const HEADER: &'static str = "secret.";
    const ID: &'static str = "sid.";
}
impl<V: LocalVersion> KeyType<V> for Local {
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
