//! PASETO Keys

use std::fmt;

use generic_array::ArrayLength;

use crate::{version::Version, Bytes, PasetoError};

/// General information about key types
pub trait KeyType<V: Version> {
    #[doc(hidden)]
    type InnerKeyType: Clone;
    #[doc(hidden)]
    fn to_bytes(k: &Self::InnerKeyType) -> Bytes<Self::KeyLen>;
    #[doc(hidden)]
    fn from_bytes(k: Bytes<Self::KeyLen>) -> Result<Self::InnerKeyType, PasetoError>;

    /// Chooses the correct length from the version
    type KeyLen: ArrayLength<u8>;
    /// Header for this key type
    const KEY_HEADER: &'static str;
    /// ID header for this key type
    const ID: &'static str;
}

/// A PASETO key.
///
/// It is [versioned](crate::version) and [typed](crate::purpose) to ensure that keys are not used for different ciphers and purposes.
pub struct Key<V: Version, K: KeyType<V>> {
    // the box is required for securely clearing the bytes
    pub(crate) key: Box<K::InnerKeyType>,
}

impl<V: Version, K: KeyType<V>> core::cmp::PartialEq for Key<V, K> {
    fn eq(&self, other: &Self) -> bool {
        K::to_bytes(&self.key) == K::to_bytes(&other.key)
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

// impl<V: Version, K: KeyType<V>> Copy for Key<V, K> where crate::Bytes<K::KeyLen>: Copy {}

impl<V: Version, K: KeyType<V>> fmt::Debug for Key<V, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_struct("Key");
        if cfg!(fuzzing_repro) {
            f.field("key", &K::to_bytes(&self.key)).finish()
        } else {
            f.finish_non_exhaustive()
        }
    }
}

mod convert;

#[cfg(fuzzing)]
mod arbitrary;
