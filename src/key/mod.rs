//! PASETO Keys

use std::fmt;

use generic_array::{ArrayLength, GenericArray};

use crate::version::Version;

/// General information about key types
pub trait KeyType<V: Version> {
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
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Key<V: Version, K: KeyType<V>> {
    // the box is required for securely clearing the bytes
    pub(crate) key: Box<GenericArray<u8, K::KeyLen>>,
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

// impl<V: Version, K: KeyType<V>> Copy for Key<V, K> where GenericArray<u8, K::KeyLen>: Copy {}

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