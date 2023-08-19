use chacha20::XChaCha20;
use cipher::KeyIvInit;
use digest::{FixedOutput, Mac};
use generic_array::{
    sequence::Split,
    typenum::{IsLessOrEqual, LeEq, NonZero, U32, U56, U64},
    ArrayLength, GenericArray,
};

use super::{
    generic_decrypt, generic_encrypt, GenericCipher, GenericMac, Kdf, LocalEncryption, LocalVersion,
};
use crate::{version::V4, Bytes};

pub struct Hash;
pub struct Cipher;

impl<O> GenericMac<O> for Hash
where
    O: ArrayLength<u8> + IsLessOrEqual<U64>,
    LeEq<O, U64>: NonZero,
{
    type Mac = blake2::Blake2bMac<O>;
}

impl<O> Kdf<O> for Hash
where
    O: ArrayLength<u8> + IsLessOrEqual<U64>,
    LeEq<O, U64>: NonZero,
{
    fn mac<const N: usize>(key: &[u8], info: [&[u8]; N]) -> Bytes<O> {
        let mut mac = blake2::Blake2bMac::<O>::new_from_slice(key).expect("key should be valid");
        for i in info {
            mac.update(i);
        }
        mac.finalize_fixed()
    }
}

impl GenericCipher for Cipher {
    type KeyIvPair = U56;

    type Stream = XChaCha20;

    fn key_iv_init(pair: GenericArray<u8, Self::KeyIvPair>) -> Self::Stream {
        let (key, iv) = pair.split();
        XChaCha20::new(&key, &iv)
    }
}

impl LocalVersion for V4 {
    type KeySize = U32;

    type TagSize = U32;

    fn encrypt(
        k: &Bytes<Self::KeySize>,
        e: &[u8],
        n: &[u8],
        m: &mut [u8],
        f: &[u8],
        i: &[u8],
    ) -> Bytes<Self::TagSize> {
        generic_encrypt::<Self>(k, e, n, m, f, i)
    }

    fn decrypt(
        k: &Bytes<Self::KeySize>,
        h: &[u8],
        n: &[u8],
        m: &mut [u8],
        t: &[u8],
        f: &[u8],
        i: &[u8],
    ) -> Result<(), ()> {
        generic_decrypt::<Self>(k, h, n, m, t, f, i)
    }
}

impl LocalEncryption for V4 {
    type AuthKeySize = U32;
    type Cipher = Cipher;
    type Mac = Hash;
}

impl<M> super::UnencryptedToken<V4, M> {
    /// Create a new [`V4`] [`EncryptedToken`](super::EncryptedToken) builder with the given message payload
    pub fn new_v4_local(message: M) -> Self {
        Self::new(message)
    }
}
