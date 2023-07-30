use cipher::KeyIvInit;
use generic_array::{
    sequence::Split,
    typenum::{U32, U48},
    ArrayLength,
};

use crate::{Bytes, UnencryptedToken, V3};

use super::{
    generic_decrypt, generic_encrypt, GenericCipher, GenericMac, Kdf, LocalEncryption, LocalVersion,
};

pub struct Hash;
pub struct Cipher;

impl GenericMac<U48> for Hash {
    type Mac = hmac::Hmac<sha2::Sha384>;
}

impl<O> Kdf<O> for Hash
where
    O: ArrayLength<u8>,
{
    fn mac<const N: usize>(key: &[u8], info: [&[u8]; N]) -> Bytes<O> {
        let mut output = Bytes::<O>::default();
        hkdf::Hkdf::<sha2::Sha384>::new(None, key)
            .expand_multi_info(&info, &mut output)
            .unwrap();
        output
    }
}

impl GenericCipher for Cipher {
    type KeyIvPair = U48;

    type Stream = ctr::Ctr64BE<aes::Aes256>;

    fn key_iv_init(pair: Bytes<Self::KeyIvPair>) -> Self::Stream {
        let (key, iv) = pair.split();
        Self::Stream::new(&key, &iv)
    }
}

impl LocalVersion for V3 {
    type KeySize = U32;

    type TagSize = U48;

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

impl LocalEncryption for V3 {
    type AuthKeySize = U48;
    type Cipher = Cipher;
    type Mac = Hash;
}

impl<M> UnencryptedToken<crate::V3, M> {
    /// Create a new V3 [`EncryptedToken`](crate::EncryptedToken) builder with the given message payload
    pub fn new_v3_local(message: M) -> Self {
        Self {
            version_header: crate::V3,
            token_type: super::Local,
            message,
            footer: (),
            encoding: crate::Json(()),
        }
    }
}
