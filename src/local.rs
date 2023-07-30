use cipher::{KeyInit, StreamCipher, Unsigned};
use digest::Mac;
use generic_array::{ArrayLength, GenericArray};
use subtle::ConstantTimeEq;

use crate::{
    Bytes, EncryptedToken, Footer, KeyType, Message, MessageEncoding, PayloadEncoding,
    SymmetricKey, TokenType, UnencryptedToken, Version,
};

/// Local symmetric encryption/decrypting keys
#[derive(Debug, Default)]
pub struct Local;

impl TokenType for Local {
    const TOKEN_TYPE: &'static str = "local";
}

impl<V: LocalVersion> KeyType<V> for Local {
    type KeyLen = V::KeySize;
    const HEADER: &'static str = "local.";
    const ID: &'static str = "lid.";
}

/// General information about a PASETO/PASERK version
trait LocalEncryption: LocalVersion {
    type AuthKeySize: ArrayLength<u8>;
    type Cipher: GenericCipher;
    type Mac: GenericMac<Self::AuthKeySize>
        + GenericMac<Self::TagSize>
        + GenericMac<<Self::Cipher as GenericCipher>::KeyIvPair>;
}

/// General information about a PASETO/PASERK version
pub trait LocalVersion: Version {
    /// Size of the symmetric local key
    type KeySize: ArrayLength<u8>;

    type TagSize: ArrayLength<u8>;

    #[doc(hidden)]
    fn encrypt(
        key: &Bytes<Self::KeySize>,
        encoding_header: &[u8],
        message: &mut [u8],
        footer: &[u8],
        implicit: &[u8],
    ) -> ([u8; NONCE_LEN], Bytes<Self::TagSize>);

    #[doc(hidden)]
    #[allow(clippy::too_many_arguments, clippy::result_unit_err)]
    fn decrypt(
        key: &Bytes<Self::KeySize>,
        encoding_header: &[u8],
        nonce: &[u8],
        message: &mut [u8],
        tag: &[u8],
        footer: &[u8],
        implicit: &[u8],
    ) -> Result<(), ()>;
}

trait GenericMac<OutputSize: ArrayLength<u8>> {
    type Mac: digest::Mac<OutputSize = OutputSize> + KeyInit;
}

trait GenericCipher {
    type KeyIvPair: ArrayLength<u8>;
    type Stream: cipher::StreamCipher;
    fn key_iv_init(pair: GenericArray<u8, Self::KeyIvPair>) -> Self::Stream;
}

const NONCE_LEN: usize = 32;

fn generic_digest<V: LocalEncryption>(
    auth_key: &Bytes<V::AuthKeySize>,
    encoding_header: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    footer: &[u8],
    implicit: &[u8],
) -> Bytes<V::TagSize> {
    let mut mac =
        <<V::Mac as GenericMac<V::TagSize>>::Mac as digest::Mac>::new_from_slice(auth_key)
            .expect("ak should be a valid mac key");
    crate::pae::mac(
        [
            [V::PASETO_HEADER.as_bytes(), encoding_header],
            [nonce, b""],
            [ciphertext, b""],
            [footer, b""],
            [implicit, b""],
        ],
        &mut mac,
    );
    mac.finalize().into_bytes()
}

fn generic_encrypt<V: LocalEncryption, R: rand::Rng + rand::CryptoRng>(
    key: &Bytes<V::KeySize>,
    encoding_header: &[u8],
    message: &mut [u8],
    footer: &[u8],
    implicit: &[u8],
    rng: &mut R,
) -> ([u8; NONCE_LEN], Bytes<V::TagSize>) {
    let mut nonce = [0; NONCE_LEN];
    rng.fill(&mut nonce);

    let ek_iv_pair = <<V::Mac as GenericMac<<V::Cipher as GenericCipher>::KeyIvPair>>::Mac as digest::Mac>::new_from_slice(key)
        .expect("key should be a valid mac key")
        .chain_update(b"paseto-encryption-key")
        .chain_update(nonce)
        .finalize()
        .into_bytes();

    let ak = <<V::Mac as GenericMac<V::AuthKeySize>>::Mac as digest::Mac>::new_from_slice(key)
        .expect("key should be a valid mac key")
        .chain_update(b"paseto-auth-key-for-aead")
        .chain_update(nonce)
        .finalize()
        .into_bytes();

    <V::Cipher as GenericCipher>::key_iv_init(ek_iv_pair).apply_keystream(message);
    let tag = generic_digest::<V>(&ak, encoding_header, &nonce, message, footer, implicit);

    (nonce, tag)
}

fn generic_decrypt<V: LocalEncryption>(
    key: &Bytes<V::KeySize>,
    encoding_header: &[u8],
    nonce: &[u8],
    message: &mut [u8],
    tag: &[u8],
    footer: &[u8],
    implicit: &[u8],
) -> Result<(), ()> {
    let ek_iv_pair = <<V::Mac as GenericMac<<V::Cipher as GenericCipher>::KeyIvPair>>::Mac as digest::Mac>::new_from_slice(key)
        .expect("key should be a valid mac key")
        .chain_update(b"paseto-encryption-key")
        .chain_update(nonce)
        .finalize()
        .into_bytes();

    let ak = <<V::Mac as GenericMac<V::AuthKeySize>>::Mac as digest::Mac>::new_from_slice(key)
        .expect("key should be a valid mac key")
        .chain_update(b"paseto-auth-key-for-aead")
        .chain_update(nonce)
        .finalize()
        .into_bytes();

    let tag2 = generic_digest::<V>(&ak, encoding_header, nonce, message, footer, implicit);

    if tag.ct_ne(&tag2).into() {
        Err(())
    } else {
        <V::Cipher as GenericCipher>::key_iv_init(ek_iv_pair).apply_keystream(message);
        Ok(())
    }
}

#[cfg(feature = "v3")]
mod v3 {
    use cipher::KeyIvInit;
    use generic_array::{
        sequence::Split,
        typenum::{U32, U48},
    };

    use crate::{Bytes, Message, UnencryptedToken, V3};

    use super::{
        generic_decrypt, generic_encrypt, GenericCipher, GenericMac, LocalEncryption, LocalVersion,
        NONCE_LEN,
    };

    pub struct Hash;
    pub struct Cipher;

    impl GenericMac<U48> for Hash {
        type Mac = hmac::Hmac<sha2::Sha384>;
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
            m: &mut [u8],
            f: &[u8],
            i: &[u8],
        ) -> ([u8; NONCE_LEN], Bytes<Self::TagSize>) {
            generic_encrypt::<Self, _>(k, e, m, f, i, &mut rand::thread_rng())
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

    impl<M: Message> UnencryptedToken<crate::V3, M> {
        pub fn new_v3_local(message: M) -> Self {
            Self {
                version_header: crate::V3,
                token_type: super::Local,
                message,
                footer: (),
                encoding: crate::JsonEncoding,
            }
        }
    }
}

#[cfg(feature = "v4")]
mod v4 {
    use chacha20::XChaCha20;
    use cipher::KeyIvInit;
    use generic_array::{
        sequence::Split,
        typenum::{IsLessOrEqual, LeEq, NonZero, U32, U56, U64},
        ArrayLength, GenericArray,
    };

    use super::{
        generic_decrypt, generic_encrypt, GenericCipher, GenericMac, LocalEncryption, LocalVersion,
        NONCE_LEN,
    };
    use crate::{Bytes, Message, UnencryptedToken, V4};

    pub struct Hash;
    pub struct Cipher;

    impl<O> GenericMac<O> for Hash
    where
        O: ArrayLength<u8> + IsLessOrEqual<U64>,
        LeEq<O, U64>: NonZero,
    {
        type Mac = blake2::Blake2bMac<O>;
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
            m: &mut [u8],
            f: &[u8],
            i: &[u8],
        ) -> ([u8; NONCE_LEN], Bytes<Self::TagSize>) {
            generic_encrypt::<Self, _>(k, e, m, f, i, &mut rand::thread_rng())
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

    impl<M: Message> UnencryptedToken<V4, M> {
        pub fn new_v4_local(message: M) -> Self {
            Self {
                version_header: V4,
                token_type: super::Local,
                message,
                footer: (),
                encoding: crate::JsonEncoding,
            }
        }
    }
}

impl<V: LocalVersion, M: Message, F: Footer, E: MessageEncoding<M>> UnencryptedToken<V, M, F, E> {
    pub fn encrypt(
        self,
        key: &SymmetricKey<V>,
        implicit_assertions: &[u8],
    ) -> Result<EncryptedToken<V, F, E>, Box<dyn std::error::Error>> {
        let mut m = self.encoding.encode(&self.message)?;
        let f = self.footer.encode();
        let (nonce, tag) = V::encrypt(
            &key.key,
            E::SUFFIX.as_bytes(),
            &mut m,
            &f,
            implicit_assertions,
        );
        sandwich(&mut m, &nonce, &tag);

        Ok(EncryptedToken {
            version_header: self.version_header,
            token_type: self.token_type,
            message: m,
            encoded_footer: f,
            footer: self.footer,
            encoding: self.encoding,
        })
    }
}

impl<V: LocalVersion, F: Footer, E: PayloadEncoding> EncryptedToken<V, F, E> {
    pub fn decrypt<M: Message>(
        mut self,
        key: &SymmetricKey<V>,
        implicit_assertions: &[u8],
    ) -> Result<UnencryptedToken<V, M, F, E>, Box<dyn std::error::Error>>
    where
        E: MessageEncoding<M>,
    {
        let (n, m) = self.message.split_at_mut(NONCE_LEN);
        let (m, t) = m.split_at_mut(m.len() - <<V as LocalVersion>::TagSize as Unsigned>::USIZE);
        V::decrypt(
            &key.key,
            E::SUFFIX.as_bytes(),
            n,
            m,
            t,
            &self.encoded_footer,
            implicit_assertions,
        )
        .map_err(|_| "decryption error")?;

        let message = self.encoding.decode(m)?;

        Ok(UnencryptedToken {
            version_header: self.version_header,
            token_type: self.token_type,
            message,
            footer: self.footer,
            encoding: self.encoding,
        })
    }
}

/// Prepends `prepend` to `v` and appends `append`. Final output of `v` is `prepend || v || append`
fn sandwich(v: &mut Vec<u8>, prepend: &[u8; NONCE_LEN], append: &[u8]) {
    let additional = prepend.len() + append.len();
    let total = v.len() + additional;
    if total < v.capacity() {
        v.extend_from_slice(prepend);
        v.rotate_right(prepend.len())
    } else {
        let mut w = Vec::with_capacity(total);
        w.extend_from_slice(prepend);
        w.append(v);
        *v = w;
    }

    v.extend_from_slice(append)
}
