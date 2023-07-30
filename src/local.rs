//! PASETO local encryption
//!
//! Example use cases:
//! * Tamper-proof, short-lived immutable data stored on client machines.
//!   + e.g. "remember me on this computer" cookies, which secure a unique ID that are used in a database lookup upon successful validation to provide long-term user authentication across multiple browsing sessions.

use cipher::{KeyInit, StreamCipher, Unsigned};
use digest::Mac;
use generic_array::{ArrayLength, GenericArray};
use rand::Rng;
use subtle::ConstantTimeEq;

use crate::{
    Bytes, EncryptedToken, Footer, KeyType, MessageEncoding, PayloadEncoding, SymmetricKey,
    TokenType, UnencryptedToken, Version,
};

/// PASETO local encryption
///
/// Example use cases:
/// * Tamper-proof, short-lived immutable data stored on client machines.
///   + e.g. "remember me on this computer" cookies, which secure a unique ID that are used in a database lookup upon successful validation to provide long-term user authentication across multiple browsing sessions.
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
    type Mac: Kdf<Self::AuthKeySize>
        + Kdf<<Self::Cipher as GenericCipher>::KeyIvPair>
        + GenericMac<Self::TagSize>;
}

/// General information about a PASETO/PASERK version
pub trait LocalVersion: Version {
    /// Size of the symmetric local key
    type KeySize: ArrayLength<u8>;

    /// The size of the authentication tag that this encryption version produces
    type TagSize: ArrayLength<u8>;

    #[doc(hidden)]
    fn encrypt(
        key: &Bytes<Self::KeySize>,
        encoding_header: &[u8],
        nonce: &[u8],
        message: &mut [u8],
        footer: &[u8],
        implicit: &[u8],
    ) -> Bytes<Self::TagSize>;

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

trait Kdf<OutputSize: ArrayLength<u8>> {
    fn mac<const N: usize>(key: &[u8], info: [&[u8]; N]) -> Bytes<OutputSize>;
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
    crate::pae::pae(
        [
            &[
                V::PASETO_HEADER.as_bytes(),
                encoding_header,
                b".",
                Local::TOKEN_TYPE.as_bytes(),
                b".",
            ],
            &[nonce],
            &[ciphertext],
            &[footer],
            &[implicit],
        ],
        &mut crate::pae::Mac(&mut mac),
    );
    mac.finalize().into_bytes()
}

fn generic_encrypt<V: LocalEncryption>(
    key: &Bytes<V::KeySize>,
    encoding_header: &[u8],
    nonce: &[u8],
    message: &mut [u8],
    footer: &[u8],
    implicit: &[u8],
) -> Bytes<V::TagSize> {
    let ek_iv_pair = <V::Mac as Kdf<<V::Cipher as GenericCipher>::KeyIvPair>>::mac(
        key,
        [b"paseto-encryption-key", nonce],
    );

    let ak = <V::Mac as Kdf<V::AuthKeySize>>::mac(key, [b"paseto-auth-key-for-aead", nonce]);

    <V::Cipher as GenericCipher>::key_iv_init(ek_iv_pair).apply_keystream(message);

    generic_digest::<V>(&ak, encoding_header, nonce, message, footer, implicit)
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
    let ek_iv_pair = <V::Mac as Kdf<<V::Cipher as GenericCipher>::KeyIvPair>>::mac(
        key,
        [b"paseto-encryption-key", nonce],
    );

    let ak = <V::Mac as Kdf<V::AuthKeySize>>::mac(key, [b"paseto-auth-key-for-aead", nonce]);

    let tag2 = generic_digest::<V>(&ak, encoding_header, nonce, message, footer, implicit);

    if tag.ct_ne(&tag2).into() {
        Err(())
    } else {
        <V::Cipher as GenericCipher>::key_iv_init(ek_iv_pair).apply_keystream(message);
        Ok(())
    }
}

#[cfg(feature = "v3-local")]
#[cfg_attr(docsrs, doc(cfg(feature = "v3-local")))]
mod v3 {
    use cipher::KeyIvInit;
    use generic_array::{
        sequence::Split,
        typenum::{U32, U48},
        ArrayLength,
    };

    use crate::{Bytes, UnencryptedToken, V3};

    use super::{
        generic_decrypt, generic_encrypt, GenericCipher, GenericMac, Kdf, LocalEncryption,
        LocalVersion,
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
}

#[cfg(feature = "v4-local")]
#[cfg_attr(docsrs, doc(cfg(feature = "v4-local")))]
mod v4 {
    use chacha20::XChaCha20;
    use cipher::KeyIvInit;
    use digest::{FixedOutput, Mac};
    use generic_array::{
        sequence::Split,
        typenum::{IsLessOrEqual, LeEq, NonZero, U32, U56, U64},
        ArrayLength, GenericArray,
    };

    use super::{
        generic_decrypt, generic_encrypt, GenericCipher, GenericMac, Kdf, LocalEncryption,
        LocalVersion,
    };
    use crate::{Bytes, UnencryptedToken, V4};

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
            let mut mac =
                blake2::Blake2bMac::<O>::new_from_slice(key).expect("key should be valid");
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

    impl<M> UnencryptedToken<V4, M> {
        /// Create a new V4 [`EncryptedToken`](crate::EncryptedToken) builder with the given message payload
        pub fn new_v4_local(message: M) -> Self {
            Self {
                version_header: V4,
                token_type: super::Local,
                message,
                footer: (),
                encoding: crate::Json(()),
            }
        }
    }
}

impl<V: LocalVersion, M, F: Footer, E: MessageEncoding<M>> UnencryptedToken<V, M, F, E> {
    fn encrypt_inner(
        self,
        key: &SymmetricKey<V>,
        nonce: [u8; NONCE_LEN],
        implicit_assertions: &[u8],
    ) -> Result<EncryptedToken<V, F, E>, Box<dyn std::error::Error>> {
        let mut m = self.encoding.encode(&self.message)?;
        let f = self.footer.encode();

        let tag = V::encrypt(
            &key.key,
            E::SUFFIX.as_bytes(),
            &nonce,
            &mut m,
            &f,
            implicit_assertions,
        );
        sandwich(&mut m, &nonce, &tag);

        Ok(EncryptedToken {
            version_header: self.version_header,
            token_type: self.token_type,
            payload: m,
            encoded_footer: f,
            footer: self.footer,
            encoding: self.encoding,
        })
    }

    /// Encrypt the token
    ///
    /// ### Implicit Assertions
    ///
    /// PASETO `v3` and `v4` tokens support a feature called **implicit assertions**, which are used
    /// in the calculation of the MAC (`local` tokens) or digital signature (`public` tokens), but
    /// **NOT** stored in the token. (Thus, its implicitness.)
    ///
    /// An implicit assertion MUST be provided by the caller explicitly when validating a PASETO token
    /// if it was provided at the time of creation.
    pub fn encrypt(
        self,
        key: &SymmetricKey<V>,
        implicit_assertions: &[u8],
    ) -> Result<EncryptedToken<V, F, E>, Box<dyn std::error::Error>> {
        self.encrypt_inner(key, rand::thread_rng().gen(), implicit_assertions)
    }

    #[doc(hidden)]
    #[cfg(feature = "test")]
    pub fn encrypt_with_nonce(
        self,
        key: &SymmetricKey<V>,
        nonce: [u8; 32],
        implicit_assertions: &[u8],
    ) -> Result<EncryptedToken<V, F, E>, Box<dyn std::error::Error>> {
        self.encrypt_inner(key, nonce, implicit_assertions)
    }
}

impl<V: LocalVersion, F: Footer, E: PayloadEncoding> EncryptedToken<V, F, E> {
    /// Decrypt the token
    ///
    /// ### Implicit Assertions
    ///
    /// PASETO `v3` and `v4` tokens support a feature called **implicit assertions**, which are used
    /// in the calculation of the MAC (`local` tokens) or digital signature (`public` tokens), but
    /// **NOT** stored in the token. (Thus, its implicitness.)
    ///
    /// An implicit assertion MUST be provided by the caller explicitly when validating a PASETO token
    /// if it was provided at the time of creation.
    pub fn decrypt<M>(
        mut self,
        key: &SymmetricKey<V>,
        implicit_assertions: &[u8],
    ) -> Result<UnencryptedToken<V, M, F, E>, Box<dyn std::error::Error>>
    where
        E: MessageEncoding<M>,
    {
        let (n, m) = self.payload.split_at_mut(NONCE_LEN);
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
