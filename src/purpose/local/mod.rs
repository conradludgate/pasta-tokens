//! PASETO shared-key authenticated encryption
//!
//! Example use cases:
//! * Tamper-proof, short-lived immutable data stored on client machines.
//!   + e.g. "remember me on this computer" cookies, which secure a unique ID that are used in a database lookup upon successful validation to provide long-term user authentication across multiple browsing sessions.

use cipher::{KeyInit, StreamCipher, Unsigned};
use digest::Mac;
use generic_array::{ArrayLength, GenericArray};
use rand::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

use crate::{
    encodings::{MessageEncoding, Payload, MessageDecoding},
    key::KeyType,
    purpose::Purpose,
    version::Version,
    Bytes, Footer, PasetoError, TokenMetadata,
};

/// A symmetric key for `local` encrypted tokens
pub type SymmetricKey<V> = crate::key::Key<V, Local>;

/// An decrypted PASETO.
pub type DecryptedToken<V, M, F = (), E = crate::Json<()>> =
    crate::tokens::ValidatedToken<V, Local, M, F, E>;
/// An encrypted PASETO.
pub type EncryptedToken<V, F = (), E = crate::Json<()>> =
    crate::tokens::SecuredToken<V, Local, F, E>;
/// An unencrypted PASETO.
pub type UnencryptedToken<V, M, F = (), E = crate::Json<()>> =
    crate::tokens::TokenBuilder<V, Local, M, F, E>;

/// PASETO shared-key authenticated encryption
///
/// Example use cases:
/// * Tamper-proof, short-lived immutable data stored on client machines.
///   + e.g. "remember me on this computer" cookies, which secure a unique ID that are used in a database lookup upon successful validation to provide long-term user authentication across multiple browsing sessions.
#[derive(Debug, Default)]
pub struct Local;

impl super::Purpose for Local {
    const HEADER: &'static str = "local";
}

#[cfg(feature = "v4-local")]
mod v4;

#[cfg(feature = "v3-local")]
mod v3;

impl<V: LocalVersion> KeyType<V> for Local {
    type KeyLen = V::KeySize;
    const KEY_HEADER: &'static str = "local.";
    const ID: &'static str = "lid.";
}

/// General information about a PASETO/PASERK version
pub(crate) trait LocalEncryption: LocalVersion {
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

pub(crate) trait GenericMac<OutputSize: ArrayLength<u8>> {
    type Mac: digest::Mac<OutputSize = OutputSize> + KeyInit;
}

pub(crate) trait Kdf<OutputSize: ArrayLength<u8>> {
    fn mac<const N: usize>(key: &[u8], info: [&[u8]; N]) -> Bytes<OutputSize>;
}

pub(crate) trait GenericCipher {
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
                Local::HEADER.as_bytes(),
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

#[allow(dead_code)]
pub(crate) fn generic_encrypt<V: LocalEncryption>(
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

#[allow(dead_code)]
pub(crate) fn generic_decrypt<V: LocalEncryption>(
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

impl<V: LocalVersion, M, F: Footer, E: MessageEncoding<M>> DecryptedToken<V, M, F, E> {
    fn encrypt_inner(
        self,
        key: &SymmetricKey<V>,
        nonce: [u8; NONCE_LEN],
        implicit_assertions: &[u8],
    ) -> Result<EncryptedToken<V, F, E>, PasetoError> {
        let mut m = self
            .meta
            .encoding
            .encode(&self.message)
            .map_err(PasetoError::PayloadError)?;
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
            meta: self.meta,
            payload: m,
            encoded_footer: f,
            footer: self.footer,
        })
    }
}

impl<V: LocalVersion, M> UnencryptedToken<V, M> {
    /// Create a new [`EncryptedToken`] builder with the given message payload
    pub fn new(message: M) -> Self {
        Self(DecryptedToken {
            meta: TokenMetadata::default(),
            message,
            footer: (),
        })
    }
}

impl<V: LocalVersion, M, F: Footer, E: MessageEncoding<M>> UnencryptedToken<V, M, F, E> {
    /// Encrypt the token using a random nonce and no implicit assertions
    pub fn encrypt(self, key: &SymmetricKey<V>) -> Result<EncryptedToken<V, F, E>, PasetoError> {
        self.encrypt_with_assertions(key, &[])
    }

    /// Encrypt the token with implciit assertions
    ///
    /// ### Implicit Assertions
    ///
    /// PASETO `v3` and `v4` tokens support a feature called **implicit assertions**, which are used
    /// in the calculation of the MAC (`local` tokens) or digital signature (`public` tokens), but
    /// **NOT** stored in the token. (Thus, its implicitness.)
    ///
    /// An implicit assertion MUST be provided by the caller explicitly when validating a PASETO token
    /// if it was provided at the time of creation.
    pub fn encrypt_with_assertions(
        self,
        key: &SymmetricKey<V>,
        implicit_assertions: &[u8],
    ) -> Result<EncryptedToken<V, F, E>, PasetoError> {
        self.encrypt_with_assertions_and_rng(key, implicit_assertions, rand::thread_rng())
    }

    /// Encrypt the token with implciit assertions
    ///
    /// ### Implicit Assertions
    ///
    /// PASETO `v3` and `v4` tokens support a feature called **implicit assertions**, which are used
    /// in the calculation of the MAC (`local` tokens) or digital signature (`public` tokens), but
    /// **NOT** stored in the token. (Thus, its implicitness.)
    ///
    /// An implicit assertion MUST be provided by the caller explicitly when validating a PASETO token
    /// if it was provided at the time of creation.
    pub fn encrypt_with_assertions_and_rng(
        self,
        key: &SymmetricKey<V>,
        implicit_assertions: &[u8],
        mut rng: impl CryptoRng + RngCore,
    ) -> Result<EncryptedToken<V, F, E>, PasetoError> {
        let mut nonce = [0; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        self.0.encrypt_inner(key, nonce, implicit_assertions)
    }
}

impl<V: LocalVersion, F: Footer, E: Payload> EncryptedToken<V, F, E> {
    /// Decrypt the token
    pub fn decrypt<M>(
        self,
        key: &SymmetricKey<V>,
    ) -> Result<DecryptedToken<V, M, F, E>, PasetoError>
    where
        E: MessageDecoding<M>,
    {
        self.decrypt_with_assertions(key, &[])
    }

    /// Decrypt the token with implicit assertions
    ///
    /// ### Implicit Assertions
    ///
    /// PASETO `v3` and `v4` tokens support a feature called **implicit assertions**, which are used
    /// in the calculation of the MAC (`local` tokens) or digital signature (`public` tokens), but
    /// **NOT** stored in the token. (Thus, its implicitness.)
    ///
    /// An implicit assertion MUST be provided by the caller explicitly when validating a PASETO token
    /// if it was provided at the time of creation.
    pub fn decrypt_with_assertions<M>(
        mut self,
        key: &SymmetricKey<V>,
        implicit_assertions: &[u8],
    ) -> Result<DecryptedToken<V, M, F, E>, PasetoError>
    where
        E: MessageDecoding<M>,
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
        .map_err(|_| PasetoError::CryptoError)?;

        let message = self
            .meta
            .encoding
            .decode(m)
            .map_err(PasetoError::PayloadError)?;

        Ok(DecryptedToken {
            meta: self.meta,
            message,
            footer: self.footer,
        })
    }
}

/// Prepends `prepend` to `v` and appends `append`. Final output of `v` is `prepend || v || append`
fn sandwich(v: &mut Vec<u8>, prepend: &[u8; NONCE_LEN], append: &[u8]) {
    let additional = prepend.len() + append.len();
    let total = v.len() + additional;
    let mut w = Vec::with_capacity(total);
    w.extend_from_slice(prepend);
    w.append(v);
    *v = w;
    v.extend_from_slice(append)
}
