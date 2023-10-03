//! PASETO public signatures
//!
//! Example use cases:
//! * Transparent claims provided by a third party.
//!   + e.g. Authentication and authorization protocols (OAuth 2, OIDC).

use cipher::Unsigned;
use generic_array::ArrayLength;

use crate::{
    encodings::{MessageDecoding, MessageEncoding, Payload},
    version::Version,
    Bytes, Footer, PasetoError,
};

#[cfg(feature = "v4-public")]
mod v4;

#[cfg(feature = "v3-public")]
mod v3;

/// PASETO public signatures
///
/// Example use cases:
/// * Transparent claims provided by a third party.
///   + e.g. Authentication and authorization protocols (OAuth 2, OIDC).
#[derive(Debug, Default)]
pub struct Public;

/// Secret signing/decrypting keys
#[derive(Debug)]
pub struct Secret;

impl super::Purpose for Public {
    const HEADER: &'static str = "public";
}

/// A public key for verifying `public` tokens
pub type PublicKey<V> = crate::key::Key<V, Public>;
/// A secret key for signing `public` tokens
pub type SecretKey<V> = crate::key::Key<V, Secret>;

/// A Verified PASETO that has been parsed and verified
pub type VerifiedToken<V, M, F = (), E = crate::Json<()>> =
    crate::tokens::ValidatedToken<V, Public, M, F, E>;

/// A Signed PASETO.
pub type SignedToken<V, F = (), E = crate::Json<()>> = crate::tokens::SecuredToken<V, Public, F, E>;

/// A PASETO that is ready to be signed.
pub type UnsignedToken<V, M, F = (), E = crate::Json<()>> =
    crate::tokens::TokenBuilder<V, Public, M, F, E>;

impl<V: PublicVersion> crate::key::KeyType<V> for Public {
    type KeyLen = V::PublicKeySize;
    const KEY_HEADER: &'static str = "public.";
    const ID: &'static str = "pid.";

    type InnerKeyType = V::InnerPublicKeyType;
    fn to_bytes(k: &Self::InnerKeyType) -> Bytes<Self::KeyLen> {
        V::to_public_bytes(k)
    }
    fn from_bytes(k: Bytes<Self::KeyLen>) -> Result<Self::InnerKeyType, PasetoError> {
        V::from_public_bytes(k)
    }
}

impl<V: PublicVersion> crate::key::KeyType<V> for Secret {
    type KeyLen = V::SecretKeySize;
    const KEY_HEADER: &'static str = "secret.";
    const ID: &'static str = "sid.";

    type InnerKeyType = V::InnerSecretKeyType;
    fn to_bytes(k: &Self::InnerKeyType) -> Bytes<Self::KeyLen> {
        V::to_secret_bytes(k)
    }
    fn from_bytes(k: Bytes<Self::KeyLen>) -> Result<Self::InnerKeyType, PasetoError> {
        V::from_secret_bytes(k)
    }
}

/// General information about a PASETO/PASERK version
pub trait PublicVersion: Version {
    /// Size of the asymmetric public key
    type PublicKeySize: ArrayLength<u8>;
    /// Size of the asymmetric secret key
    type SecretKeySize: ArrayLength<u8>;

    /// Length of the signature this signing version produces
    type Signature: ArrayLength<u8>;

    #[doc(hidden)]
    type InnerPublicKeyType: Clone;
    #[doc(hidden)]
    type InnerSecretKeyType: Clone;
    #[doc(hidden)]
    fn from_secret_bytes(
        k: Bytes<Self::SecretKeySize>,
    ) -> Result<Self::InnerSecretKeyType, PasetoError>;
    #[doc(hidden)]
    fn from_public_bytes(
        k: Bytes<Self::PublicKeySize>,
    ) -> Result<Self::InnerPublicKeyType, PasetoError>;
    #[doc(hidden)]
    fn to_secret_bytes(k: &Self::InnerSecretKeyType) -> Bytes<Self::SecretKeySize>;
    #[doc(hidden)]
    fn to_public_bytes(k: &Self::InnerPublicKeyType) -> Bytes<Self::PublicKeySize>;

    #[doc(hidden)]
    fn sign(
        sk: &Self::InnerSecretKeyType,
        h: &[u8],
        m: &[u8],
        f: &[u8],
        i: &[u8],
    ) -> Bytes<Self::Signature>;

    #[doc(hidden)]
    fn verify(
        k: &Self::InnerPublicKeyType,
        h: &[u8],
        m: &[u8],
        f: &[u8],
        i: &[u8],
        sig: &Bytes<Self::Signature>,
    ) -> Result<(), signature::Error>;
}

impl<V: PublicVersion, M, F: Footer, E: MessageEncoding<M>> UnsignedToken<V, M, F, E> {
    /// Sign this token
    pub fn sign(self, key: &SecretKey<V>) -> Result<SignedToken<V, F, E>, PasetoError> {
        self.sign_with_assertions(key, &[])
    }

    /// Sign this token with implicit assertions
    ///
    /// ### Implicit Assertions
    ///
    /// PASETO `v3` and `v4` tokens support a feature called **implicit assertions**, which are used
    /// in the calculation of the MAC (`local` tokens) or digital signature (`public` tokens), but
    /// **NOT** stored in the token. (Thus, its implicitness.)
    ///
    /// An implicit assertion MUST be provided by the caller explicitly when validating a PASETO token
    /// if it was provided at the time of creation.
    pub fn sign_with_assertions(
        self,
        key: &SecretKey<V>,
        implicit_assertions: &[u8],
    ) -> Result<SignedToken<V, F, E>, PasetoError> {
        let mut m = self
            .0
            .meta
            .encoding
            .encode(&self.0.message)
            .map_err(PasetoError::PayloadError)?;
        let f = self.0.footer.encode();
        let sig = V::sign(&key.key, E::SUFFIX.as_bytes(), &m, &f, implicit_assertions);
        m.extend_from_slice(&sig);

        Ok(SignedToken {
            meta: self.0.meta,
            payload: m,
            encoded_footer: f,
            footer: self.0.footer,
        })
    }
}

impl<V: PublicVersion, M> UnsignedToken<V, M> {
    /// Create a new [`SignedToken`] builder with the given message payload
    pub fn new_unsigned(message: M) -> Self {
        Self::new(message)
    }
}

impl<V: PublicVersion, F: Footer, E: Payload> SignedToken<V, F, E> {
    /// Verify that this token was signed with the associated key
    pub fn verify<M>(self, key: &PublicKey<V>) -> Result<VerifiedToken<V, M, F, E>, PasetoError>
    where
        E: MessageDecoding<M>,
    {
        self.verify_with_assertions(key, &[])
    }

    /// Verify that this token was signed with the associated key and with the implicit assertions
    ///
    /// ### Implicit Assertions
    ///
    /// PASETO `v3` and `v4` tokens support a feature called **implicit assertions**, which are used
    /// in the calculation of the MAC (`local` tokens) or digital signature (`public` tokens), but
    /// **NOT** stored in the token. (Thus, its implicitness.)
    ///
    /// An implicit assertion MUST be provided by the caller explicitly when validating a PASETO token
    /// if it was provided at the time of creation.
    pub fn verify_with_assertions<M>(
        self,
        key: &PublicKey<V>,
        implicit_assertions: &[u8],
    ) -> Result<VerifiedToken<V, M, F, E>, PasetoError>
    where
        E: MessageDecoding<M>,
    {
        let (m, sig) = self
            .payload
            .split_at(self.payload.len() - <<V as PublicVersion>::Signature as Unsigned>::USIZE);

        V::verify(
            &key.key,
            E::SUFFIX.as_bytes(),
            m,
            &self.encoded_footer,
            implicit_assertions,
            sig.into(),
        )
        .map_err(|_| PasetoError::CryptoError)?;

        let message = self
            .meta
            .encoding
            .decode(m)
            .map_err(PasetoError::PayloadError)?;

        Ok(VerifiedToken {
            meta: self.meta,
            message,
            footer: self.footer,
        })
    }
}
