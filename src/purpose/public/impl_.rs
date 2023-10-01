use cipher::Unsigned;
use generic_array::ArrayLength;

use crate::{
    encodings::{MessageEncoding, PayloadEncoding},
    version::Version,
    Bytes, Footer, TokenMetadata,
};

use super::{PublicKey, SecretKey, SignedToken, UnsignedToken, VerifiedToken};

/// General information about a PASETO/PASERK version
pub trait PublicVersion: Version {
    /// Size of the asymmetric public key
    type PublicKeySize: ArrayLength<u8>;
    /// Size of the asymmetric secret key
    type SecretKeySize: ArrayLength<u8>;

    /// Length of the signature this signing version produces
    type Signature: ArrayLength<u8>;

    #[doc(hidden)]
    fn sign(
        sk: &Bytes<Self::SecretKeySize>,
        h: &[u8],
        m: &[u8],
        f: &[u8],
        i: &[u8],
    ) -> Bytes<Self::Signature>;

    #[doc(hidden)]
    fn verify(
        k: &Bytes<Self::PublicKeySize>,
        h: &[u8],
        m: &[u8],
        f: &[u8],
        i: &[u8],
        sig: &Bytes<Self::Signature>,
    ) -> Result<(), signature::Error>;
}

impl<V: PublicVersion, M, F: Footer, E: MessageEncoding<M>> UnsignedToken<V, M, F, E> {
    /// Sign this token
    ///
    /// ### Implicit Assertions
    ///
    /// PASETO `v3` and `v4` tokens support a feature called **implicit assertions**, which are used
    /// in the calculation of the MAC (`local` tokens) or digital signature (`public` tokens), but
    /// **NOT** stored in the token. (Thus, its implicitness.)
    ///
    /// An implicit assertion MUST be provided by the caller explicitly when validating a PASETO token
    /// if it was provided at the time of creation.
    pub fn sign(
        self,
        key: &SecretKey<V>,
        implicit_assertions: &[u8],
    ) -> Result<SignedToken<V, F, E>, Box<dyn std::error::Error>> {
        let mut m = self.0.meta.encoding.encode(&self.0.message)?;
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
    pub fn new(message: M) -> Self {
        Self(VerifiedToken {
            meta: TokenMetadata::default(),
            message,
            footer: (),
        })
    }
}

impl<V: PublicVersion, F: Footer, E: PayloadEncoding> SignedToken<V, F, E> {
    /// Verify that this token was signed with the associated key
    ///
    /// ### Implicit Assertions
    ///
    /// PASETO `v3` and `v4` tokens support a feature called **implicit assertions**, which are used
    /// in the calculation of the MAC (`local` tokens) or digital signature (`public` tokens), but
    /// **NOT** stored in the token. (Thus, its implicitness.)
    ///
    /// An implicit assertion MUST be provided by the caller explicitly when validating a PASETO token
    /// if it was provided at the time of creation.
    pub fn verify<M>(
        self,
        key: &PublicKey<V>,
        implicit_assertions: &[u8],
    ) -> Result<VerifiedToken<V, M, F, E>, Box<dyn std::error::Error>>
    where
        E: MessageEncoding<M>,
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
        .map_err(|_| "decryption error")?;

        let message = self.meta.encoding.decode(m)?;

        Ok(VerifiedToken {
            meta: self.meta,
            message,
            footer: self.footer,
        })
    }
}
