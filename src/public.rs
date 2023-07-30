use cipher::Unsigned;
use digest::Digest;
use generic_array::ArrayLength;
use signature::{DigestSigner, DigestVerifier};

use crate::{
    Bytes, Footer, JsonEncoding, Key, KeyType, Message, MessageEncoding, PayloadEncoding,
    PublicKey, SecretKey, SignedToken, TokenType, UnsignedToken, Version,
};

/// General information about a PASETO/PASERK version
pub trait PublicVersion: Version {
    /// Size of the asymmetric public key
    type Public: ArrayLength<u8>;
    /// Size of the asymmetric secret key
    type Secret: ArrayLength<u8>;

    type Signature: ArrayLength<u8>;
    type SigningKey: signature::DigestSigner<Self::SignatureDigest, Bytes<Self::Signature>>;
    type VerifyingKey: signature::DigestVerifier<Self::SignatureDigest, Bytes<Self::Signature>>;
    type SignatureDigest: digest::Digest;

    fn signing_key(key: &Bytes<Self::Secret>) -> Self::SigningKey;
    fn verifying_key(key: &Bytes<Self::Public>) -> Self::VerifyingKey;
}

/// Public verifying/encrypting keys
#[derive(Debug, Default)]
pub struct Public;

/// Secret signing/decrypting keys
#[derive(Debug)]
pub struct Secret;

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

impl TokenType for Public {
    const TOKEN_TYPE: &'static str = "public";
}

#[cfg(feature = "v4")]
impl<M> UnsignedToken<crate::V4, M> {
    pub fn new_v4_public(message: M) -> Self {
        Self {
            version_header: crate::V4,
            token_type: Public,
            message,
            footer: (),
            encoding: JsonEncoding,
        }
    }
}

#[cfg(feature = "v3")]
impl<M> UnsignedToken<crate::V3, M> {
    pub fn new_v3_public(message: M) -> Self {
        Self {
            version_header: crate::V3,
            token_type: Public,
            message,
            footer: (),
            encoding: JsonEncoding,
        }
    }
}

fn generic_digest<V: PublicVersion>(
    encoding_header: &[u8],
    message: &[u8],
    footer: &[u8],
    implicit: &[u8],
) -> V::SignatureDigest {
    <V::SignatureDigest as digest::Digest>::new()
        // [h, m, f, i].len()
        .chain_update(4_u64.to_le_bytes())
        // h
        .chain_update(((V::PASETO_HEADER.len() + encoding_header.len()) as u64).to_le_bytes())
        .chain_update(V::PASETO_HEADER)
        .chain_update(encoding_header)
        // m
        .chain_update((message.len() as u64).to_le_bytes())
        .chain_update(message)
        // f
        .chain_update((footer.len() as u64).to_le_bytes())
        .chain_update(footer)
        // i
        .chain_update((implicit.len() as u64).to_le_bytes())
        .chain_update(implicit)
}

fn generic_sign<V: PublicVersion>(
    key: &Key<V, Secret>,
    encoding_header: &[u8],
    message: &[u8],
    footer: &[u8],
    implicit: &[u8],
) -> Bytes<V::Signature> {
    V::signing_key(&key.key).sign_digest(generic_digest::<V>(
        encoding_header,
        message,
        footer,
        implicit,
    ))
}

fn generic_verify<V: PublicVersion>(
    key: &Key<V, Public>,
    encoding_header: &[u8],
    message: &[u8],
    footer: &[u8],
    implicit: &[u8],
    sig: &Bytes<V::Signature>,
) -> Result<(), signature::Error> {
    V::verifying_key(&key.key).verify_digest(
        generic_digest::<V>(encoding_header, message, footer, implicit),
        sig,
    )
}

// monomorphise early
#[cfg(feature = "v3")]
fn sign_v3(
    key: &Key<crate::V3, Secret>,
    encoding_header: &[u8],
    message: &[u8],
    footer: &[u8],
    implicit: &[u8],
) -> Bytes<<crate::V3 as PublicVersion>::Signature> {
    generic_sign(key, encoding_header, message, footer, implicit)
}

// monomorphise early
#[cfg(feature = "v3")]
fn verify_v3(
    key: &Key<crate::V3, Public>,
    encoding_header: &[u8],
    message: &[u8],
    footer: &[u8],
    implicit: &[u8],
    sig: &Bytes<<crate::V3 as PublicVersion>::Signature>,
) -> Result<(), signature::Error> {
    generic_verify(key, encoding_header, message, footer, implicit, sig)
}

// monomorphise early
#[cfg(feature = "v4")]
fn sign_v4(
    key: &Key<crate::V4, Secret>,
    encoding_header: &[u8],
    message: &[u8],
    footer: &[u8],
    implicit: &[u8],
) -> Bytes<<crate::V4 as PublicVersion>::Signature> {
    generic_sign(key, encoding_header, message, footer, implicit)
}

// monomorphise early
#[cfg(feature = "v4")]
fn verify_v4(
    key: &Key<crate::V4, Public>,
    encoding_header: &[u8],
    message: &[u8],
    footer: &[u8],
    implicit: &[u8],
    sig: &Bytes<<crate::V4 as PublicVersion>::Signature>,
) -> Result<(), signature::Error> {
    generic_verify(key, encoding_header, message, footer, implicit, sig)
}

#[cfg(feature = "v3")]
impl<M: Message, F: Footer, E: MessageEncoding<M>> UnsignedToken<crate::V3, M, F, E> {
    pub fn sign(
        self,
        key: &SecretKey<crate::V3>,
        implicit_assertions: &[u8],
    ) -> Result<SignedToken<crate::V3, F, E>, Box<dyn std::error::Error>> {
        let mut m = self.encoding.encode(&self.message)?;
        let f = self.footer.encode();
        let sig = sign_v3(key, E::SUFFIX.as_bytes(), &m, &f, implicit_assertions);
        m.extend_from_slice(&sig);

        Ok(SignedToken {
            version_header: self.version_header,
            token_type: self.token_type,
            message: m,
            encoded_footer: f,
            footer: self.footer,
            encoding: self.encoding,
        })
    }
}

#[cfg(feature = "v3")]
impl<F: Footer, E: PayloadEncoding> SignedToken<crate::V3, F, E> {
    pub fn verify<M: Message>(
        self,
        key: &PublicKey<crate::V3>,
        implicit_assertions: &[u8],
    ) -> Result<UnsignedToken<crate::V3, M, F, E>, Box<dyn std::error::Error>>
    where
        E: MessageEncoding<M>,
    {
        let (m, sig) = self.message.split_at(
            self.message.len() - <<crate::V3 as PublicVersion>::Signature as Unsigned>::USIZE,
        );
        verify_v3(
            key,
            E::SUFFIX.as_bytes(),
            m,
            &self.encoded_footer,
            implicit_assertions,
            sig.into(),
        )
        .map_err(|_| "decryption error")?;

        let message = self.encoding.decode(m)?;

        Ok(UnsignedToken {
            version_header: self.version_header,
            token_type: self.token_type,
            message,
            footer: self.footer,
            encoding: self.encoding,
        })
    }
}

#[cfg(feature = "v4")]
impl<M: Message, F: Footer, E: MessageEncoding<M>> UnsignedToken<crate::V4, M, F, E> {
    pub fn sign(
        self,
        key: &SecretKey<crate::V4>,
        implicit_assertions: &[u8],
    ) -> Result<SignedToken<crate::V4, F, E>, Box<dyn std::error::Error>> {
        let mut m = self.encoding.encode(&self.message)?;
        let f = self.footer.encode();
        let sig = sign_v4(key, E::SUFFIX.as_bytes(), &m, &f, implicit_assertions);
        m.extend_from_slice(&sig);

        Ok(SignedToken {
            version_header: self.version_header,
            token_type: self.token_type,
            message: m,
            encoded_footer: f,
            footer: self.footer,
            encoding: self.encoding,
        })
    }
}

#[cfg(feature = "v4")]
impl<F: Footer, E: PayloadEncoding> SignedToken<crate::V4, F, E> {
    pub fn verify<M: Message>(
        self,
        key: &PublicKey<crate::V4>,
        implicit_assertions: &[u8],
    ) -> Result<UnsignedToken<crate::V4, M, F, E>, Box<dyn std::error::Error>>
    where
        E: MessageEncoding<M>,
    {
        let (m, sig) = self.message.split_at(
            self.message.len() - <<crate::V4 as PublicVersion>::Signature as Unsigned>::USIZE,
        );
        verify_v4(
            key,
            E::SUFFIX.as_bytes(),
            m,
            &self.encoded_footer,
            implicit_assertions,
            sig.into(),
        )
        .map_err(|_| "decryption error")?;

        let message = self.encoding.decode(m)?;

        Ok(UnsignedToken {
            version_header: self.version_header,
            token_type: self.token_type,
            message,
            footer: self.footer,
            encoding: self.encoding,
        })
    }
}
