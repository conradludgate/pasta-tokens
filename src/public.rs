use cipher::Unsigned;
use digest::Digest;
use generic_array::ArrayLength;
use signature::{DigestSigner, DigestVerifier};

use crate::{
    Bytes, Footer, KeyType, Message, MessageEncoding, PayloadEncoding, PublicKey, SecretKey,
    SignedToken, TokenType, UnsignedToken, Version,
};

/// General information about a PASETO/PASERK version
pub trait PublicVersion: Version {
    /// Size of the asymmetric public key
    type PublicKeySize: ArrayLength<u8>;
    /// Size of the asymmetric secret key
    type SecretKeySize: ArrayLength<u8>;

    type Signature: ArrayLength<u8>;

    #[doc(hidden)]
    fn sign(
        k: &Bytes<Self::SecretKeySize>,
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

trait Inner: PublicVersion {
    type SigningKey: signature::DigestSigner<Self::SignatureDigest, Bytes<Self::Signature>>;
    type VerifyingKey: signature::DigestVerifier<Self::SignatureDigest, Bytes<Self::Signature>>;
    type SignatureDigest: digest::Digest;

    fn signing_key(key: &Bytes<Self::SecretKeySize>) -> Self::SigningKey;
    fn verifying_key(key: &Bytes<Self::PublicKeySize>) -> Self::VerifyingKey;
}

/// Public verifying/encrypting keys
#[derive(Debug, Default)]
pub struct Public;

/// Secret signing/decrypting keys
#[derive(Debug)]
pub struct Secret;

impl<V: PublicVersion> KeyType<V> for Public {
    type KeyLen = V::PublicKeySize;
    const HEADER: &'static str = "public.";
    const ID: &'static str = "pid.";
}

impl<V: PublicVersion> KeyType<V> for Secret {
    type KeyLen = V::SecretKeySize;
    const HEADER: &'static str = "secret.";
    const ID: &'static str = "sid.";
}

impl TokenType for Public {
    const TOKEN_TYPE: &'static str = "public";
}

#[cfg(feature = "v4")]
mod v4 {
    use generic_array::sequence::Split;
    use generic_array::typenum::{U32, U64};

    use super::{Inner, PublicVersion};
    use crate::Bytes;
    use crate::V4;

    pub struct SigningKey(ed25519_dalek::SigningKey);

    pub struct VerifyingKey(ed25519_dalek::VerifyingKey);
    pub type SignatureDigest = ed25519_dalek::Sha512;

    impl signature::DigestSigner<SignatureDigest, Bytes<U64>> for SigningKey {
        fn try_sign_digest(&self, digest: SignatureDigest) -> Result<Bytes<U64>, signature::Error> {
            self.0.try_sign_digest(digest).map(|x| x.to_bytes().into())
        }
    }

    impl signature::DigestVerifier<SignatureDigest, Bytes<U64>> for VerifyingKey {
        fn verify_digest(
            &self,
            digest: SignatureDigest,
            signature: &Bytes<U64>,
        ) -> Result<(), signature::Error> {
            let sig = ed25519_dalek::Signature::from_bytes(&(*signature).into());
            self.0.verify_digest(digest, &sig)
        }
    }

    impl PublicVersion for V4 {
        /// Compressed edwards y point
        type PublicKeySize = U32;
        /// Ed25519 scalar key, concatenated with the public key bytes
        type SecretKeySize = U64;

        type Signature = U64;

        fn sign(
            k: &Bytes<Self::SecretKeySize>,
            h: &[u8],
            m: &[u8],
            f: &[u8],
            i: &[u8],
        ) -> Bytes<Self::Signature> {
            super::generic_sign::<Self>(k, h, m, f, i)
        }

        fn verify(
            k: &Bytes<Self::PublicKeySize>,
            h: &[u8],
            m: &[u8],
            f: &[u8],
            i: &[u8],
            sig: &Bytes<Self::Signature>,
        ) -> Result<(), signature::Error> {
            super::generic_verify::<Self>(k, h, m, f, i, sig)
        }
    }

    impl Inner for V4 {
        type SigningKey = SigningKey;
        type VerifyingKey = VerifyingKey;
        type SignatureDigest = SignatureDigest;

        fn signing_key(key: &Bytes<Self::SecretKeySize>) -> Self::SigningKey {
            let (sk, _pk): (Bytes<U32>, _) = (*key).split();
            SigningKey(ed25519_dalek::SigningKey::from_bytes(&sk.into()))
        }
        fn verifying_key(key: &Bytes<Self::PublicKeySize>) -> Self::VerifyingKey {
            VerifyingKey(
                ed25519_dalek::VerifyingKey::from_bytes(&(*key).into())
                    .expect("validity of this public key should already be asserted"),
            )
        }
    }

    impl<M> crate::UnsignedToken<V4, M> {
        pub fn new_v4_public(message: M) -> Self {
            Self {
                version_header: V4,
                token_type: super::Public,
                message,
                footer: (),
                encoding: crate::JsonEncoding,
            }
        }
    }
}

#[cfg(feature = "v3")]
mod v3 {
    use generic_array::typenum::{U48, U49, U96};

    use super::Inner;
    use super::PublicVersion;
    use crate::Bytes;
    use crate::V3;

    pub struct SigningKey(p384::ecdsa::SigningKey);
    pub struct VerifyingKey(p384::ecdsa::VerifyingKey);
    pub type SignatureDigest = <p384::NistP384 as ecdsa::hazmat::DigestPrimitive>::Digest;

    impl signature::DigestSigner<SignatureDigest, Bytes<U96>> for SigningKey {
        fn try_sign_digest(&self, digest: SignatureDigest) -> Result<Bytes<U96>, signature::Error> {
            self.0
                .try_sign_digest(digest)
                .map(|x: p384::ecdsa::Signature| x.to_bytes())
        }
    }
    impl signature::DigestVerifier<SignatureDigest, Bytes<U96>> for VerifyingKey {
        fn verify_digest(
            &self,
            digest: SignatureDigest,
            signature: &Bytes<U96>,
        ) -> Result<(), signature::Error> {
            let sig = p384::ecdsa::Signature::from_bytes(signature)?;
            self.0.verify_digest(digest, &sig)
        }
    }

    impl PublicVersion for V3 {
        /// P-384 Public Key in compressed format
        type PublicKeySize = U49;
        /// P-384 Secret Key (384 bits = 48 bytes)
        type SecretKeySize = U48;

        type Signature = U96;

        fn sign(
            k: &Bytes<Self::SecretKeySize>,
            h: &[u8],
            m: &[u8],
            f: &[u8],
            i: &[u8],
        ) -> Bytes<Self::Signature> {
            super::generic_sign::<Self>(k, h, m, f, i)
        }

        fn verify(
            k: &Bytes<Self::PublicKeySize>,
            h: &[u8],
            m: &[u8],
            f: &[u8],
            i: &[u8],
            sig: &Bytes<Self::Signature>,
        ) -> Result<(), signature::Error> {
            super::generic_verify::<Self>(k, h, m, f, i, sig)
        }
    }

    impl Inner for V3 {
        type SigningKey = SigningKey;
        type VerifyingKey = VerifyingKey;
        type SignatureDigest = SignatureDigest;

        fn signing_key(key: &Bytes<Self::SecretKeySize>) -> Self::SigningKey {
            SigningKey(
                p384::ecdsa::SigningKey::from_bytes(key)
                    .expect("secret key validity should already be asserted"),
            )
        }
        fn verifying_key(key: &Bytes<Self::PublicKeySize>) -> Self::VerifyingKey {
            VerifyingKey(
                p384::ecdsa::VerifyingKey::from_sec1_bytes(key)
                    .expect("secret key validity should already be asserted"),
            )
        }
    }

    impl<M> crate::UnsignedToken<V3, M> {
        pub fn new_v3_public(message: M) -> Self {
            Self {
                version_header: V3,
                token_type: super::Public,
                message,
                footer: (),
                encoding: crate::JsonEncoding,
            }
        }
    }
}

fn generic_digest<V: Inner>(
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

fn generic_sign<V: Inner>(
    key: &Bytes<V::SecretKeySize>,
    encoding_header: &[u8],
    message: &[u8],
    footer: &[u8],
    implicit: &[u8],
) -> Bytes<V::Signature> {
    V::signing_key(key).sign_digest(generic_digest::<V>(
        encoding_header,
        message,
        footer,
        implicit,
    ))
}

fn generic_verify<V: Inner>(
    key: &Bytes<V::PublicKeySize>,
    encoding_header: &[u8],
    message: &[u8],
    footer: &[u8],
    implicit: &[u8],
    sig: &Bytes<V::Signature>,
) -> Result<(), signature::Error> {
    V::verifying_key(key).verify_digest(
        generic_digest::<V>(encoding_header, message, footer, implicit),
        sig,
    )
}

impl<V: PublicVersion, M: Message, F: Footer, E: MessageEncoding<M>> UnsignedToken<V, M, F, E> {
    pub fn sign(
        self,
        key: &SecretKey<V>,
        implicit_assertions: &[u8],
    ) -> Result<SignedToken<V, F, E>, Box<dyn std::error::Error>> {
        let mut m = self.encoding.encode(&self.message)?;
        let f = self.footer.encode();
        let sig = V::sign(&key.key, E::SUFFIX.as_bytes(), &m, &f, implicit_assertions);
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

impl<V: PublicVersion, F: Footer, E: PayloadEncoding> SignedToken<V, F, E> {
    pub fn verify<M: Message>(
        self,
        key: &PublicKey<V>,
        implicit_assertions: &[u8],
    ) -> Result<UnsignedToken<V, M, F, E>, Box<dyn std::error::Error>>
    where
        E: MessageEncoding<M>,
    {
        let (m, sig) = self
            .message
            .split_at(self.message.len() - <<V as PublicVersion>::Signature as Unsigned>::USIZE);
        V::verify(
            &key.key,
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
