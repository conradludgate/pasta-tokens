use cipher::Unsigned;
use generic_array::ArrayLength;

use crate::{
    Bytes, Footer, KeyType, Message, MessageEncoding, PayloadEncoding, PublicKey, SecretKey,
    SignedToken, TokenType, VerifiedToken, Version,
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
    use signature::{Signer, Verifier};

    use super::{Public, PublicVersion};
    use crate::V4;
    use crate::{Bytes, TokenType, Version};

    fn preauth(h: &[u8], m: &[u8], f: &[u8], i: &[u8]) -> Vec<u8> {
        let mut message = Vec::new();
        // digest.update
        crate::pae::pae(
            [
                &[
                    <V4 as Version>::PASETO_HEADER.as_bytes(),
                    h,
                    b".",
                    <Public as TokenType>::TOKEN_TYPE.as_bytes(),
                    b".",
                ],
                &[m],
                &[f],
                &[i],
            ],
            &mut message,
        );
        message
    }

    impl PublicVersion for V4 {
        /// Compressed edwards y point
        type PublicKeySize = U32;
        /// Ed25519 scalar key, concatenated with the public key bytes
        type SecretKeySize = U64;

        type Signature = U64;

        fn sign(
            sk: &Bytes<Self::SecretKeySize>,
            h: &[u8],
            m: &[u8],
            f: &[u8],
            i: &[u8],
        ) -> Bytes<Self::Signature> {
            let (sk, _pk): (Bytes<U32>, _) = (*sk).split();
            let sk = ed25519_dalek::SigningKey::from_bytes(&sk.into());
            let preauth = preauth(h, m, f, i);
            let b: ed25519_dalek::Signature = sk.sign(&preauth);
            b.to_bytes().into()
        }

        fn verify(
            k: &Bytes<Self::PublicKeySize>,
            h: &[u8],
            m: &[u8],
            f: &[u8],
            i: &[u8],
            sig: &Bytes<Self::Signature>,
        ) -> Result<(), signature::Error> {
            let pk = ed25519_dalek::VerifyingKey::from_bytes(&(*k).into())?;
            let preauth = preauth(h, m, f, i);
            let sig = ed25519_dalek::Signature::from_bytes(&(*sig).into());
            pk.verify(&preauth, &sig)
        }
    }

    impl<M> crate::VerifiedToken<V4, M> {
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
    use signature::DigestSigner;
    use signature::DigestVerifier;

    use super::Public;
    use super::PublicVersion;
    use crate::Bytes;
    use crate::TokenType;
    use crate::Version;
    use crate::V3;

    pub type SignatureDigest = <p384::NistP384 as ecdsa::hazmat::DigestPrimitive>::Digest;

    fn digest(pk: &[u8], h: &[u8], m: &[u8], f: &[u8], i: &[u8]) -> SignatureDigest {
        let mut digest = <SignatureDigest as digest::Digest>::new();
        crate::pae::pae(
            [
                &[pk],
                &[
                    <V3 as Version>::PASETO_HEADER.as_bytes(),
                    h,
                    b".",
                    <Public as TokenType>::TOKEN_TYPE.as_bytes(),
                    b".",
                ],
                &[m],
                &[f],
                &[i],
            ],
            &mut crate::pae::Digest(&mut digest),
        );
        digest
    }

    impl PublicVersion for V3 {
        /// P-384 Public Key in compressed format
        type PublicKeySize = U49;
        /// P-384 Secret Key (384 bits = 48 bytes)
        type SecretKeySize = U48;

        type Signature = U96;

        fn sign(
            sk: &Bytes<Self::SecretKeySize>,
            h: &[u8],
            m: &[u8],
            f: &[u8],
            i: &[u8],
        ) -> Bytes<Self::Signature> {
            let sk = p384::ecdsa::SigningKey::from_bytes(sk)
                .expect("secret key validity should already be asserted");

            let pk: p384::EncodedPoint = sk.verifying_key().to_encoded_point(true);
            let pk = pk.as_bytes();

            let digest = digest(pk, h, m, f, i);

            let b: p384::ecdsa::Signature = sk.sign_digest(digest);
            b.to_bytes()
        }

        fn verify(
            k: &Bytes<Self::PublicKeySize>,
            h: &[u8],
            m: &[u8],
            f: &[u8],
            i: &[u8],
            sig: &Bytes<Self::Signature>,
        ) -> Result<(), signature::Error> {
            let k = p384::ecdsa::VerifyingKey::from_sec1_bytes(k)
                .expect("secret key validity should already be asserted");

            let pk: p384::EncodedPoint = k.to_encoded_point(true);
            let pk = pk.as_bytes();

            let digest = digest(pk, h, m, f, i);

            k.verify_digest(digest, &p384::ecdsa::Signature::from_bytes(sig).unwrap())
        }
    }

    impl<M> crate::VerifiedToken<V3, M> {
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

impl<V: PublicVersion, M: Message, F: Footer, E: MessageEncoding<M>> VerifiedToken<V, M, F, E> {
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
    ) -> Result<VerifiedToken<V, M, F, E>, Box<dyn std::error::Error>>
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

        Ok(VerifiedToken {
            version_header: self.version_header,
            token_type: self.token_type,
            message,
            footer: self.footer,
            encoding: self.encoding,
        })
    }
}
