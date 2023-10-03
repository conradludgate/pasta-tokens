use generic_array::typenum::{U48, U49, U96};
use signature::DigestSigner;
use signature::DigestVerifier;

use super::Public;
use super::PublicVersion;
use crate::purpose::Purpose;
use crate::version::Version;
use crate::version::V3;
use crate::Bytes;

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
                <Public as Purpose>::HEADER.as_bytes(),
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

    type InnerPublicKeyType = p384::ecdsa::VerifyingKey;
    type InnerSecretKeyType = p384::ecdsa::SigningKey;

    fn from_secret_bytes(
        k: Bytes<Self::SecretKeySize>,
    ) -> Result<Self::InnerSecretKeyType, crate::PasetoError> {
        p384::ecdsa::SigningKey::from_slice(&k).map_err(|_| crate::PasetoError::InvalidKey)
    }

    fn from_public_bytes(
        k: Bytes<Self::PublicKeySize>,
    ) -> Result<Self::InnerPublicKeyType, crate::PasetoError> {
        p384::ecdsa::VerifyingKey::from_sec1_bytes(&k).map_err(|_| crate::PasetoError::InvalidKey)
    }

    fn to_secret_bytes(k: &Self::InnerSecretKeyType) -> Bytes<Self::SecretKeySize> {
        k.to_bytes()
    }

    fn to_public_bytes(k: &Self::InnerPublicKeyType) -> Bytes<Self::PublicKeySize> {
        *Bytes::from_slice(k.to_encoded_point(true).as_bytes())
    }

    type Signature = U96;

    fn sign(
        sk: &Self::InnerSecretKeyType,
        h: &[u8],
        m: &[u8],
        f: &[u8],
        i: &[u8],
    ) -> Bytes<Self::Signature> {
        let pk = sk.verifying_key().to_encoded_point(true);
        let pk = pk.as_bytes();

        let digest = digest(pk, h, m, f, i);

        let b: p384::ecdsa::Signature = sk.sign_digest(digest);
        b.to_bytes()
    }

    fn verify(
        k: &Self::InnerPublicKeyType,
        h: &[u8],
        m: &[u8],
        f: &[u8],
        i: &[u8],
        sig: &Bytes<Self::Signature>,
    ) -> Result<(), signature::Error> {
        let pk = k.to_encoded_point(true);
        let pk = pk.as_bytes();

        let digest = digest(pk, h, m, f, i);

        k.verify_digest(digest, &p384::ecdsa::Signature::from_bytes(sig).unwrap())
    }
}

impl<M> super::UnsignedToken<V3, M> {
    /// Create a new [`V3`] [`SignedToken`](super::SignedToken) builder with the given message payload
    pub fn new_v3_public(message: M) -> Self {
        Self::new(message)
    }
}
