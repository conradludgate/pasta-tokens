use generic_array::typenum::{U48, U49, U96};
use signature::DigestSigner;
use signature::DigestVerifier;

use super::Public;
use super::PublicVersion;
use crate::Bytes;
use crate::Purpose;
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
    /// Create a new V3 [`SignedToken`]crate::SignedToken) builder with the given message payload
    pub fn new_v3_public(message: M) -> Self {
        Self {
            version_header: V3,
            token_type: super::Public,
            message,
            footer: (),
            encoding: crate::Json(()),
        }
    }
}
