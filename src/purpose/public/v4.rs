use generic_array::sequence::Split;
use generic_array::typenum::{U32, U64};
use signature::{Signer, Verifier};

use super::{Public, PublicVersion};
use crate::V4;
use crate::{Bytes, Purpose, Version};

fn preauth(h: &[u8], m: &[u8], f: &[u8], i: &[u8]) -> Vec<u8> {
    let mut message = Vec::new();
    // digest.update
    crate::pae::pae(
        [
            &[
                <V4 as Version>::PASETO_HEADER.as_bytes(),
                h,
                b".",
                <Public as Purpose>::HEADER.as_bytes(),
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
    /// Create a new V4 [`SignedToken`]crate::SignedToken) builder with the given message payload
    pub fn new_v4_public(message: M) -> Self {
        Self {
            version_header: V4,
            token_type: super::Public,
            message,
            footer: (),
            encoding: crate::Json(()),
        }
    }
}
