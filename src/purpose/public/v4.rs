use generic_array::typenum::{U32, U64};
use signature::{Signer, Verifier};

use super::{Public, PublicVersion};
use crate::purpose::Purpose;
use crate::version::{Version, V4};
use crate::Bytes;

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

    type InnerPublicKeyType = ed25519_dalek::VerifyingKey;
    type InnerSecretKeyType = ed25519_dalek::SigningKey;

    fn from_secret_bytes(
        k: Bytes<Self::SecretKeySize>,
    ) -> Result<Self::InnerSecretKeyType, crate::PasetoError> {
        ed25519_dalek::SigningKey::from_keypair_bytes(&k.into())
            .map_err(|_| crate::PasetoError::InvalidKey)
    }

    fn from_public_bytes(
        k: Bytes<Self::PublicKeySize>,
    ) -> Result<Self::InnerPublicKeyType, crate::PasetoError> {
        ed25519_dalek::VerifyingKey::from_bytes(&k.into())
            .map_err(|_| crate::PasetoError::InvalidKey)
    }

    fn to_secret_bytes(k: &Self::InnerSecretKeyType) -> Bytes<Self::SecretKeySize> {
        k.to_keypair_bytes().into()
    }

    fn to_public_bytes(k: &Self::InnerPublicKeyType) -> Bytes<Self::PublicKeySize> {
        k.to_bytes().into()
    }

    type Signature = U64;

    fn sign(
        sk: &Self::InnerSecretKeyType,
        h: &[u8],
        m: &[u8],
        f: &[u8],
        i: &[u8],
    ) -> Bytes<Self::Signature> {
        // let (sk, _pk): (Bytes<U32>, _) = (*sk).split();
        // let sk = ed25519_dalek::SigningKey::from_bytes(&sk.into());
        let preauth = preauth(h, m, f, i);
        let b: ed25519_dalek::Signature = sk.sign(&preauth);
        b.to_bytes().into()
    }

    fn verify(
        k: &Self::InnerPublicKeyType,
        h: &[u8],
        m: &[u8],
        f: &[u8],
        i: &[u8],
        sig: &Bytes<Self::Signature>,
    ) -> Result<(), signature::Error> {
        // let pk = ed25519_dalek::VerifyingKey::from_bytes(&(*k).into())?;
        let preauth = preauth(h, m, f, i);
        let sig = ed25519_dalek::Signature::from_bytes(&(*sig).into());
        k.verify(&preauth, &sig)
    }
}

impl<M> super::UnsignedToken<V4, M> {
    /// Create a new [`V4`] [`SignedToken`](super::SignedToken) builder with the given message payload
    pub fn new_v4_public(message: M) -> Self {
        Self::new(message)
    }
}
