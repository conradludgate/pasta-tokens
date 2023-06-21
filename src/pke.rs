//! PKE (Public-Key Encryption).
//! PASERK uses Public-Key encryption to wrap symmetric keys for use in local tokens.
//!
//! <https://github.com/paseto-standard/paserk/blob/master/operations/PKE.md>

use std::{fmt, str::FromStr};

use base64::URL_SAFE_NO_PAD;
use cipher::{inout::InOutBuf, KeyIvInit, StreamCipher, Unsigned};
use digest::{Digest, Mac};
use generic_array::{
    sequence::{Concat, Split},
    ArrayLength, GenericArray,
};
use rand::rngs::OsRng;
use rusty_paseto::core::PasetoError;
use subtle::ConstantTimeEq;

#[cfg(feature = "v3")]
use rusty_paseto::core::V3;
#[cfg(feature = "v4")]
use rusty_paseto::core::V4;

use crate::key::{write_b64, Key, Local, Public, Secret, Version};

/// A local key encrypted with an asymmetric wrapping key.
pub struct SealedKey<V: SealedVersion> {
    tag: GenericArray<u8, V::TagLen>,
    ephemeral_public_key: GenericArray<u8, V::EpkLen>,
    encrypted_data_key: GenericArray<u8, V::Local>,
}

impl<V: SealedVersion> Key<V, Local> {
    /// This PASERK is a secret key intended for local PASETOs, encrypted with an asymmetric wrapping key.
    pub fn seal(&self, sealing_key: &Key<V, Public>) -> SealedKey<V> {
        V::seal(self, sealing_key)
    }
}

impl<V: SealedVersion> SealedKey<V> {
    pub fn unseal(self, unsealing_key: &Key<V, Secret>) -> Result<Key<V, Local>, PasetoError> {
        V::unseal(self, unsealing_key)
    }
}

/// Version info for configuring key sealing
pub trait SealedVersion: Version + Sized {
    type TagLen: ArrayLength<u8>;
    type EpkLen: ArrayLength<u8>;

    type TotalLen: ArrayLength<u8>;
    #[allow(clippy::type_complexity)]
    fn split_total(total: GenericArray<u8, Self::TotalLen>) -> SealedKey<Self>;
    fn join_total(sealed: &SealedKey<Self>) -> GenericArray<u8, Self::TotalLen>;

    fn seal(plaintext_key: &Key<Self, Local>, sealing_key: &Key<Self, Public>) -> SealedKey<Self>;
    fn unseal(
        sealed_key: SealedKey<Self>,
        unsealing_key: &Key<Self, Secret>,
    ) -> Result<Key<Self, Local>, PasetoError>;
}

#[cfg(feature = "v3")]
impl SealedVersion for V3 {
    type TagLen = generic_array::typenum::U48;
    type EpkLen = generic_array::typenum::U49;

    /// extra byte is for annoying base64 padding
    type TotalLen = generic_array::typenum::U129;
    fn split_total(total: GenericArray<u8, Self::TotalLen>) -> SealedKey<Self> {
        let (tag, rest) = total.split();
        let (ephemeral_public_key, encrypted_data_key) = rest.split();
        SealedKey {
            tag,
            ephemeral_public_key,
            encrypted_data_key,
        }
    }
    fn join_total(sealed: &SealedKey<Self>) -> GenericArray<u8, Self::TotalLen> {
        sealed
            .tag
            .concat(sealed.ephemeral_public_key)
            .concat(sealed.encrypted_data_key)
    }

    fn seal(plaintext_key: &Key<V3, Local>, sealing_key: &Key<V3, Public>) -> SealedKey<V3> {
        use p384::ecdh::EphemeralSecret;
        use p384::{EncodedPoint, PublicKey};

        let pk = PublicKey::from_sec1_bytes(sealing_key.as_ref()).unwrap();

        let esk = EphemeralSecret::random(&mut OsRng);
        let epk: EncodedPoint = esk.public_key().into();
        let epk = epk.compress();
        let epk = epk.as_bytes();

        let xk = esk.diffie_hellman(&pk);

        let (ek, n) = sha2::Sha384::new()
            .chain_update([0x01])
            .chain_update(Self::KEY_HEADER)
            .chain_update("seal.")
            .chain_update(xk.raw_secret_bytes())
            .chain_update(epk)
            .chain_update(sealing_key.as_ref())
            .finalize()
            .split();

        let ak = sha2::Sha384::new()
            .chain_update([0x02])
            .chain_update(Self::KEY_HEADER)
            .chain_update("seal.")
            .chain_update(xk.raw_secret_bytes())
            .chain_update(epk)
            .chain_update(sealing_key.as_ref())
            .finalize();

        let mut edk = GenericArray::<u8, <Self as Version>::Local>::default();
        ctr::Ctr64BE::<aes::Aes256>::new(&ek, &n)
            .apply_keystream_inout(InOutBuf::new(plaintext_key.as_ref(), &mut edk).unwrap());

        let tag = hmac::Hmac::<sha2::Sha384>::new_from_slice(&ak)
            .unwrap()
            .chain_update(Self::KEY_HEADER)
            .chain_update("seal.")
            .chain_update(epk)
            .chain_update(edk)
            .finalize()
            .into_bytes();

        SealedKey {
            tag,
            ephemeral_public_key: *GenericArray::from_slice(epk),
            encrypted_data_key: edk,
        }
    }

    fn unseal(
        mut sealed_key: SealedKey<Self>,
        unsealing_key: &Key<Self, Secret>,
    ) -> Result<Key<Self, Local>, PasetoError> {
        use p384::ecdh::diffie_hellman;
        use p384::{EncodedPoint, PublicKey, SecretKey};

        let sk = SecretKey::from_bytes(&unsealing_key.key).unwrap();

        let pk: EncodedPoint = sk.public_key().into();
        let pk = pk.compress();
        let pk = pk.as_bytes();

        let epk = PublicKey::from_sec1_bytes(sealed_key.ephemeral_public_key.as_slice()).unwrap();

        let xk = diffie_hellman(sk.to_nonzero_scalar(), epk.as_affine());

        let ak = sha2::Sha384::new()
            .chain_update([0x02])
            .chain_update(Self::KEY_HEADER)
            .chain_update("seal.")
            .chain_update(xk.raw_secret_bytes())
            .chain_update(sealed_key.ephemeral_public_key)
            .chain_update(pk)
            .finalize();

        let tag = hmac::Hmac::<sha2::Sha384>::new_from_slice(&ak)
            .unwrap()
            .chain_update(Self::KEY_HEADER)
            .chain_update("seal.")
            .chain_update(sealed_key.ephemeral_public_key)
            .chain_update(sealed_key.encrypted_data_key)
            .finalize()
            .into_bytes();

        // step 6: Compare t2 with t, using a constant-time compare function. If it does not match, abort.
        if sealed_key.tag.ct_ne(&tag).into() {
            return Err(PasetoError::InvalidSignature);
        }

        let (ek, n) = sha2::Sha384::new()
            .chain_update([0x01])
            .chain_update(Self::KEY_HEADER)
            .chain_update("seal.")
            .chain_update(xk.raw_secret_bytes())
            .chain_update(sealed_key.ephemeral_public_key)
            .chain_update(pk)
            .finalize()
            .split();

        ctr::Ctr64BE::<aes::Aes256>::new(&ek, &n)
            .apply_keystream(&mut sealed_key.encrypted_data_key);

        Ok(sealed_key.encrypted_data_key.into())
    }
}

#[cfg(feature = "v4")]
impl SealedVersion for V4 {
    type TagLen = generic_array::typenum::U32;
    type EpkLen = generic_array::typenum::U32;

    type TotalLen = generic_array::typenum::U96;
    fn split_total(total: GenericArray<u8, Self::TotalLen>) -> SealedKey<Self> {
        let (tag, rest) = total.split();
        let (ephemeral_public_key, encrypted_data_key) = rest.split();
        SealedKey {
            tag,
            ephemeral_public_key,
            encrypted_data_key,
        }
    }
    fn join_total(sealed: &SealedKey<Self>) -> GenericArray<u8, Self::TotalLen> {
        sealed
            .tag
            .concat(sealed.ephemeral_public_key)
            .concat(sealed.encrypted_data_key)
    }

    fn seal(plaintext_key: &Key<Self, Local>, sealing_key: &Key<Self, Public>) -> SealedKey<Self> {
        // Given a plaintext data key (pdk), and an Ed25519 public key (pk).
        let pk = curve25519_dalek::edwards::CompressedEdwardsY::from_slice(sealing_key.as_ref())
            .unwrap();

        // step 1: Calculate the birationally-equivalent X25519 public key (xpk) from pk.
        // I wish the edwards point/montgomery point types were exposed by x/ed25519 libraries
        let xpk: x25519_dalek::PublicKey = pk.decompress().unwrap().to_montgomery().0.into();

        let esk = x25519_dalek::EphemeralSecret::random_from_rng(OsRng);
        let epk = x25519_dalek::PublicKey::from(&esk);

        let xk = esk.diffie_hellman(&xpk);

        let ek = blake2::Blake2b::new()
            .chain_update([0x01])
            .chain_update(Self::KEY_HEADER)
            .chain_update("seal.")
            .chain_update(xk.as_bytes())
            .chain_update(epk.as_bytes())
            .chain_update(xpk.as_bytes())
            .finalize();

        let ak = blake2::Blake2b::<generic_array::typenum::U32>::new()
            .chain_update([0x02])
            .chain_update(Self::KEY_HEADER)
            .chain_update("seal.")
            .chain_update(xk.as_bytes())
            .chain_update(epk.as_bytes())
            .chain_update(xpk.as_bytes())
            .finalize();

        let n = blake2::Blake2b::new()
            .chain_update(epk.as_bytes())
            .chain_update(xpk.as_bytes())
            .finalize();

        let mut edk = GenericArray::<u8, <Self as Version>::Local>::default();
        chacha20::XChaCha20::new(&ek, &n)
            .apply_keystream_inout(InOutBuf::new(plaintext_key.as_ref(), &mut edk).unwrap());

        let tag = blake2::Blake2bMac::new_from_slice(&ak)
            .unwrap()
            .chain_update(Self::KEY_HEADER)
            .chain_update("seal.")
            .chain_update(epk.as_bytes())
            .chain_update(edk)
            .finalize()
            .into_bytes();

        SealedKey {
            tag,
            ephemeral_public_key: epk.to_bytes().into(),
            encrypted_data_key: edk,
        }
    }

    fn unseal(
        mut sealed_key: SealedKey<Self>,
        unsealing_key: &Key<Self, Secret>,
    ) -> Result<Key<Self, Local>, PasetoError> {
        let epk: [u8; 32] = sealed_key.ephemeral_public_key.into();
        let epk = x25519_dalek::PublicKey::from(epk);

        // expand sk
        let xsk = sha2::Sha512::default()
            .chain_update(&unsealing_key.as_ref()[..32])
            .finalize()[..32]
            .try_into()
            .unwrap();
        let xsk = curve25519_dalek::Scalar::from_bits_clamped(xsk);
        let xsk = x25519_dalek::StaticSecret::from(xsk.to_bytes());
        let xpk: x25519_dalek::PublicKey = (&xsk).into();

        let xk = xsk.diffie_hellman(&epk);

        let ak = blake2::Blake2b::<generic_array::typenum::U32>::new()
            .chain_update([0x02])
            .chain_update(Self::KEY_HEADER)
            .chain_update("seal.")
            .chain_update(xk.as_bytes())
            .chain_update(epk.as_bytes())
            .chain_update(xpk.as_bytes())
            .finalize();

        let t2 = blake2::Blake2bMac::<generic_array::typenum::U32>::new_from_slice(&ak)
            .unwrap()
            .chain_update(Self::KEY_HEADER)
            .chain_update("seal.")
            .chain_update(epk.as_bytes())
            .chain_update(sealed_key.encrypted_data_key)
            .finalize()
            .into_bytes();

        // step 6: Compare t2 with t, using a constant-time compare function. If it does not match, abort.
        if sealed_key.tag.ct_ne(&t2).into() {
            return Err(PasetoError::InvalidSignature);
        }

        let ek = blake2::Blake2b::new()
            .chain_update([0x01])
            .chain_update(Self::KEY_HEADER)
            .chain_update("seal.")
            .chain_update(xk.as_bytes())
            .chain_update(epk.as_bytes())
            .chain_update(xpk.as_bytes())
            .finalize();

        let n = blake2::Blake2b::new()
            .chain_update(epk.as_bytes())
            .chain_update(xpk.as_bytes())
            .finalize();

        chacha20::XChaCha20::new(&ek, &n).apply_keystream(&mut sealed_key.encrypted_data_key);
        Ok(sealed_key.encrypted_data_key.into())
    }
}

impl<V: SealedVersion> FromStr for SealedKey<V> {
    type Err = PasetoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .strip_prefix(V::KEY_HEADER)
            .ok_or(PasetoError::WrongHeader)?;
        let s = s.strip_prefix("seal.").ok_or(PasetoError::WrongHeader)?;

        let mut total = GenericArray::<u8, V::TotalLen>::default();
        let expected_len = (s.len() + 3) / 4 * 3;
        if expected_len != <V::TotalLen as Unsigned>::USIZE {
            return Err(PasetoError::PayloadBase64Decode {
                source: base64::DecodeError::InvalidLength,
            });
        }

        let len = base64::decode_config_slice(s, URL_SAFE_NO_PAD, &mut total)?;
        if len != <V::TotalLen as Unsigned>::USIZE {
            return Err(PasetoError::PayloadBase64Decode {
                source: base64::DecodeError::InvalidLength,
            });
        }

        Ok(V::split_total(total))
    }
}

impl<V: SealedVersion> fmt::Display for SealedKey<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(V::KEY_HEADER)?;
        f.write_str("seal.")?;

        write_b64(&V::join_total(self), f)
    }
}
