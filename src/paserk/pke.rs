//! PKE (Public-Key Encryption).
//! PASERK uses Public-Key encryption to wrap symmetric keys for use in local tokens.
//!
//! <https://github.com/paseto-standard/paserk/blob/master/operations/PKE.md>

use std::{fmt, str::FromStr};

use cipher::{inout::InOutBuf, KeyIvInit, StreamCipher};
use digest::{Digest, Mac};
use generic_array::{
    sequence::{Concat, Split},
    ArrayLength, GenericArray,
};
use rand::{rngs::OsRng, CryptoRng, RngCore};
use subtle::ConstantTimeEq;

#[cfg(feature = "v3-pke")]
use crate::version::V3;
#[cfg(feature = "v4-pke")]
use crate::version::V4;
use crate::{
    key::Key,
    purpose::{
        local::{Local, LocalVersion},
        public::{Public, PublicVersion, Secret},
    },
    version::Version,
    PasetoError,
};

use super::{read_b64, write_b64};

/// A local key encrypted with an asymmetric wrapping key.
///
/// # Secret Wrapping
/// ```
/// use pasta_tokens::{
///     key::Key,
///     purpose::{local::Local, public::Secret},
///     paserk::pke::SealedKey,
///     version::V4
/// };
///
/// let key = Key::<V4, Local>::new_os_random();
///
/// let secret_key = Key::<V4, Secret>::new_os_random();
/// let public_key = secret_key.public_key();
///
/// let sealed = key.seal(&public_key).to_string();
/// // => "k4.seal.23KlrMHZLW4muL75Rnuqtaro9F16mqDNvmCbgDXi2IdNyWmjrbTVBEih1DhSI_5xp7b7mCHSFo1DMv-9GtZUSpyi4646XBxpbFShHjJihF_Af8maWsDqdzOof76ia0Cv"
///
/// let sealed: SealedKey<V4> = sealed.parse().unwrap();
/// let key2 = sealed.unseal(&secret_key).unwrap();
/// assert_eq!(key, key2);
/// ```
pub struct SealedKey<V: SealedVersion> {
    tag: GenericArray<u8, V::TagLen>,
    ephemeral_public_key: GenericArray<u8, V::EpkLen>,
    encrypted_data_key: GenericArray<u8, V::KeySize>,
}

impl<V> super::SafeForFooter for SealedKey<V> where V: SealedVersion {}

impl<V: SealedVersion> Key<V, Local> {
    /// A local key encrypted with an asymmetric wrapping key.
    ///
    /// # Secret Wrapping
    /// ```
    /// use pasta_tokens::{
    ///     key::Key,
    ///     purpose::{local::Local, public::Secret},
    ///     paserk::pke::SealedKey,
    ///     version::V4
    /// };
    ///
    /// let key = Key::<V4, Local>::new_os_random();
    ///
    /// let secret_key = Key::<V4, Secret>::new_os_random();
    /// let public_key = secret_key.public_key();
    ///
    /// let sealed = key.seal(&public_key).to_string();
    /// // => "k4.seal.23KlrMHZLW4muL75Rnuqtaro9F16mqDNvmCbgDXi2IdNyWmjrbTVBEih1DhSI_5xp7b7mCHSFo1DMv-9GtZUSpyi4646XBxpbFShHjJihF_Af8maWsDqdzOof76ia0Cv"
    ///
    /// let sealed: SealedKey<V4> = sealed.parse().unwrap();
    /// let key2 = sealed.unseal(&secret_key).unwrap();
    /// assert_eq!(key, key2);
    /// ```
    pub fn seal(&self, sealing_key: &Key<V, Public>) -> SealedKey<V> {
        self.seal_with_rng(sealing_key, &mut OsRng)
    }

    /// Seal a local key, encrypted with an asymmetric wrapping key.
    ///
    /// The ephemeral key is generated from the provided random source.
    pub fn seal_with_rng(
        &self,
        sealing_key: &Key<V, Public>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> SealedKey<V> {
        V::seal(self, sealing_key, rng)
    }
}

impl<V: SealedVersion> SealedKey<V> {
    /// Unseal an encrypted local key.
    pub fn unseal(self, unsealing_key: &Key<V, Secret>) -> Result<Key<V, Local>, PasetoError> {
        V::unseal(self, unsealing_key)
    }
}

/// Version info for configuring key sealing
pub trait SealedVersion: LocalVersion + PublicVersion + Sized {
    #[doc(hidden)]
    type TagLen: ArrayLength<u8>;
    #[doc(hidden)]
    type EpkLen: ArrayLength<u8>;

    #[doc(hidden)]
    type TotalLen: ArrayLength<u8>;
    #[allow(clippy::type_complexity)]
    #[doc(hidden)]
    fn split_total(total: GenericArray<u8, Self::TotalLen>) -> SealedKey<Self>;
    #[doc(hidden)]
    fn join_total(sealed: &SealedKey<Self>) -> GenericArray<u8, Self::TotalLen>;

    #[doc(hidden)]
    fn seal(
        plaintext_key: &Key<Self, Local>,
        sealing_key: &Key<Self, Public>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> SealedKey<Self>;
    #[doc(hidden)]
    fn unseal(
        sealed_key: SealedKey<Self>,
        unsealing_key: &Key<Self, Secret>,
    ) -> Result<Key<Self, Local>, PasetoError>;
}

#[cfg(feature = "v3-pke")]
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

    fn seal(
        plaintext_key: &Key<V3, Local>,
        sealing_key: &Key<V3, Public>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> SealedKey<V3> {
        use p384::ecdh::EphemeralSecret;
        use p384::{EncodedPoint, PublicKey};

        let pk = PublicKey::from_sec1_bytes(sealing_key.as_ref()).unwrap();

        let esk = EphemeralSecret::random(rng);
        let epk: EncodedPoint = esk.public_key().into();
        let epk = epk.compress();
        let epk = epk.as_bytes();

        let xk = esk.diffie_hellman(&pk);

        let (ek, n) = sha2::Sha384::new()
            .chain_update([0x01])
            .chain_update(Self::PASERK_HEADER)
            .chain_update(".seal.")
            .chain_update(xk.raw_secret_bytes())
            .chain_update(epk)
            .chain_update(sealing_key.as_ref())
            .finalize()
            .split();

        let ak = sha2::Sha384::new()
            .chain_update([0x02])
            .chain_update(Self::PASERK_HEADER)
            .chain_update(".seal.")
            .chain_update(xk.raw_secret_bytes())
            .chain_update(epk)
            .chain_update(sealing_key.as_ref())
            .finalize();

        let mut edk = GenericArray::<u8, <Self as LocalVersion>::KeySize>::default();
        ctr::Ctr64BE::<aes::Aes256>::new(&ek, &n)
            .apply_keystream_inout(InOutBuf::new(plaintext_key.as_ref(), &mut edk).unwrap());

        let tag = hmac::Hmac::<sha2::Sha384>::new_from_slice(&ak)
            .unwrap()
            .chain_update(Self::PASERK_HEADER)
            .chain_update(".seal.")
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
            .chain_update(Self::PASERK_HEADER)
            .chain_update(".seal.")
            .chain_update(xk.raw_secret_bytes())
            .chain_update(sealed_key.ephemeral_public_key)
            .chain_update(pk)
            .finalize();

        let tag = hmac::Hmac::<sha2::Sha384>::new_from_slice(&ak)
            .unwrap()
            .chain_update(Self::PASERK_HEADER)
            .chain_update(".seal.")
            .chain_update(sealed_key.ephemeral_public_key)
            .chain_update(sealed_key.encrypted_data_key)
            .finalize()
            .into_bytes();

        // step 6: Compare t2 with t, using a constant-time compare function. If it does not match, abort.
        if sealed_key.tag.ct_ne(&tag).into() {
            return Err(PasetoError::CryptoError);
        }

        let (ek, n) = sha2::Sha384::new()
            .chain_update([0x01])
            .chain_update(Self::PASERK_HEADER)
            .chain_update(".seal.")
            .chain_update(xk.raw_secret_bytes())
            .chain_update(sealed_key.ephemeral_public_key)
            .chain_update(pk)
            .finalize()
            .split();

        ctr::Ctr64BE::<aes::Aes256>::new(&ek, &n)
            .apply_keystream(&mut sealed_key.encrypted_data_key);

        Ok(Key {
            key: Box::new(sealed_key.encrypted_data_key),
        })
    }
}

#[cfg(feature = "v4-pke")]
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

    fn seal(
        plaintext_key: &Key<Self, Local>,
        sealing_key: &Key<Self, Public>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> SealedKey<Self> {
        use curve25519_dalek::{
            edwards::{CompressedEdwardsY, EdwardsPoint},
            scalar::{clamp_integer, Scalar},
        };

        // Given a plaintext data key (pdk), and an Ed25519 public key (pk).
        let pk = CompressedEdwardsY((*sealing_key.key).into());

        // step 1: Calculate the birationally-equivalent X25519 public key (xpk) from pk.
        let xpk = pk.decompress().unwrap().to_montgomery();

        let esk = Scalar::from_bytes_mod_order(clamp_integer({
            let mut esk = [0; 32];
            rng.fill_bytes(&mut esk);
            esk
        }));
        let epk = EdwardsPoint::mul_base(&esk).to_montgomery();

        // diffie hellman exchange
        let xk = esk * xpk;

        let ek = blake2::Blake2b::new()
            .chain_update([0x01])
            .chain_update(Self::PASERK_HEADER)
            .chain_update(".seal.")
            .chain_update(xk.as_bytes())
            .chain_update(epk.as_bytes())
            .chain_update(xpk.as_bytes())
            .finalize();

        let ak = blake2::Blake2b::<generic_array::typenum::U32>::new()
            .chain_update([0x02])
            .chain_update(Self::PASERK_HEADER)
            .chain_update(".seal.")
            .chain_update(xk.as_bytes())
            .chain_update(epk.as_bytes())
            .chain_update(xpk.as_bytes())
            .finalize();

        let n = blake2::Blake2b::new()
            .chain_update(epk.as_bytes())
            .chain_update(xpk.as_bytes())
            .finalize();

        let mut edk = GenericArray::<u8, <Self as LocalVersion>::KeySize>::default();
        chacha20::XChaCha20::new(&ek, &n)
            .apply_keystream_inout(InOutBuf::new(plaintext_key.as_ref(), &mut edk).unwrap());

        let tag = blake2::Blake2bMac::new_from_slice(&ak)
            .unwrap()
            .chain_update(Self::PASERK_HEADER)
            .chain_update(".seal.")
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
        use curve25519_dalek::edwards::CompressedEdwardsY;
        use ed25519_dalek::hazmat::ExpandedSecretKey;

        let epk: [u8; 32] = sealed_key.ephemeral_public_key.into();
        let epk = curve25519_dalek::MontgomeryPoint(epk);

        // expand pk/sk pair from ed25519 to x25519
        let (sk, pk) = unsealing_key.key.split();
        let pk = CompressedEdwardsY(pk.into());
        let xpk = pk.decompress().unwrap().to_montgomery();

        let sk: ed25519_dalek::SecretKey = sk.into();
        let xsk = ExpandedSecretKey::from(&sk);

        // diffie hellman exchange
        let xk = xsk.scalar * epk;

        let ak = blake2::Blake2b::<generic_array::typenum::U32>::new()
            .chain_update([0x02])
            .chain_update(Self::PASERK_HEADER)
            .chain_update(".seal.")
            .chain_update(xk.as_bytes())
            .chain_update(epk.as_bytes())
            .chain_update(xpk.as_bytes())
            .finalize();

        let t2 = blake2::Blake2bMac::<generic_array::typenum::U32>::new_from_slice(&ak)
            .unwrap()
            .chain_update(Self::PASERK_HEADER)
            .chain_update(".seal.")
            .chain_update(epk.as_bytes())
            .chain_update(sealed_key.encrypted_data_key)
            .finalize()
            .into_bytes();

        // step 6: Compare t2 with t, using a constant-time compare function. If it does not match, abort.
        if sealed_key.tag.ct_ne(&t2).into() {
            return Err(PasetoError::CryptoError);
        }

        let ek = blake2::Blake2b::new()
            .chain_update([0x01])
            .chain_update(Self::PASERK_HEADER)
            .chain_update(".seal.")
            .chain_update(xk.as_bytes())
            .chain_update(epk.as_bytes())
            .chain_update(xpk.as_bytes())
            .finalize();

        let n = blake2::Blake2b::new()
            .chain_update(epk.as_bytes())
            .chain_update(xpk.as_bytes())
            .finalize();

        chacha20::XChaCha20::new(&ek, &n).apply_keystream(&mut sealed_key.encrypted_data_key);
        Ok(Key {
            key: Box::new(sealed_key.encrypted_data_key),
        })
    }
}

impl<V: SealedVersion> FromStr for SealedKey<V> {
    type Err = PasetoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .strip_prefix(V::PASERK_HEADER)
            .ok_or(PasetoError::InvalidToken)?;
        let s = s.strip_prefix(".seal.").ok_or(PasetoError::InvalidToken)?;

        let total = read_b64::<GenericArray<u8, V::TotalLen>>(s)?;

        Ok(V::split_total(total))
    }
}

impl<V: SealedVersion> fmt::Display for SealedKey<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(V::PASERK_HEADER)?;
        f.write_str(".seal.")?;

        write_b64(&V::join_total(self), f)
    }
}

#[cfg(any(test, fuzzing))]
pub mod fuzz_tests {
    use crate::{
        fuzzing::FakeRng,
        key::Key,
        purpose::{local::Local, public::Secret},
        version::{V3, V4},
    };

    #[derive(Debug)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct V3SealInput {
        key: Key<V3, Local>,
        secret_key: Key<V3, Secret>,
        ephemeral: FakeRng<48>,
    }

    impl V3SealInput {
        pub fn run(mut self) {
            let x: Option<p384::Scalar> =
                p384::Scalar::from_bytes(&self.ephemeral.bytes.into()).into();
            match x {
                Some(s) if s.is_zero().into() => return,
                None => return,
                Some(_) => {}
            }

            let sealed = self
                .key
                .seal_with_rng(&self.secret_key.public_key(), &mut self.ephemeral);
            let local_key2 = sealed.unseal(&self.secret_key).unwrap();

            assert_eq!(self.key, local_key2);
        }
    }

    #[derive(Debug)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct V4SealInput {
        key: Key<V4, Local>,
        secret_key: Key<V4, Secret>,
        ephemeral: FakeRng<32>,
    }

    impl V4SealInput {
        pub fn run(mut self) {
            let sealed = self
                .key
                .seal_with_rng(&self.secret_key.public_key(), &mut self.ephemeral);
            let local_key2 = sealed.unseal(&self.secret_key).unwrap();

            assert_eq!(self.key, local_key2);
        }
    }
}

impl<V: SealedVersion> serde::Serialize for SealedKey<V> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de, V: SealedVersion> serde::Deserialize<'de> for SealedKey<V> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct FromStrVisitor<V>(std::marker::PhantomData<V>);
        impl<'de, V: SealedVersion> serde::de::Visitor<'de> for FromStrVisitor<V> {
            type Value = SealedKey<V>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "a \"{}.seal.\" serialized key", V::PASERK_HEADER)
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                v.parse().map_err(E::custom)
            }
        }
        deserializer.deserialize_str(FromStrVisitor(std::marker::PhantomData))
    }
}
