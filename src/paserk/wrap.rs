//! PASERK uses symmetric-key encryption to wrap PASETO keys.
//!
//! <https://github.com/paseto-standard/paserk/blob/master/operations/Wrap.md>
//! <https://github.com/paseto-standard/paserk/blob/master/operations/Wrap/pie.md>

use std::{fmt, ops::DerefMut, str::FromStr};

use cipher::{KeyInit, KeyIvInit, StreamCipher};
use digest::{Mac, OutputSizeUser};
use generic_array::{
    sequence::{Concat, GenericSequence, Split},
    typenum::U32,
    GenericArray,
};
use rand::{rngs::OsRng, CryptoRng, RngCore};
use rusty_paseto::core::PasetoError;

#[cfg(feature = "v3")]
use rusty_paseto::core::V3;
#[cfg(feature = "v4")]
use rusty_paseto::core::V4;
use subtle::ConstantTimeEq;

use crate::{read_b64, write_b64, Key, KeyType, Local, Secret, Version};

/// Paragon Initiative Enterprises standard key-wrapping
///
/// # Local Wrapping
/// ```
/// use rusty_paserk::{PieWrappedKey, Key, Local, V4};
///
/// let wrapping_key = Key::<V4, Local>::new_os_random();
///
/// let local_key = Key::<V4, Local>::new_os_random();
///
/// let wrapped_local = local_key.wrap_pie(&wrapping_key).to_string();
/// // => "k4.local-wrap.pie.RcAvOxHI0H-0uMsIl6KGcplH_tDlOhW1omFwXltZCiynHeRNH0hmn28AkN516h3WHuAReH3CvQ2SZ6mevnTquPETSd3XnlcbRWACT5GLWcus3BsD4IFWm9wFZgNF7C_E"
///
/// let wrapped_local: PieWrappedKey<V4, Local> = wrapped_local.parse().unwrap();
/// let local_key2 = wrapped_local.unwrap_key(&wrapping_key).unwrap();
/// assert_eq!(local_key, local_key2);
/// ```
///
/// # Secret Wrapping
/// ```
/// use rusty_paserk::{PieWrappedKey, Key, Local, Secret, V4};
///
/// let wrapping_key = Key::<V4, Local>::new_os_random();
///
/// let secret_key = Key::<V4, Secret>::new_os_random();
///
/// let wrapped_secret = secret_key.wrap_pie(&wrapping_key).to_string();
/// // => "k4.secret-wrap.pie.cTTnZwzBA3AKBugQCzmctv5R9CjyPOlelG9SLZrhupDwk6vYx-3UQFCZ7x4d57KU4K4U1qJeFP6ELzkMJ0s8qHt0hsQkW14Ni6TJ89MRzEqglUgI6hJD-EF2E9kIFO5YuC5MHwXN7Wi_vG1S3L-OoTjZgT_ZJ__8T7SJhvYLodo"
///
/// let wrapped_secret: PieWrappedKey<V4, Secret> = wrapped_secret.parse().unwrap();
/// let secret_key2 = wrapped_secret.unwrap_key(&wrapping_key).unwrap();
/// assert_eq!(secret_key, secret_key2);
/// ```
pub struct PieWrappedKey<V: PieVersion, K: KeyType<V>> {
    tag: V::Tag,
    nonce: GenericArray<u8, U32>,
    wrapped_key: GenericArray<u8, K::KeyLen>,
}

impl<V, K> super::SafeForFooter for PieWrappedKey<V, K>
where
    V: PieVersion,
    K: PieWrapType<V>,
{
}

impl<V: PieVersion, K: PieWrapType<V>> Key<V, K> {
    /// Paragon Initiative Enterprises standard key-wrapping
    ///
    /// # Local Wrapping
    /// ```
    /// use rusty_paserk::{PieWrappedKey, Key, Local, V4};
    ///
    /// let wrapping_key = Key::<V4, Local>::new_os_random();
    ///
    /// let local_key = Key::<V4, Local>::new_os_random();
    ///
    /// let wrapped_local = local_key.wrap_pie(&wrapping_key).to_string();
    /// // => "k4.local-wrap.pie.RcAvOxHI0H-0uMsIl6KGcplH_tDlOhW1omFwXltZCiynHeRNH0hmn28AkN516h3WHuAReH3CvQ2SZ6mevnTquPETSd3XnlcbRWACT5GLWcus3BsD4IFWm9wFZgNF7C_E"
    ///
    /// let wrapped_local: PieWrappedKey<V4, Local> = wrapped_local.parse().unwrap();
    /// let local_key2 = wrapped_local.unwrap_key(&wrapping_key).unwrap();
    /// assert_eq!(local_key, local_key2);
    /// ```
    ///
    /// # Secret Wrapping
    /// ```
    /// use rusty_paserk::{PieWrappedKey, Key, Local, Secret, V4};
    ///
    /// let wrapping_key = Key::<V4, Local>::new_os_random();
    ///
    /// let secret_key = Key::<V4, Secret>::new_os_random();
    ///
    /// let wrapped_secret = secret_key.wrap_pie(&wrapping_key).to_string();
    /// // => "k4.secret-wrap.pie.cTTnZwzBA3AKBugQCzmctv5R9CjyPOlelG9SLZrhupDwk6vYx-3UQFCZ7x4d57KU4K4U1qJeFP6ELzkMJ0s8qHt0hsQkW14Ni6TJ89MRzEqglUgI6hJD-EF2E9kIFO5YuC5MHwXN7Wi_vG1S3L-OoTjZgT_ZJ__8T7SJhvYLodo"
    ///
    /// let wrapped_secret: PieWrappedKey<V4, Secret> = wrapped_secret.parse().unwrap();
    /// let secret_key2 = wrapped_secret.unwrap_key(&wrapping_key).unwrap();
    /// assert_eq!(secret_key, secret_key2);
    /// ```
    pub fn wrap_pie(&self, wrapping_key: &Key<V, Local>) -> PieWrappedKey<V, K> {
        self.wrap_pie_with_rng(wrapping_key, &mut OsRng)
    }

    /// Paragon Initiative Enterprises standard key-wrapping.
    ///
    /// Using the given RNG source for the IV
    pub fn wrap_pie_with_rng(
        &self,
        wrapping_key: &Key<V, Local>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> PieWrappedKey<V, K> {
        // step 1: Enforce Algorithm Lucidity
        // asserted by the caller.

        // step 2: Generate a 256 bit (32 bytes) random nonce, n.
        let mut n = GenericArray::<u8, U32>::default();
        rng.fill_bytes(&mut n);

        // step 3: Derive the encryption key `Ek` and XChaCha nonce `n2`
        let ek = <V::EncKeyMac as Mac>::new_from_slice(wrapping_key.as_ref())
            .unwrap()
            .chain_update([0x80])
            .chain_update(n)
            .finalize()
            .into_bytes();
        let (ek, n2) = V::split_enc_key(ek);

        // step 4: Derive the authentication key `Ak`
        let ak = <V::AuthKeyMac as Mac>::new_from_slice(wrapping_key.as_ref())
            .unwrap()
            .chain_update([0x81])
            .chain_update(n)
            .finalize()
            .into_bytes();

        // step 5: Encrypt the plaintext key `ptk` with `Ek` and `n2` to obtain the wrapped key `c`
        let mut cipher = <V::Cipher as KeyIvInit>::new(&ek, &n2);
        let mut c = GenericArray::<u8, K::KeyLen>::default();
        cipher.apply_keystream_b2b(self.as_ref(), &mut c).unwrap();

        // step 6: Calculate the authentication tag `t`
        let tag = <V::TagMac as Mac>::new_from_slice(&ak[..32])
            .unwrap()
            .chain_update(V::KEY_HEADER)
            .chain_update(K::WRAP_HEADER)
            .chain_update("pie.")
            .chain_update(n)
            .chain_update(&c)
            .finalize()
            .into_bytes();

        PieWrappedKey {
            wrapped_key: c,
            nonce: n,
            tag: tag.into(),
        }
    }
}

impl<V, K> PieWrappedKey<V, K>
where
    K: PieWrapType<V>,
    V: PieVersion,
{
    /// Paragon Initiative Enterprises standard key-wrapping
    ///
    /// # Local Wrapping
    /// ```
    /// use rusty_paserk::{PieWrappedKey, Key, Local, V4};
    ///
    /// let wrapping_key = Key::<V4, Local>::new_os_random();
    ///
    /// let local_key = Key::<V4, Local>::new_os_random();
    ///
    /// let wrapped_local = local_key.wrap_pie(&wrapping_key).to_string();
    /// // => "k4.local-wrap.pie.RcAvOxHI0H-0uMsIl6KGcplH_tDlOhW1omFwXltZCiynHeRNH0hmn28AkN516h3WHuAReH3CvQ2SZ6mevnTquPETSd3XnlcbRWACT5GLWcus3BsD4IFWm9wFZgNF7C_E"
    ///
    /// let wrapped_local: PieWrappedKey<V4, Local> = wrapped_local.parse().unwrap();
    /// let local_key2 = wrapped_local.unwrap_key(&wrapping_key).unwrap();
    /// assert_eq!(local_key, local_key2);
    /// ```
    ///
    /// # Secret Wrapping
    /// ```
    /// use rusty_paserk::{PieWrappedKey, Key, Local, Secret, V4};
    ///
    /// let wrapping_key = Key::<V4, Local>::new_os_random();
    ///
    /// let secret_key = Key::<V4, Secret>::new_os_random();
    ///
    /// let wrapped_secret = secret_key.wrap_pie(&wrapping_key).to_string();
    /// // => "k4.secret-wrap.pie.cTTnZwzBA3AKBugQCzmctv5R9CjyPOlelG9SLZrhupDwk6vYx-3UQFCZ7x4d57KU4K4U1qJeFP6ELzkMJ0s8qHt0hsQkW14Ni6TJ89MRzEqglUgI6hJD-EF2E9kIFO5YuC5MHwXN7Wi_vG1S3L-OoTjZgT_ZJ__8T7SJhvYLodo"
    ///
    /// let wrapped_secret: PieWrappedKey<V4, Secret> = wrapped_secret.parse().unwrap();
    /// let secret_key2 = wrapped_secret.unwrap_key(&wrapping_key).unwrap();
    /// assert_eq!(secret_key, secret_key2);
    /// ```
    pub fn unwrap_key(self, wrapping_key: &Key<V, Local>) -> Result<Key<V, K>, PasetoError> {
        let Self {
            mut wrapped_key,
            nonce,
            tag,
            ..
        } = self;

        // step 2: Derive the authentication key `Ak`
        let ak = <V::AuthKeyMac as Mac>::new_from_slice(wrapping_key.as_ref())
            .unwrap()
            .chain_update([0x81])
            .chain_update(nonce)
            .finalize()
            .into_bytes();

        // step 3: Recalculate the authentication tag t2
        let tag2 = <V::TagMac as Mac>::new_from_slice(&ak[..32])
            .unwrap()
            .chain_update(V::KEY_HEADER)
            .chain_update(K::WRAP_HEADER)
            .chain_update("pie.")
            .chain_update(nonce)
            .chain_update(&wrapped_key)
            .finalize()
            .into_bytes();

        // step 4: Compare t with t2 in constant-time. If it doesn't match, abort.
        if tag.ct_ne(&tag2).into() {
            return Err(PasetoError::InvalidSignature);
        }

        // step 5: Derive the encryption key `Ek` and XChaCha nonce `n2`
        let ek = <V::EncKeyMac as Mac>::new_from_slice(wrapping_key.as_ref())
            .unwrap()
            .chain_update([0x80])
            .chain_update(nonce)
            .finalize()
            .into_bytes();
        let (ek, n2) = V::split_enc_key(ek);

        // step 6: Decrypt the wrapped key `c` with `Ek` and `n2` to obtain the plaintext key `ptk`
        let mut cipher = <V::Cipher as KeyIvInit>::new(&ek, &n2);
        cipher.apply_keystream(&mut wrapped_key);

        // step 7: Enforce Algorithm Lucidity
        // asserted by type signature

        // step 8: return ptk
        Ok(Key { key: wrapped_key })
    }
}

impl<V: PieVersion, K: PieWrapType<V>> FromStr for PieWrappedKey<V, K> {
    type Err = PasetoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .strip_prefix(V::KEY_HEADER)
            .ok_or(PasetoError::WrongHeader)?;
        let s = s
            .strip_prefix(K::WRAP_HEADER)
            .ok_or(PasetoError::WrongHeader)?;
        let s = s.strip_prefix("pie.").ok_or(PasetoError::WrongHeader)?;

        let total = read_b64::<K::Output>(s)?;

        let (tagiv, wrapped_key) = total.split();
        let (tag, nonce) = tagiv.split();

        Ok(Self {
            wrapped_key,
            nonce,
            tag,
        })
    }
}

impl<V: PieVersion, K: PieWrapType<V>> fmt::Display for PieWrappedKey<V, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(V::KEY_HEADER)?;
        f.write_str(K::WRAP_HEADER)?;
        f.write_str("pie.")?;

        let tagiv: K::TagIv = self.tag.concat(self.nonce).into();
        let output = tagiv.concat(self.wrapped_key.clone());

        write_b64(&output, f)
    }
}

/// Version info for configuring PIE Key wrapping
pub trait PieVersion: Version {
    #[doc(hidden)]
    type Cipher: StreamCipher + KeyIvInit;
    #[doc(hidden)]
    type AuthKeyMac: Mac + KeyInit;
    #[doc(hidden)]
    type EncKeyMac: Mac + KeyInit;
    #[doc(hidden)]
    type TagMac: Mac
        + KeyInit
        + OutputSizeUser<OutputSize = <Self::Tag as GenericSequence<u8>>::Length>;

    #[doc(hidden)]
    type Tag: Concat<u8, U32, Rest = GenericArray<u8, U32>, Output = Self::TagIv>
        + From<digest::Output<Self::TagMac>>
        + DerefMut<Target = [u8]>
        + Copy;
    #[doc(hidden)]
    type TagIv: Split<
        u8,
        <Self::Tag as GenericSequence<u8>>::Length,
        First = Self::Tag,
        Second = GenericArray<u8, U32>,
    >;

    #[doc(hidden)]
    fn split_enc_key(
        ek: digest::Output<Self::EncKeyMac>,
    ) -> (cipher::Key<Self::Cipher>, cipher::Iv<Self::Cipher>);
}

#[cfg(feature = "v3")]
impl PieVersion for V3 {
    type Cipher = ctr::Ctr64BE<aes::Aes256>;
    type AuthKeyMac = hmac::Hmac<sha2::Sha384>;
    type EncKeyMac = hmac::Hmac<sha2::Sha384>;
    type TagMac = hmac::Hmac<sha2::Sha384>;

    type Tag = digest::Output<Self::TagMac>;
    type TagIv = GenericArray<u8, generic_array::typenum::U80>;

    fn split_enc_key(
        ek: digest::Output<Self::EncKeyMac>,
    ) -> (cipher::Key<Self::Cipher>, cipher::Iv<Self::Cipher>) {
        ek.split()
    }
}

#[cfg(feature = "v4")]
impl PieVersion for V4 {
    type Cipher = chacha20::XChaCha20;
    type AuthKeyMac = blake2::Blake2bMac<U32>;
    type EncKeyMac = blake2::Blake2bMac<generic_array::typenum::U56>;
    type TagMac = blake2::Blake2bMac<U32>;

    type Tag = digest::Output<Self::TagMac>;
    type TagIv = GenericArray<u8, generic_array::typenum::U64>;

    fn split_enc_key(
        ek: digest::Output<Self::EncKeyMac>,
    ) -> (cipher::Key<Self::Cipher>, cipher::Iv<Self::Cipher>) {
        ek.split()
    }
}

/// Key wrapping type. Can be either `local-wrap.` or `secret-wrap.`
pub trait WrapType {
    /// The header used when wrapping
    const WRAP_HEADER: &'static str;
}

impl WrapType for Local {
    const WRAP_HEADER: &'static str = "local-wrap.";
}

impl WrapType for Secret {
    const WRAP_HEADER: &'static str = "secret-wrap.";
}

/// Helper trait for configuring the key wrapping
pub trait PieWrapType<V: PieVersion>: KeyType<V> + WrapType {
    #[doc(hidden)]
    type Output: Split<
            u8,
            <V::TagIv as GenericSequence<u8>>::Length,
            First = V::TagIv,
            Second = GenericArray<u8, Self::KeyLen>,
        > + Default
        + DerefMut<Target = [u8]>;
    #[doc(hidden)]
    type TagIv: From<V::TagIv>
        + Concat<u8, Self::KeyLen, Rest = GenericArray<u8, Self::KeyLen>, Output = Self::Output>;
}

#[cfg(feature = "v3")]
impl PieWrapType<V3> for Local {
    // 32 + 48 + 32 = 112
    type Output = GenericArray<u8, generic_array::typenum::U112>;
    type TagIv = <V3 as PieVersion>::TagIv;
}

#[cfg(feature = "v3")]
impl PieWrapType<V3> for Secret {
    // 32 + 48 + 48 = 128
    type Output = GenericArray<u8, generic_array::typenum::U128>;
    type TagIv = <V3 as PieVersion>::TagIv;
}

#[cfg(feature = "v4")]
impl PieWrapType<V4> for Local {
    // 32 + 32 + 32 = 96
    type Output = GenericArray<u8, generic_array::typenum::U96>;
    type TagIv = <V4 as PieVersion>::TagIv;
}

#[cfg(feature = "v4")]
impl PieWrapType<V4> for Secret {
    // 32 + 32 + 64 = 128
    type Output = GenericArray<u8, generic_array::typenum::U128>;
    type TagIv = <V4 as PieVersion>::TagIv;
}

#[cfg(any(test, fuzzing))]
pub mod fuzz_tests {
    use crate::{fuzzing::FakeRng, Key, Local};

    use super::{PieVersion, PieWrapType};

    #[derive(Debug)]
    pub struct FuzzInput<V: PieVersion, K: PieWrapType<V>> {
        wrapping_key: Key<V, Local>,
        key: Key<V, K>,
        ephemeral: FakeRng<32>,
    }

    #[cfg(feature = "arbitrary")]
    impl<'a, V: PieVersion, K: PieWrapType<V>> arbitrary::Arbitrary<'a> for FuzzInput<V, K>
    where
        Key<V, Local>: arbitrary::Arbitrary<'a>,
        Key<V, K>: arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                wrapping_key: u.arbitrary()?,
                key: u.arbitrary()?,
                ephemeral: u.arbitrary()?,
            })
        }
    }

    impl<V: PieVersion, K: PieWrapType<V>> FuzzInput<V, K> {
        pub fn run(mut self) {
            let mut wrapped = self
                .key
                .wrap_pie_with_rng(&self.wrapping_key, &mut self.ephemeral);
            let s = wrapped.to_string();
            wrapped = s.parse().unwrap();
            let key = wrapped.unwrap_key(&self.wrapping_key).unwrap();

            assert_eq!(self.key, key);
        }
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
#[cfg(feature = "serde")]
impl<V: PieVersion, K: PieWrapType<V>> serde::Serialize for PieWrappedKey<V, K> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
#[cfg(feature = "serde")]
impl<'de, V: PieVersion, K: PieWrapType<V>> serde::Deserialize<'de> for PieWrappedKey<V, K> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct FromStrVisitor<V, K>(std::marker::PhantomData<(V, K)>);
        impl<'de, V: PieVersion, K: PieWrapType<V>> serde::de::Visitor<'de> for FromStrVisitor<V, K> {
            type Value = PieWrappedKey<V, K>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(
                    formatter,
                    "a \"{}{}pie.\" serialized key",
                    V::KEY_HEADER,
                    K::WRAP_HEADER
                )
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
