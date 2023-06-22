//! PASERK uses symmetric-key encryption to wrap PASETO keys.
//!
//! <https://github.com/paseto-standard/paserk/blob/master/operations/Wrap.md>

use std::{fmt, str::FromStr};

use base64::URL_SAFE_NO_PAD;
use cipher::{KeyInit, KeyIvInit, StreamCipher, Unsigned};
use digest::{Mac, OutputSizeUser};
use generic_array::{
    sequence::{Concat, Split},
    typenum::U32,
    ArrayLength, GenericArray,
};
use rand::{rngs::OsRng, CryptoRng, RngCore};
use rusty_paseto::core::PasetoError;

#[cfg(feature = "v3")]
use rusty_paseto::core::V3;
#[cfg(feature = "v4")]
use rusty_paseto::core::V4;
use subtle::ConstantTimeEq;

use crate::key::{write_b64, Key, KeyType, Local, Secret, Version};

/// Paragon Initiative Enterprises standard key-wrapping
/// <https://github.com/paseto-standard/paserk/blob/master/operations/Wrap/pie.md>
///
/// # Local Wrapping
/// ```
/// use rusty_paserk::{PieWrappedKey, Key, Local, V4};
///
/// let wrapping_key = Key::<V4, Local>::new_random();
///
/// let local_key = Key::<V4, Local>::new_random();
///
/// let wrapped_local = local_key.wrap_pie(&wrapping_key).to_string();
/// // => "k4.local-wrap.pie.RcAvOxHI0H-0uMsIl6KGcplH_tDlOhW1omFwXltZCiynHeRNH0hmn28AkN516h3WHuAReH3CvQ2SZ6mevnTquPETSd3XnlcbRWACT5GLWcus3BsD4IFWm9wFZgNF7C_E"
///
/// let wrapped_local: PieWrappedKey<V4, Local> = wrapped_local.parse().unwrap();
/// let local_key2 = wrapped_local.unwrap(&wrapping_key).unwrap();
/// assert_eq!(local_key, local_key2);
/// ```
///
/// # Secret Wrapping
/// ```
/// use rusty_paserk::{PieWrappedKey, Key, Local, Secret, V4};
///
/// let wrapping_key = Key::<V4, Local>::new_random();
///
/// let secret_key = Key::<V4, Secret>::new_random();
///
/// let wrapped_secret = secret_key.wrap_pie(&wrapping_key).to_string();
/// // => "k4.secret-wrap.pie.cTTnZwzBA3AKBugQCzmctv5R9CjyPOlelG9SLZrhupDwk6vYx-3UQFCZ7x4d57KU4K4U1qJeFP6ELzkMJ0s8qHt0hsQkW14Ni6TJ89MRzEqglUgI6hJD-EF2E9kIFO5YuC5MHwXN7Wi_vG1S3L-OoTjZgT_ZJ__8T7SJhvYLodo"
///
/// let wrapped_secret: PieWrappedKey<V4, Secret> = wrapped_secret.parse().unwrap();
/// let secret_key2 = wrapped_secret.unwrap(&wrapping_key).unwrap();
/// assert_eq!(secret_key, secret_key2);
/// ```
pub struct PieWrappedKey<V: PieVersion, K: KeyType<V>> {
    tag: GenericArray<u8, <V::TagMac as OutputSizeUser>::OutputSize>,
    nonce: GenericArray<u8, U32>,
    wrapped_key: GenericArray<u8, K::KeyLen>,
}

impl<V: PieVersion, K: WrapType<V>> Key<V, K> {
    /// Paragon Initiative Enterprises standard key-wrapping
    /// <https://github.com/paseto-standard/paserk/blob/master/operations/Wrap/pie.md>
    ///
    /// # Local Wrapping
    /// ```
    /// use rusty_paserk::{PieWrappedKey, Key, Local, V4};
    ///
    /// let wrapping_key = Key::<V4, Local>::new_random();
    ///
    /// let local_key = Key::<V4, Local>::new_random();
    ///
    /// let wrapped_local = local_key.wrap_pie(&wrapping_key).to_string();
    /// // => "k4.local-wrap.pie.RcAvOxHI0H-0uMsIl6KGcplH_tDlOhW1omFwXltZCiynHeRNH0hmn28AkN516h3WHuAReH3CvQ2SZ6mevnTquPETSd3XnlcbRWACT5GLWcus3BsD4IFWm9wFZgNF7C_E"
    ///
    /// let wrapped_local: PieWrappedKey<V4, Local> = wrapped_local.parse().unwrap();
    /// let local_key2 = wrapped_local.unwrap(&wrapping_key).unwrap();
    /// assert_eq!(local_key, local_key2);
    /// ```
    ///
    /// # Secret Wrapping
    /// ```
    /// use rusty_paserk::{PieWrappedKey, Key, Local, Secret, V4};
    ///
    /// let wrapping_key = Key::<V4, Local>::new_random();
    ///
    /// let secret_key = Key::<V4, Secret>::new_random();
    ///
    /// let wrapped_secret = secret_key.wrap_pie(&wrapping_key).to_string();
    /// // => "k4.secret-wrap.pie.cTTnZwzBA3AKBugQCzmctv5R9CjyPOlelG9SLZrhupDwk6vYx-3UQFCZ7x4d57KU4K4U1qJeFP6ELzkMJ0s8qHt0hsQkW14Ni6TJ89MRzEqglUgI6hJD-EF2E9kIFO5YuC5MHwXN7Wi_vG1S3L-OoTjZgT_ZJ__8T7SJhvYLodo"
    ///
    /// let wrapped_secret: PieWrappedKey<V4, Secret> = wrapped_secret.parse().unwrap();
    /// let secret_key2 = wrapped_secret.unwrap(&wrapping_key).unwrap();
    /// assert_eq!(secret_key, secret_key2);
    /// ```
    pub fn wrap_pie(&self, wrapping_key: &Key<V, Local>) -> PieWrappedKey<V, K> {
        self.wrap_pie_with_rng(wrapping_key, &mut OsRng)
    }
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
            tag,
        }
    }
}

impl<V, K> PieWrappedKey<V, K>
where
    K: WrapType<V>,
    V: PieVersion,
{
    /// Paragon Initiative Enterprises standard key-wrapping
    /// <https://github.com/paseto-standard/paserk/blob/master/operations/Wrap/pie.md>
    ///
    /// # Local Wrapping
    /// ```
    /// use rusty_paserk::{PieWrappedKey, Key, Local, V4};
    ///
    /// let wrapping_key = Key::<V4, Local>::new_random();
    ///
    /// let local_key = Key::<V4, Local>::new_random();
    ///
    /// let wrapped_local = local_key.wrap_pie(&wrapping_key).to_string();
    /// // => "k4.local-wrap.pie.RcAvOxHI0H-0uMsIl6KGcplH_tDlOhW1omFwXltZCiynHeRNH0hmn28AkN516h3WHuAReH3CvQ2SZ6mevnTquPETSd3XnlcbRWACT5GLWcus3BsD4IFWm9wFZgNF7C_E"
    ///
    /// let wrapped_local: PieWrappedKey<V4, Local> = wrapped_local.parse().unwrap();
    /// let local_key2 = wrapped_local.unwrap(&wrapping_key).unwrap();
    /// assert_eq!(local_key, local_key2);
    /// ```
    ///
    /// # Secret Wrapping
    /// ```
    /// use rusty_paserk::{PieWrappedKey, Key, Local, Secret, V4};
    ///
    /// let wrapping_key = Key::<V4, Local>::new_random();
    ///
    /// let secret_key = Key::<V4, Secret>::new_random();
    ///
    /// let wrapped_secret = secret_key.wrap_pie(&wrapping_key).to_string();
    /// // => "k4.secret-wrap.pie.cTTnZwzBA3AKBugQCzmctv5R9CjyPOlelG9SLZrhupDwk6vYx-3UQFCZ7x4d57KU4K4U1qJeFP6ELzkMJ0s8qHt0hsQkW14Ni6TJ89MRzEqglUgI6hJD-EF2E9kIFO5YuC5MHwXN7Wi_vG1S3L-OoTjZgT_ZJ__8T7SJhvYLodo"
    ///
    /// let wrapped_secret: PieWrappedKey<V4, Secret> = wrapped_secret.parse().unwrap();
    /// let secret_key2 = wrapped_secret.unwrap(&wrapping_key).unwrap();
    /// assert_eq!(secret_key, secret_key2);
    /// ```
    pub fn unwrap(self, wrapping_key: &Key<V, Local>) -> Result<Key<V, K>, PasetoError> {
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
        Ok(wrapped_key.into())
    }
}

impl<V: PieVersion, K: WrapType<V>> FromStr for PieWrappedKey<V, K> {
    type Err = PasetoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .strip_prefix(V::KEY_HEADER)
            .ok_or(PasetoError::WrongHeader)?;
        let s = s
            .strip_prefix(K::WRAP_HEADER)
            .ok_or(PasetoError::WrongHeader)?;
        let s = s.strip_prefix("pie.").ok_or(PasetoError::WrongHeader)?;

        let mut total = GenericArray::<u8, K::TotalLen>::default();
        let len = base64::decode_config_slice(s, URL_SAFE_NO_PAD, &mut total)?;
        if len != <K::TotalLen as Unsigned>::USIZE {
            return Err(PasetoError::PayloadBase64Decode {
                source: base64::DecodeError::InvalidLength,
            });
        }

        let (tag, nonce, wrapped_key) = K::split_total(total);

        Ok(Self {
            wrapped_key,
            nonce,
            tag,
        })
    }
}

impl<V: PieVersion, K: WrapType<V>> fmt::Display for PieWrappedKey<V, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(V::KEY_HEADER)?;
        f.write_str(K::WRAP_HEADER)?;
        f.write_str("pie.")?;

        let total = K::into_total(&self.tag, &self.nonce, &self.wrapped_key);
        write_b64(&total, f)
    }
}

/// Version info for configuring PIE Key wrapping
pub trait PieVersion: Version {
    type Cipher: StreamCipher + KeyIvInit;
    type AuthKeyMac: Mac + KeyInit;
    type EncKeyMac: Mac + KeyInit;
    type TagMac: Mac + KeyInit;

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

    fn split_enc_key(
        ek: digest::Output<Self::EncKeyMac>,
    ) -> (cipher::Key<Self::Cipher>, cipher::Iv<Self::Cipher>) {
        ek.split()
    }
}

/// Key wrap information (`local`/`secret`)
pub trait WrapType<V: PieVersion>: KeyType<V> {
    const WRAP_HEADER: &'static str;

    type TotalLen: ArrayLength<u8>;
    #[allow(clippy::type_complexity)]
    fn split_total(
        total: GenericArray<u8, Self::TotalLen>,
    ) -> (
        digest::Output<V::TagMac>,
        GenericArray<u8, U32>,
        GenericArray<u8, Self::KeyLen>,
    );
    fn into_total(
        tag: &digest::Output<V::TagMac>,
        nonce: &GenericArray<u8, U32>,
        wrapped_key: &GenericArray<u8, Self::KeyLen>,
    ) -> GenericArray<u8, Self::TotalLen>;
}

#[cfg(feature = "v3")]
impl WrapType<V3> for Local {
    const WRAP_HEADER: &'static str = "local-wrap.";

    // 32 + 48 + 32 = 112
    type TotalLen = generic_array::typenum::U112;
    fn split_total(
        total: GenericArray<u8, Self::TotalLen>,
    ) -> (
        digest::Output<<V3 as PieVersion>::TagMac>,
        GenericArray<u8, U32>,
        GenericArray<u8, Self::KeyLen>,
    ) {
        let (tag, rest) = total.split();
        let (nonce, c) = rest.split();
        (tag, nonce, c)
    }
    fn into_total(
        tag: &digest::Output<<V3 as PieVersion>::TagMac>,
        nonce: &GenericArray<u8, U32>,
        wrapped_key: &GenericArray<u8, Self::KeyLen>,
    ) -> GenericArray<u8, Self::TotalLen> {
        tag.concat(*nonce).concat(*wrapped_key)
    }
}

#[cfg(feature = "v3")]
impl WrapType<V3> for Secret {
    const WRAP_HEADER: &'static str = "secret-wrap.";

    // 32 + 48 + 48 = 128
    type TotalLen = generic_array::typenum::U128;
    fn split_total(
        total: GenericArray<u8, Self::TotalLen>,
    ) -> (
        digest::Output<<V3 as PieVersion>::TagMac>,
        GenericArray<u8, U32>,
        GenericArray<u8, Self::KeyLen>,
    ) {
        let (tag, rest) = total.split();
        let (nonce, c) = rest.split();
        (tag, nonce, c)
    }
    fn into_total(
        tag: &digest::Output<<V3 as PieVersion>::TagMac>,
        nonce: &GenericArray<u8, U32>,
        wrapped_key: &GenericArray<u8, Self::KeyLen>,
    ) -> GenericArray<u8, Self::TotalLen> {
        tag.concat(*nonce).concat(*wrapped_key)
    }
}

#[cfg(feature = "v4")]
impl WrapType<V4> for Local {
    const WRAP_HEADER: &'static str = "local-wrap.";

    // 32 + 32 + 32 = 96
    type TotalLen = generic_array::typenum::U96;
    fn split_total(
        total: GenericArray<u8, Self::TotalLen>,
    ) -> (
        digest::Output<<V4 as PieVersion>::TagMac>,
        GenericArray<u8, U32>,
        GenericArray<u8, Self::KeyLen>,
    ) {
        let (tag, rest) = total.split();
        let (nonce, c) = rest.split();
        (tag, nonce, c)
    }
    fn into_total(
        tag: &digest::Output<<V4 as PieVersion>::TagMac>,
        nonce: &GenericArray<u8, U32>,
        wrapped_key: &GenericArray<u8, Self::KeyLen>,
    ) -> GenericArray<u8, Self::TotalLen> {
        tag.concat(*nonce).concat(*wrapped_key)
    }
}

#[cfg(feature = "v4")]
impl WrapType<V4> for Secret {
    const WRAP_HEADER: &'static str = "secret-wrap.";

    // 32 + 32 + 64 = 128
    type TotalLen = generic_array::typenum::U128;
    fn split_total(
        total: GenericArray<u8, Self::TotalLen>,
    ) -> (
        digest::Output<<V4 as PieVersion>::TagMac>,
        GenericArray<u8, U32>,
        GenericArray<u8, Self::KeyLen>,
    ) {
        let (tag, rest) = total.split();
        let (nonce, c) = rest.split();
        (tag, nonce, c)
    }
    fn into_total(
        tag: &digest::Output<<V4 as PieVersion>::TagMac>,
        nonce: &GenericArray<u8, U32>,
        wrapped_key: &GenericArray<u8, Self::KeyLen>,
    ) -> GenericArray<u8, Self::TotalLen> {
        tag.concat(*nonce).concat(*wrapped_key)
    }
}
