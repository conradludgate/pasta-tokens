//! PASERK uses symmetric-key encryption to wrap PASETO keys.
//!
//! <https://github.com/paseto-standard/paserk/blob/master/operations/Wrap.md>

use rusty_paseto::core::{Key, Local, PasetoError, PasetoSymmetricKey};

#[cfg(feature = "v1")]
use rusty_paseto::core::V1;
#[cfg(feature = "v2")]
use rusty_paseto::core::V2;
#[cfg(feature = "v3")]
use rusty_paseto::core::V3;
#[cfg(feature = "v4")]
use rusty_paseto::core::V4;

/// Paragon Initiative Enterprises standard key-wrapping
/// <https://github.com/paseto-standard/paserk/blob/master/operations/Wrap/pie.md>
///
/// # Local Wrapping
/// ```
/// use rusty_paserk::wrap::{Pie, LocalWrapperExt};
/// use rusty_paseto::core::{PasetoSymmetricKey, V4, Local, Key};
///
/// let wrapping_key = PasetoSymmetricKey::<V4, Local>::from(Key::try_new_random().unwrap());
///
/// let local_key = PasetoSymmetricKey::from(Key::try_new_random().unwrap());
/// let nonce = Key::try_new_random().unwrap();
///
/// let wrapped_local = Pie::wrap_local(&local_key, &wrapping_key, &nonce);
/// // => "k4.local-wrap.pie.RcAvOxHI0H-0uMsIl6KGcplH_tDlOhW1omFwXltZCiynHeRNH0hmn28AkN516h3WHuAReH3CvQ2SZ6mevnTquPETSd3XnlcbRWACT5GLWcus3BsD4IFWm9wFZgNF7C_E"
///
/// let mut wrapped_local = wrapped_local.into_bytes();
/// let local_key2 = Pie::unwrap_local(&mut wrapped_local, &wrapping_key).unwrap();
/// assert_eq!(local_key.as_ref(), local_key2.as_ref());
/// ```
///
/// # Secret Wrapping
/// ```
/// use rusty_paserk::wrap::{Pie, SecretWrapperExt};
/// use rusty_paseto::core::{PasetoSymmetricKey, PasetoAsymmetricPrivateKey, V4, Public, Key};
///
/// let wrapping_key = PasetoSymmetricKey::from(Key::try_new_random().unwrap());
///
/// let secret_key = Key::try_new_random().unwrap();
/// let secret_key = PasetoAsymmetricPrivateKey::<V4, Public>::from(&secret_key);
/// let nonce = Key::try_new_random().unwrap();
///
/// let wrapped_secret = Pie::wrap_secret(&secret_key, &wrapping_key, &nonce);
/// // => "k4.secret-wrap.pie.cTTnZwzBA3AKBugQCzmctv5R9CjyPOlelG9SLZrhupDwk6vYx-3UQFCZ7x4d57KU4K4U1qJeFP6ELzkMJ0s8qHt0hsQkW14Ni6TJ89MRzEqglUgI6hJD-EF2E9kIFO5YuC5MHwXN7Wi_vG1S3L-OoTjZgT_ZJ__8T7SJhvYLodo"
///
/// let mut wrapped_secret = wrapped_secret.into_bytes();
/// let secret_key2 = Pie::unwrap_secret(&mut wrapped_secret, &wrapping_key).unwrap();
/// assert_eq!(secret_key.as_ref(), secret_key2.as_ref());
/// ```
pub struct Pie;

#[cfg(feature = "local")]
mod local {
    use super::*;

    pub trait LocalWrapperExt<Version> {
        fn wrap_local(
            ptk: &PasetoSymmetricKey<Version, Local>,
            wk: &PasetoSymmetricKey<Version, Local>,
            nonce: &Key<{ pie::NONCE_SIZE }>,
        ) -> String;

        fn unwrap_local(
            wpk: &mut [u8],
            wk: &PasetoSymmetricKey<Version, Local>,
        ) -> Result<PasetoSymmetricKey<Version, Local>, PasetoError>;
    }

    #[cfg(feature = "v1")]
    impl LocalWrapperExt<V1> for Pie {
        fn wrap_local(
            ptk: &PasetoSymmetricKey<V1, Local>,
            wk: &PasetoSymmetricKey<V1, Local>,
            nonce: &Key<{ pie::NONCE_SIZE }>,
        ) -> String {
            let header = "k1.local-wrap.pie.";
            pie::v1_v3::wrap(header, ptk.as_ref(), wk.as_ref(), nonce)
        }

        fn unwrap_local(
            wpk: &mut [u8],
            wk: &PasetoSymmetricKey<V1, Local>,
        ) -> Result<PasetoSymmetricKey<V1, Local>, PasetoError> {
            let header = "k1.local-wrap.pie.";
            pie::v1_v3::unwrap(header, wpk, wk.as_ref())
                .and_then(|k| {
                    if k.len() != 32 {
                        Err(PasetoError::IncorrectSize)
                    } else {
                        Ok(k)
                    }
                })
                .map(Key::from)
                .map(PasetoSymmetricKey::from)
        }
    }

    #[cfg(feature = "v2")]
    impl LocalWrapperExt<V2> for Pie {
        fn wrap_local(
            ptk: &PasetoSymmetricKey<V2, Local>,
            wk: &PasetoSymmetricKey<V2, Local>,
            nonce: &Key<{ pie::NONCE_SIZE }>,
        ) -> String {
            let header = "k2.local-wrap.pie.";
            pie::v2_v4::wrap(header, ptk.as_ref(), wk.as_ref(), nonce)
        }

        fn unwrap_local(
            wpk: &mut [u8],
            wk: &PasetoSymmetricKey<V2, Local>,
        ) -> Result<PasetoSymmetricKey<V2, Local>, PasetoError> {
            let header = "k2.local-wrap.pie.";
            pie::v2_v4::unwrap(header, wpk, wk.as_ref())
                .and_then(|k| {
                    if k.len() != 32 {
                        Err(PasetoError::IncorrectSize)
                    } else {
                        Ok(k)
                    }
                })
                .map(Key::from)
                .map(PasetoSymmetricKey::from)
        }
    }

    #[cfg(feature = "v3")]
    impl LocalWrapperExt<V3> for Pie {
        fn wrap_local(
            ptk: &PasetoSymmetricKey<V3, Local>,
            wk: &PasetoSymmetricKey<V3, Local>,
            nonce: &Key<{ pie::NONCE_SIZE }>,
        ) -> String {
            let header = "k3.local-wrap.pie.";
            pie::v1_v3::wrap(header, ptk.as_ref(), wk.as_ref(), nonce)
        }

        fn unwrap_local(
            wpk: &mut [u8],
            wk: &PasetoSymmetricKey<V3, Local>,
        ) -> Result<PasetoSymmetricKey<V3, Local>, PasetoError> {
            let header = "k3.local-wrap.pie.";
            pie::v1_v3::unwrap(header, wpk, wk.as_ref())
                .and_then(|k| {
                    if k.len() != 32 {
                        Err(PasetoError::IncorrectSize)
                    } else {
                        Ok(k)
                    }
                })
                .map(Key::from)
                .map(PasetoSymmetricKey::from)
        }
    }

    #[cfg(feature = "v4")]
    impl LocalWrapperExt<V4> for Pie {
        fn wrap_local(
            ptk: &PasetoSymmetricKey<V4, Local>,
            wk: &PasetoSymmetricKey<V4, Local>,
            nonce: &Key<{ pie::NONCE_SIZE }>,
        ) -> String {
            let header = "k4.local-wrap.pie.";
            pie::v2_v4::wrap(header, ptk.as_ref(), wk.as_ref(), nonce)
        }

        fn unwrap_local(
            wpk: &mut [u8],
            wk: &PasetoSymmetricKey<V4, Local>,
        ) -> Result<PasetoSymmetricKey<V4, Local>, PasetoError> {
            let header = "k4.local-wrap.pie.";
            pie::v2_v4::unwrap(header, wpk, wk.as_ref())
                .and_then(|k| {
                    if k.len() != 32 {
                        Err(PasetoError::IncorrectSize)
                    } else {
                        Ok(k)
                    }
                })
                .map(Key::from)
                .map(PasetoSymmetricKey::from)
        }
    }
}
#[cfg(feature = "local")]
pub use local::LocalWrapperExt;

#[cfg(feature = "public")]
mod public {
    use rusty_paseto::core::{PasetoAsymmetricPrivateKey, Public};

    use super::*;

    pub trait SecretWrapperExt<Version> {
        fn wrap_secret(
            ptk: &PasetoAsymmetricPrivateKey<Version, Public>,
            wk: &PasetoSymmetricKey<Version, Local>,
            nonce: &Key<{ pie::NONCE_SIZE }>,
        ) -> String;

        fn unwrap_secret<'wpk>(
            wpk: &'wpk mut [u8],
            wk: &PasetoSymmetricKey<Version, Local>,
        ) -> Result<PasetoAsymmetricPrivateKey<'wpk, Version, Public>, PasetoError>;
    }

    #[cfg(feature = "v1")]
    impl SecretWrapperExt<V1> for Pie {
        fn wrap_secret(
            ptk: &PasetoAsymmetricPrivateKey<V1, Public>,
            wk: &PasetoSymmetricKey<V1, Local>,
            nonce: &Key<{ pie::NONCE_SIZE }>,
        ) -> String {
            let header = "k1.secret-wrap.pie.";
            pie::v1_v3::wrap(header, ptk.as_ref(), wk.as_ref(), nonce)
        }

        fn unwrap_secret<'wpk>(
            wpk: &'wpk mut [u8],
            wk: &PasetoSymmetricKey<V1, Local>,
        ) -> Result<PasetoAsymmetricPrivateKey<'wpk, V1, Public>, PasetoError> {
            let header = "k1.secret-wrap.pie.";
            pie::v1_v3::unwrap(header, wpk, wk.as_ref()).map(PasetoAsymmetricPrivateKey::from)
        }
    }

    #[cfg(feature = "v2")]
    impl SecretWrapperExt<V2> for Pie {
        fn wrap_secret(
            ptk: &PasetoAsymmetricPrivateKey<V2, Public>,
            wk: &PasetoSymmetricKey<V2, Local>,
            nonce: &Key<{ pie::NONCE_SIZE }>,
        ) -> String {
            let header = "k2.secret-wrap.pie.";
            pie::v2_v4::wrap(header, ptk.as_ref(), wk.as_ref(), nonce)
        }

        fn unwrap_secret<'wpk>(
            wpk: &'wpk mut [u8],
            wk: &PasetoSymmetricKey<V2, Local>,
        ) -> Result<PasetoAsymmetricPrivateKey<'wpk, V2, Public>, PasetoError> {
            let header = "k2.secret-wrap.pie.";
            pie::v2_v4::unwrap(header, wpk, wk.as_ref()).map(PasetoAsymmetricPrivateKey::from)
        }
    }

    // We can't support v3 because there's no way to return a type of `PasetoAsymmetricPrivateKey<'wpk, V3, Public>`

    // #[cfg(feature = "v3")]
    // impl SecretWrapperExt<V3> for Pie {
    //     fn wrap_secret(
    //         ptk: &PasetoAsymmetricPrivateKey<V3, Public>,
    //         wk: &PasetoSymmetricKey<V3, Local>,
    //         nonce: &Key<{ pie::NONCE_SIZE }>,
    //     ) -> String {
    //         let header = "k3.secret-wrap.pie.";
    //         pie::v1_v3::wrap(header, ptk.as_ref(), wk.as_ref(), nonce)
    //     }

    //     fn unwrap_secret<'wpk>(
    //         wpk: &'wpk mut [u8],
    //         wk: &PasetoSymmetricKey<V3, Local>,
    //     ) -> Result<PasetoAsymmetricPrivateKey<'wpk, V3, Public>, PasetoError> {
    //         let header = "k3.secret-wrap.pie.";
    //         pie::v1_v3::unwrap(header, wpk, wk.as_ref())
    //             .and_then(|k| {
    //                 if k.len() != 48 {
    //                     Err(PasetoError::IncorrectSize)
    //                 } else {
    //                     Ok(k)
    //                 }
    //             })
    //             .map(Key::from)
    //             .map(PasetoAsymmetricPrivateKey::from)
    //     }
    // }

    #[cfg(feature = "v4")]
    impl SecretWrapperExt<V4> for Pie {
        fn wrap_secret(
            ptk: &PasetoAsymmetricPrivateKey<V4, Public>,
            wk: &PasetoSymmetricKey<V4, Local>,
            nonce: &Key<{ pie::NONCE_SIZE }>,
        ) -> String {
            let header = "k4.secret-wrap.pie.";
            pie::v2_v4::wrap(header, ptk.as_ref(), wk.as_ref(), nonce)
        }

        fn unwrap_secret<'wpk>(
            wpk: &'wpk mut [u8],
            wk: &PasetoSymmetricKey<V4, Local>,
        ) -> Result<PasetoAsymmetricPrivateKey<'wpk, V4, Public>, PasetoError> {
            let header = "k4.secret-wrap.pie.";
            pie::v2_v4::unwrap(header, wpk, wk.as_ref()).map(PasetoAsymmetricPrivateKey::from)
        }
    }
}
#[cfg(feature = "public")]
pub use public::SecretWrapperExt;

mod pie {
    #[cfg(any(feature = "v2", feature = "v4"))]
    pub(crate) mod v2_v4 {
        use blake2::Blake2bMac;
        use chacha20::XChaCha20;
        use generic_array::typenum::{U32, U56};
        use rusty_paseto::core::{Key, PasetoError};

        /// Implementation of <https://github.com/paseto-standard/paserk/blob/master/operations/Wrap/pie.md#v2v4-encryption>
        pub(crate) fn wrap(
            h: &str,
            ptk: &[u8],
            wk: &[u8],
            n: &Key<{ super::NONCE_SIZE }>,
        ) -> String {
            super::generic::wrap::<Blake2bMac<U56>, Blake2bMac<U32>, XChaCha20>(h, ptk, wk, n)
        }

        /// Implementation of <https://github.com/paseto-standard/paserk/blob/master/operations/Wrap/pie.md#v2v4-decryption>
        pub(crate) fn unwrap<'a>(
            h: &str,
            wpk: &'a mut [u8],
            wk: &[u8],
        ) -> Result<&'a [u8], PasetoError> {
            super::generic::unwrap::<Blake2bMac<U56>, Blake2bMac<U32>, XChaCha20>(h, wpk, wk)
        }

        #[test]
        fn round_trip() {
            use rand::rngs::OsRng;
            use rand::RngCore;

            let mut ptk = [0u8; 123];
            OsRng.fill_bytes(&mut ptk);

            let nonce = Key::try_new_random().unwrap();

            let wk = rusty_paseto::core::Key::<32>::try_new_random().unwrap();

            let mut token = wrap("header", &ptk, &*wk, &nonce).into_bytes();
            let ptk2 = unwrap("header", &mut token, &*wk).unwrap();

            assert_eq!(ptk.as_ref(), ptk2);
        }
    }

    #[cfg(any(feature = "v1", feature = "v3"))]
    pub(crate) mod v1_v3 {
        use aes::Aes256;
        use ctr::Ctr64BE;
        use hmac::Hmac;
        use rusty_paseto::core::{Key, PasetoError};
        use sha2::Sha384;

        /// Implementation of <https://github.com/paseto-standard/paserk/blob/master/operations/Wrap/pie.md#v2v4-encryption>
        pub(crate) fn wrap(
            h: &str,
            ptk: &[u8],
            wk: &[u8],
            n: &Key<{ super::NONCE_SIZE }>,
        ) -> String {
            super::generic::wrap::<Hmac<Sha384>, Hmac<Sha384>, Ctr64BE<Aes256>>(h, ptk, wk, n)
        }

        /// Implementation of <https://github.com/paseto-standard/paserk/blob/master/operations/Wrap/pie.md#v2v4-decryption>
        pub(crate) fn unwrap<'a>(
            h: &str,
            wpk: &'a mut [u8],
            wk: &[u8],
        ) -> Result<&'a [u8], PasetoError> {
            super::generic::unwrap::<Hmac<Sha384>, Hmac<Sha384>, Ctr64BE<Aes256>>(h, wpk, wk)
        }

        #[test]
        fn round_trip() {
            use rand::rngs::OsRng;
            use rand::RngCore;

            let mut ptk = [0u8; 123];
            OsRng.fill_bytes(&mut ptk);

            let nonce = Key::try_new_random().unwrap();

            let wk = rusty_paseto::core::Key::<32>::try_new_random().unwrap();

            let mut token = wrap("header", &ptk, &*wk, &nonce).into_bytes();
            let ptk2 = unwrap("header", &mut token, &*wk).unwrap();

            assert_eq!(ptk.as_ref(), ptk2);
        }
    }

    pub const NONCE_SIZE: usize = 32;

    mod generic {
        use std::io::Write;
        use std::ops::{Add, Sub};

        use base64::{write::EncoderStringWriter, URL_SAFE_NO_PAD};
        use base64ct::{Base64UrlUnpadded, Encoding};

        use cipher::Unsigned;
        use cipher::{inout::InOutBuf, Iv, Key, KeyInit, KeyIvInit, KeySizeUser, StreamCipher};
        use digest::Mac;
        use generic_array::sequence::Concat;
        use generic_array::typenum::{Sum, U2};
        use generic_array::ArrayLength;
        use generic_array::{sequence::Split, GenericArray};
        use rusty_paseto::core::PasetoError;
        use subtle::ConstantTimeEq;

        const ENC_CODE: u8 = 0x80;
        const AUTH_CODE: u8 = 0x81;

        /// Implementation of <https://github.com/paseto-standard/paserk/blob/master/operations/Wrap/pie.md#v2v4-encryption>
        pub(crate) fn wrap<D1, D2, C>(
            h: &str,
            ptk: &[u8],
            wk: &[u8],
            n: &rusty_paseto::core::Key<{ super::NONCE_SIZE }>,
        ) -> String
        where
            D1: Mac + KeyInit,
            D2: Mac + KeyInit,
            C: StreamCipher + KeyIvInit,
            D1::OutputSize: Sub<<C as KeySizeUser>::KeySize, Output = C::IvSize>,
            D2::OutputSize: Add<U2>,
            Sum<D2::OutputSize, U2>: ArrayLength<u8>,
        {
            // step 1: Enforce Algorithm Lucidity
            // asserted by the caller.

            // step 2: Generate a 256 bit (32 bytes) random nonce, n.
            // done by the caller

            // step 3: Derive the encryption key `Ek` and XChaCha nonce `n2`
            let mut derive_ek = <D1 as Mac>::new_from_slice(wk).unwrap();
            derive_ek.update(&[ENC_CODE]);
            derive_ek.update(n.as_ref());
            let (ek, n2): (Key<C>, Iv<C>) = derive_ek.finalize().into_bytes().split();

            // step 4: Derive the authentication key `Ak`
            let mut derive_ak = <D2 as Mac>::new_from_slice(wk).unwrap();
            derive_ak.update(&[AUTH_CODE]);
            derive_ak.update(n.as_ref());
            let ak = derive_ak.finalize().into_bytes();

            // step 5: Encrypt the plaintext key `ptk` with `Ek` and `n2` to obtain the wrapped key `c`
            let mut chacha = C::new(&ek, &n2);
            // a bit out of order, we stream the cipher into the MAC/base64 encoding

            // step 6: Calculate the authentication tag `t`
            let mut derive_tag = <D2 as Mac>::new_from_slice(&ak[..32]).unwrap();
            derive_tag.update(h.as_bytes());
            derive_tag.update(n.as_ref());

            // step 7: Return base64url(t || n || c)
            let mut enc = EncoderStringWriter::from(h.to_owned(), URL_SAFE_NO_PAD);
            // write temporary tag which we will fill in later
            enc.write_all(&GenericArray::<u8, D2::OutputSize>::default())
                .unwrap();
            enc.write_all(n.as_ref()).unwrap();

            for slice in ptk.chunks(64) {
                let mut c = [0; 64];
                chacha.apply_keystream_inout(InOutBuf::new(slice, &mut c[..slice.len()]).unwrap());

                derive_tag.update(&c[..slice.len()]);
                enc.write_all(&c[..slice.len()]).unwrap();
            }

            let t = derive_tag.finalize().into_bytes();

            // pad the tag with 2 extra bytes so we definitely fill a base64 quad
            let extra = GenericArray::<u8, U2>::from_slice(&n.as_ref()[..2]);
            let te = t.concat(*extra);

            // encode the tag
            let mut b64t = [0; 96];
            let b64t = Base64UrlUnpadded::encode(&te, &mut b64t).unwrap();
            let full_len = te.len() / 3 * 4;

            let mut output = enc.into_inner();
            output.replace_range(h.len()..h.len() + full_len, &b64t[..full_len]);
            output
        }

        /// Implementation of <https://github.com/paseto-standard/paserk/blob/master/operations/Wrap/pie.md#v2v4-decryption>
        pub(crate) fn unwrap<'a, D1, D2, C>(
            h: &str,
            wpk: &'a mut [u8],
            wk: &[u8],
        ) -> Result<&'a [u8], PasetoError>
        where
            D1: Mac + KeyInit,
            D2: Mac + KeyInit,
            C: StreamCipher + KeyIvInit,
            GenericArray<u8, D1::OutputSize>:
                Split<u8, <C as KeySizeUser>::KeySize, First = Key<C>, Second = Iv<C>>,
        {
            if !wpk.starts_with(h.as_bytes()) {
                return Err(PasetoError::WrongHeader);
            }
            let wpk = &mut wpk[h.len()..];

            // step 1: Decode `b` from Base64url
            let len = Base64UrlUnpadded::decode_in_place(wpk)
                .map_err(|_err| PasetoError::PayloadBase64Decode {
                    source: base64::DecodeError::InvalidLength,
                })?
                .len();

            if len < 64 {
                return Err(PasetoError::IncorrectSize);
            }

            let b = &mut wpk[..len];
            let (t, b) = b.split_at_mut(<D2::OutputSize as Unsigned>::USIZE);
            let (n, c) = b.split_at_mut(super::NONCE_SIZE);

            // step 2: Derive the authentication key `Ak`
            let mut derive_ak = <D2 as Mac>::new_from_slice(wk).unwrap();
            derive_ak.update(&[AUTH_CODE]);
            derive_ak.update(n);
            let ak = derive_ak.finalize().into_bytes();

            // step 3: Recalculate the authentication tag t2
            let mut derive_tag = <D2 as Mac>::new_from_slice(&ak[..32]).unwrap();
            derive_tag.update(h.as_bytes());
            derive_tag.update(n);
            derive_tag.update(c);
            let t2 = derive_tag.finalize().into_bytes();

            // step 4: Compare t with t2 in constant-time. If it doesn't match, abort.
            if t.ct_ne(&t2).into() {
                return Err(PasetoError::InvalidSignature);
            }

            // step 5: Derive the encryption key `Ek` and XChaCha nonce `n2`
            let mut derive_ek = <D1 as Mac>::new_from_slice(wk).unwrap();
            derive_ek.update(&[ENC_CODE]);
            derive_ek.update(n);
            let (ek, n2): (Key<C>, Iv<C>) = derive_ek.finalize().into_bytes().split();

            // step 6: Decrypt the wrapped key `c` with `Ek` and `n2` to obtain the plaintext key `ptk`
            let mut chacha = C::new(&ek, &n2);
            chacha.apply_keystream_inout(InOutBuf::from(&mut *c));

            // step 7: Enforce Algorithm Lucidity
            // asserted by the caller.

            // step 8: return ptk
            Ok(c)
        }
    }
}
