//! Key wrapping algorithms <https://github.com/paseto-standard/paserk/blob/master/operations/Wrap.md>

use rusty_paseto::prelude::{Key, Local, PasetoError, PasetoSymmetricKey};

// #[cfg(feature = "v1")]
// use rusty_paseto::prelude::V1;
#[cfg(feature = "v2")]
use rusty_paseto::prelude::V2;
// #[cfg(feature = "v3")]
// use rusty_paseto::prelude::V3;
#[cfg(feature = "v4")]
use rusty_paseto::prelude::V4;

/// Paragon Initiative Enterprises standard key-wrapping
/// <https://github.com/paseto-standard/paserk/blob/master/operations/Wrap/pie.md>
pub struct Pie;

#[cfg(feature = "local")]
mod local {
    use super::*;

    pub trait LocalWrapperExt<Version> {
        fn wrap_local(
            ptk: &PasetoSymmetricKey<Version, Local>,
            wk: &PasetoSymmetricKey<Version, Local>,
        ) -> String;

        fn unwrap_local(
            wpk: &mut [u8],
            wk: &PasetoSymmetricKey<Version, Local>,
        ) -> Result<PasetoSymmetricKey<Version, Local>, PasetoError>;
    }

    #[cfg(feature = "v2")]
    impl LocalWrapperExt<V2> for Pie {
        fn wrap_local(
            ptk: &PasetoSymmetricKey<V2, Local>,
            wk: &PasetoSymmetricKey<V2, Local>,
        ) -> String {
            let header = "k2.local-wrap.pie.";
            pie::v2_v4::wrap(header, ptk.as_ref(), wk.as_ref())
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

    #[cfg(feature = "v4")]
    impl LocalWrapperExt<V4> for Pie {
        fn wrap_local(
            ptk: &PasetoSymmetricKey<V4, Local>,
            wk: &PasetoSymmetricKey<V4, Local>,
        ) -> String {
            let header = "k4.local-wrap.pie.";
            pie::v2_v4::wrap(header, ptk.as_ref(), wk.as_ref())
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
    use rusty_paseto::prelude::{PasetoAsymmetricPrivateKey, Public};

    use super::*;

    pub trait SecretWrapperExt<Version> {
        fn wrap_secret(
            ptk: &PasetoAsymmetricPrivateKey<Version, Public>,
            wk: &PasetoSymmetricKey<Version, Local>,
        ) -> String;

        fn unwrap_secret<'wpk>(
            wpk: &'wpk mut [u8],
            wk: &PasetoSymmetricKey<Version, Local>,
        ) -> Result<PasetoAsymmetricPrivateKey<'wpk, Version, Public>, PasetoError>;
    }

    #[cfg(feature = "v2")]
    impl SecretWrapperExt<V2> for Pie {
        fn wrap_secret(
            ptk: &PasetoAsymmetricPrivateKey<V2, Public>,
            wk: &PasetoSymmetricKey<V2, Local>,
        ) -> String {
            let header = "k2.secret-wrap.pie.";
            pie::v2_v4::wrap(header, ptk.as_ref(), wk.as_ref())
        }

        fn unwrap_secret<'wpk>(
            wpk: &'wpk mut [u8],
            wk: &PasetoSymmetricKey<V2, Local>,
        ) -> Result<PasetoAsymmetricPrivateKey<'wpk, V2, Public>, PasetoError> {
            let header = "k2.secret-wrap.pie.";
            pie::v2_v4::unwrap(header, wpk, wk.as_ref()).map(PasetoAsymmetricPrivateKey::from)
        }
    }

    #[cfg(feature = "v4")]
    impl SecretWrapperExt<V4> for Pie {
        fn wrap_secret(
            ptk: &PasetoAsymmetricPrivateKey<V4, Public>,
            wk: &PasetoSymmetricKey<V4, Local>,
        ) -> String {
            let header = "k4.secret-wrap.pie.";
            pie::v2_v4::wrap(header, ptk.as_ref(), wk.as_ref())
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
        use std::io::Write;

        use base64::{engine::general_purpose, write::EncoderStringWriter};
        use base64ct::Base64Url;
        use base64ct::Encoding;
        use blake2::{digest::Mac, Blake2bMac};
        use chacha20::{
            cipher::{inout::InOutBuf, KeyIvInit, StreamCipher},
            XChaCha20,
        };
        use generic_array::{
            sequence::Split,
            typenum::{U24, U32, U56},
            GenericArray,
        };
        use rand::{rngs::OsRng, RngCore};
        use rusty_paseto::prelude::PasetoError;
        use subtle::ConstantTimeEq;

        /// Implementation of <https://github.com/paseto-standard/paserk/blob/master/operations/Wrap/pie.md#v2v4-encryption>
        pub(crate) fn wrap(h: &str, ptk: &[u8], wk: &[u8]) -> String {
            // step 1: Enforce Algorithm Lucidity
            // asserted by the caller.

            // step 2: Generate a 256 bit (32 bytes) random nonce, n.
            let mut n = [0u8; 32];
            OsRng.fill_bytes(&mut n);

            // step 3: Derive the encryption key `Ek` and XChaCha nonce `n2`
            let mut derive_ek = Blake2bMac::<U56>::new_from_slice(wk).unwrap();
            derive_ek.update(&[0x80]);
            derive_ek.update(&n);
            let (ek, n2): (GenericArray<u8, U32>, GenericArray<u8, U24>) =
                derive_ek.finalize().into_bytes().split();

            // step 4: Derive the authentication key `Ak`
            let mut derive_ak = Blake2bMac::<U32>::new_from_slice(wk).unwrap();
            derive_ak.update(&[0x81]);
            derive_ak.update(&n);
            let ak = derive_ak.finalize().into_bytes();

            // step 5: Encrypt the plaintext key `ptk` with `Ek` and `n2` to obtain the wrapped key `c`
            let mut c = vec![0; ptk.len()];
            let mut chacha = XChaCha20::new(&ek, &n2);
            chacha.apply_keystream_inout(InOutBuf::new(ptk, &mut c).unwrap());

            // step 6: Calculate the authentication tag `t`
            let mut derive_tag = Blake2bMac::<U32>::new_from_slice(&ak).unwrap();
            derive_tag.update(h.as_bytes());
            derive_tag.update(&n);
            derive_tag.update(&c);
            let t = derive_tag.finalize().into_bytes();

            // step 7: Return base64url(t || n || c)
            let mut enc =
                EncoderStringWriter::from_consumer(h.to_owned(), &general_purpose::URL_SAFE);
            enc.write_all(&t).unwrap();
            enc.write_all(&n).unwrap();
            enc.write_all(&c).unwrap();
            enc.into_inner()
        }

        /// Implementation of <https://github.com/paseto-standard/paserk/blob/master/operations/Wrap/pie.md#v2v4-decryption>
        pub(crate) fn unwrap<'a>(
            h: &str,
            wpk: &'a mut [u8],
            wk: &[u8],
        ) -> Result<&'a [u8], PasetoError> {
            if !wpk.starts_with(h.as_bytes()) {
                return Err(PasetoError::WrongHeader);
            }
            let wpk = &mut wpk[h.len()..];

            // step 1: Decode `b` from Base64url
            let len = Base64Url::decode_in_place(wpk)
                .map_err(|_err| PasetoError::PayloadBase64Decode {
                    source: base64_13::DecodeError::InvalidLength,
                })?
                .len();

            if len < 64 {
                return Err(PasetoError::IncorrectSize);
            }

            let b = &mut wpk[..len];
            let (t, b) = b.split_at_mut(32);
            let (n, c) = b.split_at_mut(32);

            // step 2: Derive the authentication key `Ak`
            let mut derive_ak = Blake2bMac::<U32>::new_from_slice(wk).unwrap();
            derive_ak.update(&[0x81]);
            derive_ak.update(n);
            let ak = derive_ak.finalize().into_bytes();

            // step 3: Recalculate the authentication tag t2
            let mut derive_tag = Blake2bMac::<U32>::new_from_slice(&ak).unwrap();
            derive_tag.update(h.as_bytes());
            derive_tag.update(n);
            derive_tag.update(c);
            let t2 = derive_tag.finalize().into_bytes();

            // step 4: Compare t with t2 in constant-time. If it doesn't match, abort.
            assert!(bool::from(t.ct_eq(&t2)), "invalid message tag");

            // step 5: Derive the encryption key `Ek` and XChaCha nonce `n2`
            let mut derive_ek = Blake2bMac::<U56>::new_from_slice(wk).unwrap();
            derive_ek.update(&[0x80]);
            derive_ek.update(n);
            let (ek, n2): (GenericArray<u8, U32>, GenericArray<u8, U24>) =
                derive_ek.finalize().into_bytes().split();

            // step 6: Decrypt the wrapped key `c` with `Ek` and `n2` to obtain the plaintext key `ptk`
            let mut chacha = XChaCha20::new(&ek, &n2);
            chacha.apply_keystream_inout(InOutBuf::from(&mut *c));

            // step 7: Enforce Algorithm Lucidity
            // asserted by the caller.

            // step 8: return ptk
            Ok(c)
        }

        #[test]
        fn round_trip() {
            let mut ptk = [0u8; 123];
            OsRng.fill_bytes(&mut ptk);

            let wk = rusty_paseto::core::Key::<32>::try_new_random().unwrap();

            let mut token = wrap("header", &ptk, &*wk).into_bytes();
            let ptk2 = unwrap("header", &mut token, &*wk).unwrap();

            assert_eq!(ptk.as_ref(), ptk2);
        }
    }
}
