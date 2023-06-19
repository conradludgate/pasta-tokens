//! PBKD (Password-Based Key Wrapping).
//! Derive a unique encryption key from a password, then use it to wrap the key.
//!
//! <https://github.com/paseto-standard/paserk/blob/master/operations/PBKW.md>

use rusty_paseto::core::{Key, Local, PasetoError, PasetoSymmetricKey};

#[cfg(feature = "v1")]
use rusty_paseto::core::V1;
#[cfg(feature = "v2")]
use rusty_paseto::core::V2;
#[cfg(feature = "v3")]
use rusty_paseto::core::V3;
#[cfg(feature = "v4")]
use rusty_paseto::core::V4;

#[cfg(feature = "local")]
mod local {
    use super::*;

    /// Key ID encodings <https://github.com/paseto-standard/paserk/blob/master/operations/ID.md>
    pub trait LocalPwWrap<Version> {
        /// Wrap the key using the given password
        fn local_pw_wrap(&self, pw: &[u8]) -> String;

        fn local_pw_unwrap(
            wpk: &str,
            pw: &[u8],
        ) -> Result<PasetoSymmetricKey<V1, Local>, PasetoError>;
    }

    impl LocalPwWrap<V1> for PasetoSymmetricKey<V1, Local> {
        fn local_pw_wrap(&self, pw: &[u8]) -> String {
            v1_v3::wrap("k1.local-pw.", self.as_ref(), pw)
        }

        fn local_pw_unwrap(
            wpk: &str,
            pw: &[u8],
        ) -> Result<PasetoSymmetricKey<V1, Local>, PasetoError> {
            let mut output = [0; 196];
            output.copy_from_slice(wpk.as_bytes());
            let ptk = v1_v3::unwrap("k1.local-pw.", &mut output, pw)?;
            Ok(Key::from(ptk).into())
        }
    }
    impl LocalPwWrap<V3> for PasetoSymmetricKey<V3, Local> {
        fn local_pw_wrap(&self, pw: &[u8]) -> String {
            v1_v3::wrap("k3.local-pw.", self.as_ref(), pw)
        }

        fn local_pw_unwrap(
            wpk: &str,
            pw: &[u8],
        ) -> Result<PasetoSymmetricKey<V1, Local>, PasetoError> {
            let mut output = [0; 196];
            output.copy_from_slice(wpk.as_bytes());
            let ptk = v1_v3::unwrap("k3.local-pw.", &mut output, pw)?;
            Ok(Key::from(ptk).into())
        }
    }
}

mod v1_v3 {
    use std::io::Write;

    use aes::Aes256;
    use base64::{write::EncoderStringWriter, URL_SAFE_NO_PAD};
    use base64ct::{Base64UrlUnpadded, Encoding};

    use cipher::{inout::InOutBuf, Key, KeyIvInit, StreamCipher};
    use ctr::Ctr64BE;
    use digest::Mac;
    use generic_array::sequence::Split;
    use hmac::Hmac;
    use rusty_paseto::core::PasetoError;
    use sha2::{Digest, Sha384};
    use subtle::ConstantTimeEq;

    const ENC_CODE: u8 = 0xFF;
    const AUTH_CODE: u8 = 0xFE;

    /// Implementation of <https://github.com/paseto-standard/paserk/blob/master/operations/PBKW.md#v1v3-encryption>
    pub(crate) fn wrap(h: &str, ptk: &[u8], pw: &[u8]) -> String {
        let mut enc = EncoderStringWriter::from(h.to_owned(), URL_SAFE_NO_PAD);

        // step 1: Generate a random 256-bit (32-byte) salt `s`
        let s = rusty_paseto::core::Key::<32>::try_new_random().unwrap();

        // step 2: Derive the 256-bit (32 byte) pre-key k from the password and salt
        let i = 100_000;
        let k = pbkdf2::pbkdf2_hmac_array::<Sha384, 32>(pw, &*s, i);

        // step 3: Derive the encryption key (Ek), truncated to the 32 most significant bytes.
        let (ek, _): (Key<Ctr64BE<Aes256>>, _) = Sha384::new()
            .chain_update([ENC_CODE])
            .chain_update(k)
            .finalize()
            .split();

        // step 4: Derive the authentication key (Ak).
        let ak = Sha384::new()
            .chain_update([AUTH_CODE])
            .chain_update(k)
            .finalize();

        // step 5: Generate a random 128-bit nonce `n`
        let n = rusty_paseto::core::Key::<16>::try_new_random().unwrap();

        let mut derive_tag = <Hmac<Sha384> as Mac>::new_from_slice(&ak)
            .unwrap()
            .chain_update(h.as_bytes())
            .chain_update(*s)
            .chain_update(i.to_be_bytes())
            .chain_update(*n);

        enc.write_all(&*s).unwrap();
        enc.write_all(&i.to_be_bytes()).unwrap();
        enc.write_all(&*n).unwrap();

        // step 6: Encrypt the plaintext key ptk with Ek and n to obtain the encrypted data key edk
        let mut cipher = Ctr64BE::<Aes256>::new(&ek, (&*n).into());

        let mut chunks = ptk.chunks_exact(64);
        let mut c = [0; 64];
        for slice in chunks.by_ref() {
            cipher.apply_keystream_inout(InOutBuf::new(slice, &mut c).unwrap());

            derive_tag.update(&c);
            enc.write_all(&c).unwrap();
        }
        let r = chunks.remainder();
        if !r.is_empty() {
            cipher.apply_keystream_inout(InOutBuf::new(r, &mut c[..r.len()]).unwrap());

            derive_tag.update(&c[..r.len()]);
            enc.write_all(&c[..r.len()]).unwrap();
        }

        // step 7: Calculate the authentication tag t over h, s, i, n, and edk.
        let t = derive_tag.finalize().into_bytes();

        enc.write_all(&t).unwrap();
        enc.into_inner()
    }

    /// Implementation of <https://github.com/paseto-standard/paserk/blob/master/operations/PBKW.md#v1v3-decryption>
    pub(crate) fn unwrap<'a>(
        h: &str,
        wpk: &'a mut [u8],
        pw: &[u8],
    ) -> Result<&'a [u8], PasetoError> {
        // step 1: Assert that the header h is correct for the expected version of the wrapped key.
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

        if len < 100 {
            return Err(PasetoError::IncorrectSize);
        }

        let b = &mut wpk[..len];
        let (s, b) = b.split_at_mut(32);
        let (i, b) = b.split_at_mut(4);
        let (n, b) = b.split_at_mut(16);
        let (edk, t) = b.split_at_mut(b.len() - 48);

        let iterations = u32::from_be_bytes(i.try_into().unwrap());

        let k = pbkdf2::pbkdf2_hmac_array::<Sha384, 32>(pw, &*s, iterations);

        let ak = Sha384::new()
            .chain_update([AUTH_CODE])
            .chain_update(k)
            .finalize();

        let t2 = <Hmac<Sha384> as Mac>::new_from_slice(&ak)
            .unwrap()
            .chain_update(h.as_bytes())
            .chain_update(s)
            .chain_update(i)
            .chain_update(&n)
            .chain_update(&edk)
            .finalize()
            .into_bytes();

        if t.ct_ne(&t2).into() {
            return Err(PasetoError::InvalidSignature);
        }

        let (ek, _): (Key<Ctr64BE<Aes256>>, _) = Sha384::new()
            .chain_update([ENC_CODE])
            .chain_update(k)
            .finalize()
            .split();

        Ctr64BE::<Aes256>::new(&ek, (&*n).into()).apply_keystream_inout(InOutBuf::from(&mut *edk));

        Ok(edk)
    }
}
