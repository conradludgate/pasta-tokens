//! PBKD (Password-Based Key Wrapping).
//! Derive a unique encryption key from a password, then use it to wrap the key.
//!
//! <https://github.com/paseto-standard/paserk/blob/master/operations/PBKW.md>

use cipher::{KeyInit, KeyIvInit, StreamCipher};
use digest::{Digest, Mac};
use generic_array::{
    sequence::{Concat, Split},
    typenum::U32,
    ArrayLength, GenericArray,
};
use rand::{CryptoRng, RngCore};

use rand::rngs::OsRng;
use rusty_paseto::core::PasetoError;
#[cfg(feature = "v3")]
use rusty_paseto::core::V3;
#[cfg(feature = "v4")]
use rusty_paseto::core::V4;
use subtle::ConstantTimeEq;

use crate::{Key, KeyType, Local, Version};

// #[cfg(feature = "local")]
// mod local {
//     use super::*;

//     /// Key ID encodings <https://github.com/paseto-standard/paserk/blob/master/operations/ID.md>
//     pub trait LocalPwWrap<Version> {
//         /// Wrap the key using the given password
//         fn local_pw_wrap(&self, pw: &[u8]) -> String;

//         fn local_pw_unwrap(
//             wpk: &str,
//             pw: &[u8],
//         ) -> Result<PasetoSymmetricKey<V1, Local>, PasetoError>;
//     }

//     impl LocalPwWrap<V1> for PasetoSymmetricKey<V1, Local> {
//         fn local_pw_wrap(&self, pw: &[u8]) -> String {
//             v1_v3::wrap("k1.local-pw.", self.as_ref(), pw)
//         }

//         fn local_pw_unwrap(
//             wpk: &str,
//             pw: &[u8],
//         ) -> Result<PasetoSymmetricKey<V1, Local>, PasetoError> {
//             let mut output = [0; 196];
//             output.copy_from_slice(wpk.as_bytes());
//             let ptk = v1_v3::unwrap("k1.local-pw.", &mut output, pw)?;
//             Ok(Key::from(ptk).into())
//         }
//     }
//     impl LocalPwWrap<V3> for PasetoSymmetricKey<V3, Local> {
//         fn local_pw_wrap(&self, pw: &[u8]) -> String {
//             v1_v3::wrap("k3.local-pw.", self.as_ref(), pw)
//         }

//         fn local_pw_unwrap(
//             wpk: &str,
//             pw: &[u8],
//         ) -> Result<PasetoSymmetricKey<V1, Local>, PasetoError> {
//             let mut output = [0; 196];
//             output.copy_from_slice(wpk.as_bytes());
//             let ptk = v1_v3::unwrap("k3.local-pw.", &mut output, pw)?;
//             Ok(Key::from(ptk).into())
//         }
//     }
// }

// mod v1_v3 {
//     use std::io::Write;

//     use aes::Aes256;
//     use base64::{write::EncoderStringWriter, URL_SAFE_NO_PAD};
//     use base64ct::{Base64UrlUnpadded, Encoding};

//     use cipher::{inout::InOutBuf, Key, KeyIvInit, StreamCipher};
//     use ctr::Ctr64BE;
//     use digest::Mac;
//     use generic_array::sequence::Split;
//     use hmac::Hmac;
//     use rusty_paseto::core::PasetoError;
//     use sha2::{Digest, Sha384};
//     use subtle::ConstantTimeEq;

//     const ENC_CODE: u8 = 0xFF;
//     const AUTH_CODE: u8 = 0xFE;

//     /// Implementation of <https://github.com/paseto-standard/paserk/blob/master/operations/PBKW.md#v1v3-encryption>
//     pub(crate) fn wrap(h: &str, ptk: &[u8], pw: &[u8]) -> String {
//         let mut enc = EncoderStringWriter::from(h.to_owned(), URL_SAFE_NO_PAD);

//         // step 1: Generate a random 256-bit (32-byte) salt `s`
//         let s = rusty_paseto::core::Key::<32>::try_new_random().unwrap();

//         // step 2: Derive the 256-bit (32 byte) pre-key k from the password and salt
//         let i = 100_000;
//         let k = pbkdf2::pbkdf2_hmac_array::<Sha384, 32>(pw, &*s, i);

//         // step 3: Derive the encryption key (Ek), truncated to the 32 most significant bytes.
//         let (ek, _): (Key<Ctr64BE<Aes256>>, _) = Sha384::new()
//             .chain_update([ENC_CODE])
//             .chain_update(k)
//             .finalize()
//             .split();

//         // step 4: Derive the authentication key (Ak).
//         let ak = Sha384::new()
//             .chain_update([AUTH_CODE])
//             .chain_update(k)
//             .finalize();

//         // step 5: Generate a random 128-bit nonce `n`
//         let n = rusty_paseto::core::Key::<16>::try_new_random().unwrap();

//         let mut derive_tag = <Hmac<Sha384> as Mac>::new_from_slice(&ak)
//             .unwrap()
//             .chain_update(h.as_bytes())
//             .chain_update(*s)
//             .chain_update(i.to_be_bytes())
//             .chain_update(*n);

//         enc.write_all(&*s).unwrap();
//         enc.write_all(&i.to_be_bytes()).unwrap();
//         enc.write_all(&*n).unwrap();

//         // step 6: Encrypt the plaintext key ptk with Ek and n to obtain the encrypted data key edk
//         let mut cipher = Ctr64BE::<Aes256>::new(&ek, (&*n).into());

//         let mut chunks = ptk.chunks_exact(64);
//         let mut c = [0; 64];
//         for slice in chunks.by_ref() {
//             cipher.apply_keystream_inout(InOutBuf::new(slice, &mut c).unwrap());

//             derive_tag.update(&c);
//             enc.write_all(&c).unwrap();
//         }
//         let r = chunks.remainder();
//         if !r.is_empty() {
//             cipher.apply_keystream_inout(InOutBuf::new(r, &mut c[..r.len()]).unwrap());

//             derive_tag.update(&c[..r.len()]);
//             enc.write_all(&c[..r.len()]).unwrap();
//         }

//         // step 7: Calculate the authentication tag t over h, s, i, n, and edk.
//         let t = derive_tag.finalize().into_bytes();

//         enc.write_all(&t).unwrap();
//         enc.into_inner()
//     }

//     /// Implementation of <https://github.com/paseto-standard/paserk/blob/master/operations/PBKW.md#v1v3-decryption>
//     pub(crate) fn unwrap<'a>(
//         h: &str,
//         wpk: &'a mut [u8],
//         pw: &[u8],
//     ) -> Result<&'a [u8], PasetoError> {
//         // step 1: Assert that the header h is correct for the expected version of the wrapped key.
//         if !wpk.starts_with(h.as_bytes()) {
//             return Err(PasetoError::WrongHeader);
//         }
//         let wpk = &mut wpk[h.len()..];

//         // step 1: Decode `b` from Base64url
//         let len = Base64UrlUnpadded::decode_in_place(wpk)
//             .map_err(|_err| PasetoError::PayloadBase64Decode {
//                 source: base64::DecodeError::InvalidLength,
//             })?
//             .len();

//         if len < 100 {
//             return Err(PasetoError::IncorrectSize);
//         }

//         let b = &mut wpk[..len];
//         let (s, b) = b.split_at_mut(32);
//         let (i, b) = b.split_at_mut(4);
//         let (n, b) = b.split_at_mut(16);
//         let (edk, t) = b.split_at_mut(b.len() - 48);

//         let iterations = u32::from_be_bytes(i.try_into().unwrap());

//         let k = pbkdf2::pbkdf2_hmac_array::<Sha384, 32>(pw, &*s, iterations);

//         let ak = Sha384::new()
//             .chain_update([AUTH_CODE])
//             .chain_update(k)
//             .finalize();

//         let t2 = <Hmac<Sha384> as Mac>::new_from_slice(&ak)
//             .unwrap()
//             .chain_update(h.as_bytes())
//             .chain_update(s)
//             .chain_update(i)
//             .chain_update(&n)
//             .chain_update(&edk)
//             .finalize()
//             .into_bytes();

//         if t.ct_ne(&t2).into() {
//             return Err(PasetoError::InvalidSignature);
//         }

//         let (ek, _): (Key<Ctr64BE<Aes256>>, _) = Sha384::new()
//             .chain_update([ENC_CODE])
//             .chain_update(k)
//             .finalize()
//             .split();

//         Ctr64BE::<Aes256>::new(&ek, (&*n).into()).apply_keystream_inout(InOutBuf::from(&mut *edk));

//         Ok(edk)
//     }
// }

pub struct PwWrappedKey<V: PwVersion, K: PwWrapType<V>> {
    salt: GenericArray<u8, V::SaltLen>,
    state: V::KdfState,
    nonce: cipher::Iv<V::Cipher>,
    edk: GenericArray<u8, K::KeyLen>,
    tag: digest::Output<V::TagMac>,
}

impl<V: PwVersion, K: PwWrapType<V>> Key<V, K> {
    pub fn pw_wrap_with_rng(
        &self,
        password: &[u8],
        settings: V::KdfState,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> PwWrappedKey<V, K> {
        let mut salt = GenericArray::<u8, V::SaltLen>::default();
        rng.fill_bytes(&mut salt);

        let k = V::kdf(password, &salt, &settings);

        let ek = <V::KeyHash as Digest>::new()
            .chain_update([0xff])
            .chain_update(k)
            .finalize();
        let ek = V::split_ek(ek);

        let ak = <V::KeyHash as Digest>::new()
            .chain_update([0xfe])
            .chain_update(k)
            .finalize();

        let mut n = cipher::Iv::<V::Cipher>::default();
        rng.fill_bytes(&mut n);

        let mut edk = GenericArray::<u8, K::KeyLen>::default();
        <V::Cipher as KeyIvInit>::new(&ek, &n)
            .apply_keystream_b2b(self.as_ref(), &mut edk)
            .unwrap();

        let tag = <V::TagMac as Mac>::new_from_slice(&ak)
            .unwrap()
            .chain_update(V::KEY_HEADER)
            .chain_update(K::WRAP_HEADER)
            .chain_update(&salt)
            .chain_update(V::encode_state(&settings))
            .chain_update(&n)
            .chain_update(&edk)
            .finalize()
            .into_bytes();

        PwWrappedKey {
            salt,
            state: settings,
            nonce: n,
            edk,
            tag,
        }
    }
    pub fn pw_wrap(&self, password: &[u8], settings: V::KdfState) -> PwWrappedKey<V, K> {
        self.pw_wrap_with_rng(password, settings, &mut OsRng)
    }
}

impl<V: PwVersion, K: PwWrapType<V>> PwWrappedKey<V, K> {
    pub fn unwrap(mut self, password: &[u8]) -> Result<Key<V, K>, PasetoError> {
        let k = V::kdf(password, &self.salt, &self.state);

        let ak = <V::KeyHash as Digest>::new()
            .chain_update([0xfe])
            .chain_update(k)
            .finalize();

        let tag = <V::TagMac as Mac>::new_from_slice(&ak)
            .unwrap()
            .chain_update(V::KEY_HEADER)
            .chain_update(K::WRAP_HEADER)
            .chain_update(&self.salt)
            .chain_update(V::encode_state(&self.state))
            .chain_update(&self.nonce)
            .chain_update(&self.edk)
            .finalize()
            .into_bytes();

        // step 4: Compare t with t2 in constant-time. If it doesn't match, abort.
        if tag.ct_ne(&self.tag).into() {
            return Err(PasetoError::InvalidSignature);
        }

        let ek = <V::KeyHash as Digest>::new()
            .chain_update([0xff])
            .chain_update(k)
            .finalize();
        let ek = V::split_ek(ek);

        <V::Cipher as KeyIvInit>::new(&ek, &self.nonce).apply_keystream(&mut self.edk);

        Ok(Key::from(self.edk))
    }
}

/// Version info for configuring password wrapping
pub trait PwVersion: Version {
    type SaltLen: ArrayLength<u8>;

    type KdfStateLen: ArrayLength<u8>;
    type KdfState;

    type Cipher: StreamCipher + KeyIvInit;

    type KeyHash: Digest;
    type TagMac: Mac + KeyInit;

    fn kdf(
        pw: &[u8],
        salt: &GenericArray<u8, Self::SaltLen>,
        state: &Self::KdfState,
    ) -> GenericArray<u8, U32>;

    fn split_ek(ek: digest::Output<Self::KeyHash>) -> cipher::Key<Self::Cipher>;
    fn encode_state(s: &Self::KdfState) -> GenericArray<u8, Self::KdfStateLen>;
}

pub struct Pbkdf2State {
    /// Defaults to 100,000 according to the PASERK PBKW specifications.
    /// Password hashing recommends 600,000 iterations, but we're not directly storing the output
    /// of this computation
    pub iterations: u32,
}

impl Default for Pbkdf2State {
    fn default() -> Self {
        Self {
            iterations: 100_000,
        }
    }
}

#[cfg(feature = "v3")]
impl PwVersion for V3 {
    type Cipher = ctr::Ctr64BE<aes::Aes256>;
    type KeyHash = sha2::Sha384;
    type TagMac = hmac::Hmac<sha2::Sha384>;

    type SaltLen = generic_array::typenum::U32;

    type KdfStateLen = generic_array::typenum::U4;
    type KdfState = Pbkdf2State;

    fn kdf(
        pw: &[u8],
        salt: &GenericArray<u8, Self::SaltLen>,
        state: &Self::KdfState,
    ) -> GenericArray<u8, U32> {
        pbkdf2::pbkdf2_hmac_array::<sha2::Sha384, 32>(pw, salt.as_slice(), state.iterations).into()
    }

    fn split_ek(ek: digest::Output<Self::KeyHash>) -> cipher::Key<Self::Cipher> {
        let (ek, _) = ek.split();
        ek
    }

    fn encode_state(s: &Self::KdfState) -> GenericArray<u8, Self::KdfStateLen> {
        s.iterations.to_be_bytes().into()
    }
}

pub struct Argon2State {
    /// Defaults to 64 MiB
    pub mem: u32,
    /// Defaults to 2
    pub time: u32,
    /// Defaults to 1
    pub para: u32,
}

impl Default for Argon2State {
    fn default() -> Self {
        Self {
            // 64 MiB in KiB
            mem: 0x1_0000,
            time: 2,
            para: 1,
        }
    }
}

#[cfg(feature = "v4")]
impl PwVersion for V4 {
    type Cipher = chacha20::XChaCha20;
    type KeyHash = blake2::Blake2b<U32>;
    type TagMac = blake2::Blake2bMac<U32>;

    type SaltLen = generic_array::typenum::U16;

    type KdfStateLen = generic_array::typenum::U16;
    type KdfState = Argon2State;

    fn kdf(
        pw: &[u8],
        salt: &GenericArray<u8, Self::SaltLen>,
        state: &Self::KdfState,
    ) -> GenericArray<u8, U32> {
        let mut out = GenericArray::<u8, U32>::default();
        argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(state.mem, state.time, state.para, Some(32)).unwrap(),
        )
        .hash_password_into(pw, salt.as_slice(), &mut out)
        .unwrap();
        out
    }

    fn split_ek(ek: digest::Output<Self::KeyHash>) -> cipher::Key<Self::Cipher> {
        ek
    }

    fn encode_state(s: &Self::KdfState) -> GenericArray<u8, Self::KdfStateLen> {
        GenericArray::<u8, generic_array::typenum::U4>::default()
            .concat(s.mem.to_be_bytes().into())
            .concat(s.time.to_be_bytes().into())
            .concat(s.para.to_be_bytes().into())
    }
}

/// Key wrap information (`local`/`secret`)
pub trait PwWrapType<V: PwVersion>: KeyType<V> {
    const WRAP_HEADER: &'static str;

    type TotalLen: ArrayLength<u8>;
    #[allow(clippy::type_complexity)]
    fn split_total(
        total: GenericArray<u8, Self::TotalLen>,
    ) -> (
        GenericArray<u8, V::SaltLen>,
        V::KdfState,
        cipher::Iv<V::Cipher>,
        GenericArray<u8, Self::KeyLen>,
        digest::Output<V::TagMac>,
    );
    fn into_total(
        salt: &GenericArray<u8, V::SaltLen>,
        state: &V::KdfState,
        nonce: &cipher::Iv<V::Cipher>,
        edk: &GenericArray<u8, Self::KeyLen>,
        tag: &digest::Output<V::TagMac>,
    ) -> GenericArray<u8, Self::TotalLen>;
}

#[cfg(feature = "v3")]
impl PwWrapType<V3> for Local {
    const WRAP_HEADER: &'static str = "local-pw.";

    type TotalLen = generic_array::typenum::U132;
    fn split_total(
        total: GenericArray<u8, Self::TotalLen>,
    ) -> (
        GenericArray<u8, <V3 as PwVersion>::SaltLen>,
        <V3 as PwVersion>::KdfState,
        cipher::Iv<<V3 as PwVersion>::Cipher>,
        GenericArray<u8, Self::KeyLen>,
        digest::Output<<V3 as PwVersion>::TagMac>,
    ) {
        let (s, b) = total.split();
        let (i, b) = b.split();
        let (n, b) = b.split();
        let (edk, t) = b.split();

        let i = u32::from_be_bytes(i.into());

        (s, Pbkdf2State { iterations: i }, n, edk, t)
    }
    fn into_total(
        salt: &GenericArray<u8, <V3 as PwVersion>::SaltLen>,
        state: &<V3 as PwVersion>::KdfState,
        nonce: &cipher::Iv<<V3 as PwVersion>::Cipher>,
        edk: &GenericArray<u8, Self::KeyLen>,
        tag: &digest::Output<<V3 as PwVersion>::TagMac>,
    ) -> GenericArray<u8, Self::TotalLen> {
        let i = state.iterations.to_be_bytes();
        salt.concat(i.into())
            .concat(*nonce)
            .concat(*edk)
            .concat(*tag)
    }
}

// #[cfg(feature = "v3")]
// impl PwWrapType<V3> for Secret {
//     const WRAP_HEADER: &'static str = "secret-wrap.";

//     // 32 + 48 + 48 = 128
//     type TotalLen = generic_array::typenum::U128;
//     fn split_total(
//         total: GenericArray<u8, Self::TotalLen>,
//     ) -> (
//         digest::Output<<V3 as PwVersion>::TagMac>,
//         GenericArray<u8, U32>,
//         GenericArray<u8, Self::KeyLen>,
//     ) {
//         let (tag, rest) = total.split();
//         let (nonce, c) = rest.split();
//         (tag, nonce, c)
//     }
//     fn into_total(
//         tag: &digest::Output<<V3 as PwVersion>::TagMac>,
//         nonce: &GenericArray<u8, U32>,
//         wrapped_key: &GenericArray<u8, Self::KeyLen>,
//     ) -> GenericArray<u8, Self::TotalLen> {
//         tag.concat(*nonce).concat(*wrapped_key)
//     }
// }

#[cfg(feature = "v4")]
impl PwWrapType<V4> for Local {
    const WRAP_HEADER: &'static str = "local-pw.";

    type TotalLen = generic_array::typenum::U120;
    fn split_total(
        total: GenericArray<u8, Self::TotalLen>,
    ) -> (
        GenericArray<u8, <V4 as PwVersion>::SaltLen>,
        <V4 as PwVersion>::KdfState,
        cipher::Iv<<V4 as PwVersion>::Cipher>,
        GenericArray<u8, Self::KeyLen>,
        digest::Output<<V4 as PwVersion>::TagMac>,
    ) {
        let (s, b) = total.split();
        let (state, b) = b.split();
        let (n, b) = b.split();
        let (edk, t) = b.split();

        let state: GenericArray<u8, generic_array::typenum::U16> = state;
        let (mem1, b) = state.split();
        let (mem2, b) = b.split();
        let (time, para) = b.split();

        let _mem1: GenericArray<u8, generic_array::typenum::U4> = mem1;
        let mem = u32::from_be_bytes(mem2.into());
        let time = u32::from_be_bytes(time.into());
        let para = u32::from_be_bytes(para.into());

        (s, Argon2State { mem, time, para }, n, edk, t)
    }
    fn into_total(
        salt: &GenericArray<u8, <V4 as PwVersion>::SaltLen>,
        state: &<V4 as PwVersion>::KdfState,
        nonce: &cipher::Iv<<V4 as PwVersion>::Cipher>,
        edk: &GenericArray<u8, Self::KeyLen>,
        tag: &digest::Output<<V4 as PwVersion>::TagMac>,
    ) -> GenericArray<u8, Self::TotalLen> {
        let mem = state.mem.to_be_bytes();
        let time = state.time.to_be_bytes();
        let para = state.para.to_be_bytes();
        salt.concat([0, 0, 0, 0].into())
            .concat(mem.into())
            .concat(time.into())
            .concat(para.into())
            .concat(*nonce)
            .concat(*edk)
            .concat(*tag)
    }
}

// #[cfg(feature = "v4")]
// impl PwWrapType<V4> for Secret {
//     const WRAP_HEADER: &'static str = "secret-wrap.";

//     // 32 + 32 + 64 = 128
//     type TotalLen = generic_array::typenum::U128;
//     fn split_total(
//         total: GenericArray<u8, Self::TotalLen>,
//     ) -> (
//         digest::Output<<V4 as PwVersion>::TagMac>,
//         GenericArray<u8, U32>,
//         GenericArray<u8, Self::KeyLen>,
//     ) {
//         let (tag, rest) = total.split();
//         let (nonce, c) = rest.split();
//         (tag, nonce, c)
//     }
//     fn into_total(
//         tag: &digest::Output<<V4 as PwVersion>::TagMac>,
//         nonce: &GenericArray<u8, U32>,
//         wrapped_key: &GenericArray<u8, Self::KeyLen>,
//     ) -> GenericArray<u8, Self::TotalLen> {
//         tag.concat(*nonce).concat(*wrapped_key)
//     }
// }
