//! PBKD (Password-Based Key Wrapping).
//! Derive a unique encryption key from a password, then use it to wrap the key.
//!
//! <https://github.com/paseto-standard/paserk/blob/master/operations/PBKW.md>

use std::{fmt, str::FromStr};

use base64::URL_SAFE_NO_PAD;
use cipher::{KeyInit, KeyIvInit, StreamCipher, Unsigned};
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

use crate::{key::write_b64, Key, KeyType, Local, Secret, Version};

/// Password wrapped keys
/// <https://github.com/paseto-standard/paserk/blob/master/operations/PBKW.md>
///
/// # Local password wrapping
/// ```
/// use rusty_paserk::{PwWrappedKey, Key, Local, V4, Argon2State};
///
/// let password = "hunter2";
///
/// let local_key = Key::<V4, Local>::new_random();
/// let wrap_state = Argon2State::default();
///
/// let wrapped_local = local_key.pw_wrap(password.as_bytes(), wrap_state).to_string();
/// // => "k4.local-pw.Ibx3cOeBAsBEJsjMFXBgYgAAAAAEAAAAAAAAAgAAAAG2RRITciuBSfCWR3e324EuatP9XsKkyLcTgeZPxg6N-JhlpV2GAqvPQjRK89QnepimbYTaNitInOj45ksyyNfAEjRgjuVYUZo7vrI6unVfvtDehIc8VvgR"
///
/// let wrapped_local: PwWrappedKey<V4, Local> = wrapped_local.parse().unwrap();
/// let local_key2 = wrapped_local.unwrap(password.as_bytes()).unwrap();
/// assert_eq!(local_key, local_key2);
/// ```
///
/// # Secret password wrapping
/// ```
/// use rusty_paserk::{PwWrappedKey, Key, Local, Secret, V4, Argon2State};
///
/// let password = "hunter2";
///
/// let secret_key = Key::<V4, Secret>::new_random();
/// let wrap_state = Argon2State::default();
///
/// let wrapped_secret = secret_key.pw_wrap(password.as_bytes(), wrap_state).to_string();
/// // => "k4.secret-pw.uscmLPzUoxxRfuzmY0DWcAAAAAAEAAAAAAAAAgAAAAHVNddVDnjRCc-ZmT-R-Xp7c7s4Wn1iH0dllAPFBmknEJpKGYP_aPoxVzNS_O93M0sCb68t7HjdD-jXWp-ioWe56iLoA6MlxE-SmnKear60aDwqk5fYv_EMD4Y2pV049BvDNGNN-MzR6fwW_OlyhV9omEvxmczAujM"
///
/// let wrapped_secret: PwWrappedKey<V4, Secret> = wrapped_secret.parse().unwrap();
/// let secret_key2 = wrapped_secret.unwrap(password.as_bytes()).unwrap();
/// assert_eq!(secret_key, secret_key2);
/// ```
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

    /// Password wrapped keys
    /// <https://github.com/paseto-standard/paserk/blob/master/operations/PBKW.md>
    ///
    /// # Local password wrapping
    /// ```
    /// use rusty_paserk::{PwWrappedKey, Key, Local, V4, Argon2State};
    ///
    /// let password = "hunter2";
    ///
    /// let local_key = Key::<V4, Local>::new_random();
    /// let wrap_state = Argon2State::default();
    ///
    /// let wrapped_local = local_key.pw_wrap(password.as_bytes(), wrap_state).to_string();
    /// // => "k4.local-pw.Ibx3cOeBAsBEJsjMFXBgYgAAAAAEAAAAAAAAAgAAAAG2RRITciuBSfCWR3e324EuatP9XsKkyLcTgeZPxg6N-JhlpV2GAqvPQjRK89QnepimbYTaNitInOj45ksyyNfAEjRgjuVYUZo7vrI6unVfvtDehIc8VvgR"
    ///
    /// let wrapped_local: PwWrappedKey<V4, Local> = wrapped_local.parse().unwrap();
    /// let local_key2 = wrapped_local.unwrap(password.as_bytes()).unwrap();
    /// assert_eq!(local_key, local_key2);
    /// ```
    ///
    /// # Secret password wrapping
    /// ```
    /// use rusty_paserk::{PwWrappedKey, Key, Local, Secret, V4, Argon2State};
    ///
    /// let password = "hunter2";
    ///
    /// let secret_key = Key::<V4, Secret>::new_random();
    /// let wrap_state = Argon2State::default();
    ///
    /// let wrapped_secret = secret_key.pw_wrap(password.as_bytes(), wrap_state).to_string();
    /// // => "k4.secret-pw.uscmLPzUoxxRfuzmY0DWcAAAAAAEAAAAAAAAAgAAAAHVNddVDnjRCc-ZmT-R-Xp7c7s4Wn1iH0dllAPFBmknEJpKGYP_aPoxVzNS_O93M0sCb68t7HjdD-jXWp-ioWe56iLoA6MlxE-SmnKear60aDwqk5fYv_EMD4Y2pV049BvDNGNN-MzR6fwW_OlyhV9omEvxmczAujM"
    ///
    /// let wrapped_secret: PwWrappedKey<V4, Secret> = wrapped_secret.parse().unwrap();
    /// let secret_key2 = wrapped_secret.unwrap(password.as_bytes()).unwrap();
    /// assert_eq!(secret_key, secret_key2);
    /// ```
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

impl<V: PwVersion, K: PwWrapType<V>> FromStr for PwWrappedKey<V, K> {
    type Err = PasetoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .strip_prefix(V::KEY_HEADER)
            .ok_or(PasetoError::WrongHeader)?;
        let s = s
            .strip_prefix(K::WRAP_HEADER)
            .ok_or(PasetoError::WrongHeader)?;

        let mut total = GenericArray::<u8, K::TotalLen>::default();
        let len = base64::decode_config_slice(s, URL_SAFE_NO_PAD, &mut total)?;
        if len != <K::TotalLen as Unsigned>::USIZE {
            return Err(PasetoError::PayloadBase64Decode {
                source: base64::DecodeError::InvalidLength,
            });
        }

        let (salt, state, nonce, edk, tag) = K::split_total(total);

        Ok(Self {
            salt,
            state,
            nonce,
            edk,
            tag,
        })
    }
}

impl<V: PwVersion, K: PwWrapType<V>> fmt::Display for PwWrappedKey<V, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(V::KEY_HEADER)?;
        f.write_str(K::WRAP_HEADER)?;

        let output = K::into_total(&self.salt, &self.state, &self.nonce, &self.edk, &self.tag);

        write_b64(&output, f)
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

#[derive(Debug)]
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
            // 64 MiB
            mem: 0x0400_0000,
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
            argon2::Params::new(state.mem / 1024, state.time, state.para, Some(32)).unwrap(),
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

#[cfg(feature = "v3")]
impl PwWrapType<V3> for Secret {
    const WRAP_HEADER: &'static str = "secret-pw.";

    type TotalLen = generic_array::typenum::U148;
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

#[cfg(feature = "v4")]
impl PwWrapType<V4> for Secret {
    const WRAP_HEADER: &'static str = "secret-pw.";

    type TotalLen = generic_array::typenum::U152;
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
