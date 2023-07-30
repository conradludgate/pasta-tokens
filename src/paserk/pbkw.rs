//! PBKD (Password-Based Key Wrapping).
//! Derive a unique encryption key from a password, then use it to wrap the key.
//!
//! <https://github.com/paseto-standard/paserk/blob/master/operations/PBKW.md>

use std::{fmt, ops::DerefMut, str::FromStr};

use cipher::{IvSizeUser, KeyInit, KeyIvInit, StreamCipher};
use digest::{Digest, Mac, OutputSizeUser};
use generic_array::{
    sequence::{Concat, GenericSequence, Split},
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

use crate::{read_b64, write_b64, Key, KeyType, Local, Secret, Version};

/// Password wrapped keys
///
/// # Local password wrapping
/// ```
/// use rusty_paserk::{PwWrappedKey, Key, Local, V4, Argon2State};
///
/// let password = "hunter2";
///
/// let local_key = Key::<V4, Local>::new_os_random();
///
/// let wrapped_local = local_key.pw_wrap(password.as_bytes()).to_string();
/// // => "k4.local-pw.Ibx3cOeBAsBEJsjMFXBgYgAAAAAEAAAAAAAAAgAAAAG2RRITciuBSfCWR3e324EuatP9XsKkyLcTgeZPxg6N-JhlpV2GAqvPQjRK89QnepimbYTaNitInOj45ksyyNfAEjRgjuVYUZo7vrI6unVfvtDehIc8VvgR"
///
/// let wrapped_local: PwWrappedKey<V4, Local> = wrapped_local.parse().unwrap();
/// let local_key2 = wrapped_local.unwrap_key(password.as_bytes()).unwrap();
/// assert_eq!(local_key, local_key2);
/// ```
///
/// # Secret password wrapping
/// ```
/// use rusty_paserk::{PwWrappedKey, Key, Local, Secret, V4, Argon2State};
///
/// let password = "hunter2";
///
/// let secret_key = Key::<V4, Secret>::new_os_random();
///
/// let wrapped_secret = secret_key.pw_wrap(password.as_bytes()).to_string();
/// // => "k4.secret-pw.uscmLPzUoxxRfuzmY0DWcAAAAAAEAAAAAAAAAgAAAAHVNddVDnjRCc-ZmT-R-Xp7c7s4Wn1iH0dllAPFBmknEJpKGYP_aPoxVzNS_O93M0sCb68t7HjdD-jXWp-ioWe56iLoA6MlxE-SmnKear60aDwqk5fYv_EMD4Y2pV049BvDNGNN-MzR6fwW_OlyhV9omEvxmczAujM"
///
/// let wrapped_secret: PwWrappedKey<V4, Secret> = wrapped_secret.parse().unwrap();
/// let secret_key2 = wrapped_secret.unwrap_key(password.as_bytes()).unwrap();
/// assert_eq!(secret_key, secret_key2);
/// ```
pub struct PwWrappedKey<V: PwVersion, K: PwWrapType<V>> {
    salt: V::Salt,
    state: V::KdfState,
    nonce: cipher::Iv<V::Cipher>,
    edk: GenericArray<u8, K::KeyLen>,
    tag: digest::Output<V::TagMac>,
}

impl<V: PwVersion, K: PwWrapType<V>> Key<V, K> {
    /// Password wrapped keys
    ///
    /// * Use the default KDF settings
    /// * Use the OS RNG to determine a random salt
    ///
    /// # Local password wrapping
    /// ```
    /// use rusty_paserk::{PwWrappedKey, Key, Local, V4, Argon2State};
    ///
    /// let password = "hunter2";
    ///
    /// let local_key = Key::<V4, Local>::new_os_random();
    ///
    /// let wrapped_local = local_key.pw_wrap(password.as_bytes()).to_string();
    /// // => "k4.local-pw.Ibx3cOeBAsBEJsjMFXBgYgAAAAAEAAAAAAAAAgAAAAG2RRITciuBSfCWR3e324EuatP9XsKkyLcTgeZPxg6N-JhlpV2GAqvPQjRK89QnepimbYTaNitInOj45ksyyNfAEjRgjuVYUZo7vrI6unVfvtDehIc8VvgR"
    ///
    /// let wrapped_local: PwWrappedKey<V4, Local> = wrapped_local.parse().unwrap();
    /// let local_key2 = wrapped_local.unwrap_key(password.as_bytes()).unwrap();
    /// assert_eq!(local_key, local_key2);
    /// ```
    ///
    /// # Secret password wrapping
    /// ```
    /// use rusty_paserk::{PwWrappedKey, Key, Local, Secret, V4, Argon2State};
    ///
    /// let password = "hunter2";
    ///
    /// let secret_key = Key::<V4, Secret>::new_os_random();
    ///
    /// let wrapped_secret = secret_key.pw_wrap(password.as_bytes()).to_string();
    /// // => "k4.secret-pw.uscmLPzUoxxRfuzmY0DWcAAAAAAEAAAAAAAAAgAAAAHVNddVDnjRCc-ZmT-R-Xp7c7s4Wn1iH0dllAPFBmknEJpKGYP_aPoxVzNS_O93M0sCb68t7HjdD-jXWp-ioWe56iLoA6MlxE-SmnKear60aDwqk5fYv_EMD4Y2pV049BvDNGNN-MzR6fwW_OlyhV9omEvxmczAujM"
    ///
    /// let wrapped_secret: PwWrappedKey<V4, Secret> = wrapped_secret.parse().unwrap();
    /// let secret_key2 = wrapped_secret.unwrap_key(password.as_bytes()).unwrap();
    /// assert_eq!(secret_key, secret_key2);
    /// ```
    pub fn pw_wrap(&self, password: &[u8]) -> PwWrappedKey<V, K> {
        self.pw_wrap_with_settings(password, V::KdfState::default())
    }

    /// Password wrapped keys
    ///
    /// * Use the settings to configure how strong the derived key should be
    /// * Use the OS RNG to determine a random salt
    pub fn pw_wrap_with_settings(
        &self,
        password: &[u8],
        settings: V::KdfState,
    ) -> PwWrappedKey<V, K> {
        self.pw_wrap_with_settings_and_rng(password, settings, &mut OsRng)
    }

    /// Password wrapped keys
    ///
    /// * Use the settings to configure how strong the derived key should be
    /// * Use the RNG source to determine a random salt
    pub fn pw_wrap_with_settings_and_rng(
        &self,
        password: &[u8],
        settings: V::KdfState,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> PwWrappedKey<V, K> {
        let mut salt = V::Salt::default();
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
            .chain_update(&*salt)
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
}

impl<V: PwVersion, K: PwWrapType<V>> PwWrappedKey<V, K> {
    /// Unwrap the password wrapped key
    pub fn unwrap_key(mut self, password: &[u8]) -> Result<Key<V, K>, PasetoError> {
        let k = V::kdf(password, &self.salt, &self.state);

        let ak = <V::KeyHash as Digest>::new()
            .chain_update([0xfe])
            .chain_update(k)
            .finalize();

        let tag = <V::TagMac as Mac>::new_from_slice(&ak)
            .unwrap()
            .chain_update(V::KEY_HEADER)
            .chain_update(K::WRAP_HEADER)
            .chain_update(&*self.salt)
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

        Ok(Key { key: self.edk })
    }

    /// Return the password KDF settings that were used to encrypt the key.
    /// This is important to check prevent DOS attacks otherwise an attacked can
    /// send a key with arbitrary large memory and iteration counts.
    pub fn settings(&self) -> &V::KdfState {
        &self.state
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

        let total = read_b64::<K::SaltStateIvEdkTag>(s)?;

        let (salt_state_nonce_edk, tag) = total.split();
        let (salt_state_nonce, edk) = salt_state_nonce_edk.split();
        let (salt_state, nonce) = salt_state_nonce.split();
        let (salt, state) = salt_state.split();
        let state = V::decode_state(state);

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

        let output: K::SaltStateIv = self
            .salt
            .concat(V::encode_state(&self.state))
            .concat(self.nonce.clone())
            .into();

        let output = output.concat(self.edk.clone()).concat(self.tag.clone());

        write_b64(&output, f)
    }
}

#[cfg(feature = "v3")]
/// PBKDF2 parameters for V3 password wrapping
pub struct Pbkdf2State {
    /// Defaults to 100,000 according to the PASERK PBKW specifications.
    /// Password hashing recommends 600,000 iterations, but we're not directly storing the output
    /// of this computation
    pub iterations: u32,
}

#[cfg(feature = "v3")]
impl Default for Pbkdf2State {
    fn default() -> Self {
        Self {
            iterations: 100_000,
        }
    }
}

#[cfg(feature = "v4")]
/// Argon2 parameters for V4 password wrapping
pub struct Argon2State {
    /// Defaults to 64 MiB
    pub mem: u32,
    /// Defaults to 2
    pub time: u32,
    /// Defaults to 1
    pub para: u32,
}

#[cfg(feature = "v4")]
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

/// Version info for configuring password wrapping
pub trait PwVersion: Version {
    /// The settings that the KDF function uses
    type KdfState: Default;

    #[doc(hidden)]
    type KdfStateLen: ArrayLength<u8>;
    #[doc(hidden)]
    type Cipher: StreamCipher + KeyIvInit;
    #[doc(hidden)]
    type KeyHash: Digest;
    #[doc(hidden)]
    type TagMac: Mac + KeyInit;

    #[doc(hidden)]
    type Salt: Concat<
            u8,
            Self::KdfStateLen,
            Rest = GenericArray<u8, Self::KdfStateLen>,
            Output = Self::SaltState,
        > + DerefMut<Target = [u8]>
        + Copy
        + Default;

    #[doc(hidden)]
    type SaltState: Split<
            u8,
            <Self::Salt as GenericSequence<u8>>::Length,
            First = Self::Salt,
            Second = GenericArray<u8, Self::KdfStateLen>,
        > + Concat<
            u8,
            <Self::Cipher as IvSizeUser>::IvSize,
            Rest = cipher::Iv<Self::Cipher>,
            Output = Self::SaltStateIv,
        >;

    #[doc(hidden)]
    type SaltStateIv: Split<
        u8,
        <Self::SaltState as GenericSequence<u8>>::Length,
        First = Self::SaltState,
        Second = cipher::Iv<Self::Cipher>,
    >;

    #[doc(hidden)]
    fn kdf(pw: &[u8], salt: &Self::Salt, state: &Self::KdfState) -> GenericArray<u8, U32>;

    #[doc(hidden)]
    fn split_ek(ek: digest::Output<Self::KeyHash>) -> cipher::Key<Self::Cipher>;

    #[doc(hidden)]
    fn encode_state(s: &Self::KdfState) -> GenericArray<u8, Self::KdfStateLen>;

    #[doc(hidden)]
    fn decode_state(s: GenericArray<u8, Self::KdfStateLen>) -> Self::KdfState;
}

/// Key wrapping type. Can be either `local-pw.` or `secret-pw.`
pub trait PwType {
    /// The type of password wrapped key
    const WRAP_HEADER: &'static str;
}

impl PwType for Local {
    const WRAP_HEADER: &'static str = "local-pw.";
}

impl PwType for Secret {
    const WRAP_HEADER: &'static str = "secret-pw.";
}

/// Helper trait for configuring the key wrapping
pub trait PwWrapType<V: PwVersion>: KeyType<V> + PwType {
    #[doc(hidden)]
    type SaltStateIv: From<V::SaltStateIv>
        + Concat<
            u8,
            Self::KeyLen,
            Rest = GenericArray<u8, Self::KeyLen>,
            Output = Self::SaltStateIvEdk,
        >;

    #[doc(hidden)]
    type SaltStateIvEdk: Split<
            u8,
            <V::SaltStateIv as GenericSequence<u8>>::Length,
            First = V::SaltStateIv,
            Second = GenericArray<u8, Self::KeyLen>,
        > + Concat<
            u8,
            <V::TagMac as OutputSizeUser>::OutputSize,
            Rest = GenericArray<u8, <V::TagMac as OutputSizeUser>::OutputSize>,
            Output = Self::SaltStateIvEdkTag,
        >;

    #[doc(hidden)]
    type SaltStateIvEdkTag: Split<
            u8,
            <Self::SaltStateIvEdk as GenericSequence<u8>>::Length,
            First = Self::SaltStateIvEdk,
            Second = GenericArray<u8, <V::TagMac as OutputSizeUser>::OutputSize>,
        > + DerefMut<Target = [u8]>
        + Default;
}

#[cfg(feature = "v3")]
impl PwVersion for V3 {
    type Cipher = ctr::Ctr64BE<aes::Aes256>;
    type KeyHash = sha2::Sha384;
    type TagMac = hmac::Hmac<sha2::Sha384>;

    type KdfStateLen = generic_array::typenum::U4;
    type KdfState = Pbkdf2State;

    type Salt = GenericArray<u8, generic_array::typenum::U32>;
    type SaltState = GenericArray<u8, generic_array::typenum::U36>;
    type SaltStateIv = GenericArray<u8, generic_array::typenum::U52>;

    fn kdf(pw: &[u8], salt: &Self::Salt, state: &Self::KdfState) -> GenericArray<u8, U32> {
        pbkdf2::pbkdf2_hmac_array::<sha2::Sha384, 32>(pw, salt.as_slice(), state.iterations).into()
    }

    fn split_ek(ek: digest::Output<Self::KeyHash>) -> cipher::Key<Self::Cipher> {
        let (ek, _) = ek.split();
        ek
    }

    fn encode_state(s: &Self::KdfState) -> GenericArray<u8, Self::KdfStateLen> {
        s.iterations.to_be_bytes().into()
    }
    fn decode_state(s: GenericArray<u8, Self::KdfStateLen>) -> Self::KdfState {
        let i = u32::from_be_bytes(s.into());
        Pbkdf2State { iterations: i }
    }
}

#[cfg(feature = "v4")]
impl PwVersion for V4 {
    type Cipher = chacha20::XChaCha20;
    type KeyHash = blake2::Blake2b<U32>;
    type TagMac = blake2::Blake2bMac<U32>;

    type KdfStateLen = generic_array::typenum::U16;
    type KdfState = Argon2State;

    type Salt = GenericArray<u8, generic_array::typenum::U16>;
    type SaltState = GenericArray<u8, generic_array::typenum::U32>;
    type SaltStateIv = GenericArray<u8, generic_array::typenum::U56>;

    fn kdf(pw: &[u8], salt: &Self::Salt, state: &Self::KdfState) -> GenericArray<u8, U32> {
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
    fn decode_state(s: GenericArray<u8, Self::KdfStateLen>) -> Self::KdfState {
        let (mem1, b) = s.split();
        let (mem2, b) = b.split();
        let (time, para) = b.split();

        let _mem1: GenericArray<u8, generic_array::typenum::U4> = mem1;
        let mem = u32::from_be_bytes(mem2.into());
        let time = u32::from_be_bytes(time.into());
        let para = u32::from_be_bytes(para.into());

        Argon2State { mem, time, para }
    }
}

#[cfg(feature = "v4")]
impl PwWrapType<V4> for Local {
    type SaltStateIv = GenericArray<u8, generic_array::typenum::U56>;
    type SaltStateIvEdk = GenericArray<u8, generic_array::typenum::U88>;
    type SaltStateIvEdkTag = GenericArray<u8, generic_array::typenum::U120>;
}

#[cfg(feature = "v3")]
impl PwWrapType<V3> for Local {
    type SaltStateIv = GenericArray<u8, generic_array::typenum::U52>;
    type SaltStateIvEdk = GenericArray<u8, generic_array::typenum::U84>;
    type SaltStateIvEdkTag = GenericArray<u8, generic_array::typenum::U132>;
}

#[cfg(feature = "v4")]
impl PwWrapType<V4> for Secret {
    type SaltStateIv = GenericArray<u8, generic_array::typenum::U56>;
    type SaltStateIvEdk = GenericArray<u8, generic_array::typenum::U120>;
    type SaltStateIvEdkTag = GenericArray<u8, generic_array::typenum::U152>;
}

#[cfg(feature = "v3")]
impl PwWrapType<V3> for Secret {
    type SaltStateIv = GenericArray<u8, generic_array::typenum::U52>;
    type SaltStateIvEdk = GenericArray<u8, generic_array::typenum::U100>;
    type SaltStateIvEdkTag = GenericArray<u8, generic_array::typenum::U148>;
}

#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
#[cfg(feature = "serde")]
impl<V: PwVersion, K: PwWrapType<V>> serde::Serialize for PwWrappedKey<V, K> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
#[cfg(feature = "serde")]
impl<'de, V: PwVersion, K: PwWrapType<V>> serde::Deserialize<'de> for PwWrappedKey<V, K> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct FromStrVisitor<V, K>(std::marker::PhantomData<(V, K)>);
        impl<'de, V: PwVersion, K: PwWrapType<V>> serde::de::Visitor<'de> for FromStrVisitor<V, K> {
            type Value = PwWrappedKey<V, K>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(
                    formatter,
                    "a \"{}{}\" serialized key",
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
