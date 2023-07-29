#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
// #![warn(missing_docs)]
//! [Platform-Agnostic Serialized Keys](https://github.com/paseto-standard/paserk)
//!
//! PASERK is an extension to [PASETO](https://paseto.io) that provides key-wrapping and serialization.
//!
//! ## Motivation
//!
//! PASETO provides two types of tokens (called a purpose) in each of its versions:
//!
//! | Purpose  | Cryptographic Operation                                            |
//! |----------|--------------------------------------------------------------------|
//! | `local`  | Symmetric-key authenticated encryption with additional data (AEAD) |
//! | `public` | Asymmetric-key digital signatures (**no encryption**)              |
//!
//! These two token modes solve at least 80% of use cases for secure tokens. You can
//! even solve *unencrypted* symmetric-key authentication by storing your claims in
//! the unencrypted footer, rather than encrypting them.
//!
//! The use-cases that PASETO doesn't address out of the box are:
//!
//! * Key-wrapping
//! * Asymmetric encryption
//! * Password-based key encryption
//!
//! PASERK aims to provide an answer for these circumstances, as well as provide a
//! consistent standard for the encoding of PASETO keys.
//!
//! ## PASERK
//!
//! A serialized key in PASERK has the format:
//!
//! ```text
//! k[version].[type].[data]
//! ```
//!
//! Where `[version]` is an integer, `[data]` is the (*typically* base64url-encoded)
//! payload data, and `[type]` is one of the items in the following table:
//!
//! | PASERK Type   | Meaning                                                                     | PASETO Compatibility | \[data\] Encoded? | Safe in Footer? |
//! |---------------|-----------------------------------------------------------------------------|----------------------|-------------------|-----------------|
//! | `lid`         | Unique Identifier for a separate PASERK for `local` PASETOs.                | `local`              | Yes               | Yes             |
//! | `pid`         | Unique Identifier for a separate PASERK for `public` PASETOs. (Public Key)  | `public`             | Yes               | Yes             |
//! | `sid`         | Unique Identifier for a separate PASERK for `public` PASETOs. (Secret Key)  | `public`             | Yes               | Yes             |
//! | `local`       | Symmetric key for `local` tokens.                                           | `local`              | Yes               | **No**          |
//! | `public`      | Public key for verifying `public` tokens.                                   | `public`             | Yes               | **No**          |
//! | `secret`      | Secret key for signing `public` tokens.                                     | `public`             | Yes               | **No**          |
//! | `seal`        | Symmetric key wrapped using asymmetric encryption.                          | `local`              | Yes               | Yes             |
//! | `local-wrap`  | Symmetric key wrapped by another symmetric key.                             | `local`              | No                | Yes             |
//! | `local-pw`    | Symmetric key wrapped using password-based encryption.                      | `local`              | Yes               | **No**          |
//! | `secret-wrap` | Asymmetric secret key wrapped by another symmetric key.                     | `public`             | No                | Yes             |
//! | `secret-pw`   | Asymmetric secret key wrapped using password-based encryption.              | `public`             | Yes               | **No**          |
//!
//! ## implementation
//!
//! This library offers each of the key types and PASERK types from PASETO V3/4 as a unique rust type.
//!
//! ### [`Key`]s
//!
//! Since PASETO identifies 3 different key types, so do we. They are as follows
//! * [`Local`] - For local symmetric encryption.
//! * [`Public`] - For public asymmetric verification and encryption
//! * [`Secret`] - For public asymmetric signing and decryption
//!
//! Keys are also versioned. We support the following versions
//! * [`V3`] - NIST based modern cryptography (hmac, sha2, aes, p384)
//! * [`V4`] - Sodium based modern cryptography (blake2b, chacha, ed25519)
//!
//! ### IDs: `lid`/`pid`/`sid`
//!
//! The [`KeyId`] type represents key ids. Building a KeyID is as simple as
//!
//! ```
//! use rusty_paserk::{Key, Local, KeyId, V4};
//!
//! let local_key = Key::<V4, Local>::new_os_random();
//! let kid: KeyId<V4, Local> = local_key.into();
//! // kid.to_string() => "k4.lid.XxPub51WIAEmbVTmrs-lFoFodxTSKk8RuYEJk3gl-DYB"
//! ```
//!
//! You can also parse the KeyId from a string to have a smaller in memory representation. It can be safely shared and stored.
//!
//! ### Plaintext: `local`/`public`/`secret`
//!
//! The [`PlaintextKey`] type represents the base64 encoded plaintext key types.
//!
//! ```
//! use rusty_paserk::{Key, Local, PlaintextKey, V4};
//!
//! let local_key = Key::<V4, Local>::new_os_random();
//! let key = PlaintextKey(local_key);
//! // key.to_string() => "k4.local.bkwMkk5uhGbHAISf4bzY5nlm6y_sfzOIAZTfj6Tc9y0"
//! ```
//!
//! These are considered sensitive and should not be shared (besides public keys)
//!
//! ### Seal
//!
//! Using a public key, you can seal a local key. Using the corresponding private key, you can unseal the key again.
//!
//! ```
//! use rusty_paserk::{SealedKey, Key, Local, Secret, V4};
//!
//! let key = Key::<V4, Local>::new_os_random();
//!
//! let secret_key = Key::<V4, Secret>::new_os_random();
//! let public_key = secret_key.public_key();
//!
//! let sealed = key.seal(&public_key).to_string();
//! // => "k4.seal.23KlrMHZLW4muL75Rnuqtaro9F16mqDNvmCbgDXi2IdNyWmjrbTVBEih1DhSI_5xp7b7mCHSFo1DMv-9GtZUSpyi4646XBxpbFShHjJihF_Af8maWsDqdzOof76ia0Cv"
//!
//! let sealed: SealedKey<V4> = sealed.parse().unwrap();
//! let key2 = sealed.unseal(&secret_key).unwrap();
//! assert_eq!(key, key2);
//! ```
//!
//! See the [`SealedKey`] type for more info.
//!
//! ### Wrap `local-wrap`/`secret-wrap`
//!
//! Using a local key, you can wrap a local or a secret key. It can be unwrapped using the same local key.
//!
//! ```
//! use rusty_paserk::{PieWrappedKey, Key, Local, V4};
//!
//! let wrapping_key = Key::<V4, Local>::new_os_random();
//!
//! let local_key = Key::<V4, Local>::new_os_random();
//!
//! let wrapped_local = local_key.wrap_pie(&wrapping_key).to_string();
//! // => "k4.local-wrap.pie.RcAvOxHI0H-0uMsIl6KGcplH_tDlOhW1omFwXltZCiynHeRNH0hmn28AkN516h3WHuAReH3CvQ2SZ6mevnTquPETSd3XnlcbRWACT5GLWcus3BsD4IFWm9wFZgNF7C_E"
//!
//! let wrapped_local: PieWrappedKey<V4, Local> = wrapped_local.parse().unwrap();
//! let local_key2 = wrapped_local.unwrap_key(&wrapping_key).unwrap();
//! assert_eq!(local_key, local_key2);
//! ```
//!
//! See the [`PieWrappedKey`] type for more info.
//!
//! ### Password wrapping `local-pw`/`secret-pw`
//!
//! Using a password, you can wrap a local or a secret key. It can be unwrapped using the same password.
//!
//! ```
//! use rusty_paserk::{PwWrappedKey, Key, Local, Secret, V4, Argon2State};
//!
//! let password = "hunter2";
//!
//! let secret_key = Key::<V4, Secret>::new_os_random();
//!
//! let wrapped_secret = secret_key.pw_wrap(password.as_bytes()).to_string();
//! // => "k4.secret-pw.uscmLPzUoxxRfuzmY0DWcAAAAAAEAAAAAAAAAgAAAAHVNddVDnjRCc-ZmT-R-Xp7c7s4Wn1iH0dllAPFBmknEJpKGYP_aPoxVzNS_O93M0sCb68t7HjdD-jXWp-ioWe56iLoA6MlxE-SmnKear60aDwqk5fYv_EMD4Y2pV049BvDNGNN-MzR6fwW_OlyhV9omEvxmczAujM"
//!
//! let wrapped_secret: PwWrappedKey<V4, Secret> = wrapped_secret.parse().unwrap();
//! let secret_key2 = wrapped_secret.unwrap_key(password.as_bytes()).unwrap();
//! assert_eq!(secret_key, secret_key2);
//! ```
//!
//! See the [`PwWrappedKey`] type for more info.

use std::{borrow::Cow, fmt, ops::DerefMut, str::FromStr};

type Bytes<N> = GenericArray<u8, N>;

#[cfg(feature = "v3")]
#[derive(Default)]
pub struct V3;
#[cfg(feature = "v4")]
#[derive(Default)]
pub struct V4;

use base64ct::Encoding;
use cipher::Unsigned;
use generic_array::{sequence::GenericSequence, ArrayLength, GenericArray};

pub use key::{Key, KeyType, Public, Secret};
use serde::{de::DeserializeOwned, Serialize};

mod base64ct2;
mod key;
mod local;

/// General information about token types
pub trait TokenType: Default {
    /// "local" or "public"
    const TOKEN_TYPE: &'static str;
}

fn pae(pieces: &[&str], out: &mut Vec<u8>) {
    out.extend_from_slice(&(pieces.len() as u64).to_le_bytes());
    for piece in pieces {
        out.extend_from_slice(&(piece.len() as u64).to_le_bytes());
        out.extend_from_slice(piece.as_bytes());
    }
}

pub trait PayloadEncoding {
    /// Suffix for this encoding type
    const SUFFIX: &'static str;
}

pub trait MessageEncoding<M: Message>: PayloadEncoding {
    fn encode(&self, s: &M) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
    fn decode(&self, from: &[u8]) -> Result<M, Box<dyn std::error::Error>>;
}

pub struct JsonEncoding;

impl PayloadEncoding for JsonEncoding {
    const SUFFIX: &'static str = "";
}
impl<M: Message + Serialize + DeserializeOwned> MessageEncoding<M> for JsonEncoding {
    fn encode(&self, s: &M) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        serde_json::to_vec(s).map_err(From::from)
    }

    fn decode(&self, from: &[u8]) -> Result<M, Box<dyn std::error::Error>> {
        serde_json::from_slice(from).map_err(From::from)
    }
}

pub trait Message {
    fn validate(&self) -> Result<(), Box<dyn std::error::Error>>;
}

pub trait Footer: Sized {
    fn encode(&self) -> Vec<u8>;
    fn decode(footer: Option<&str>) -> Result<Self, Box<dyn std::error::Error>>;
}

impl Footer for () {
    fn encode(&self) -> Vec<u8> {
        Vec::new()
    }

    fn decode(footer: Option<&str>) -> Result<Self, Box<dyn std::error::Error>> {
        match footer {
            Some(x) => Err(format!("unexpected footer {x:?}").into()),
            None => Ok(()),
        }
    }
}

/// General information about a PASETO/PASERK version
pub trait Version: Default {
    /// Header for PASETO
    const PASETO_HEADER: &'static str;
    /// Header for PASERK
    const PASERK_HEADER: &'static str;
}

/// General information about a PASETO/PASERK version
pub trait PublicVersion: Version {
    /// Size of the asymmetric public key
    type Public: ArrayLength<u8>;
    /// Size of the asymmetric secret key
    type Secret: ArrayLength<u8>;

    type Signature: ArrayLength<u8>;
    type SigningKey: signature::Signer<GenericArray<u8, Self::Signature>>;
    type VerifyingKey: signature::Verifier<GenericArray<u8, Self::Signature>>;

    fn signing_key(key: GenericArray<u8, Self::Secret>) -> Self::SigningKey;
    fn verifying_key(key: GenericArray<u8, Self::Public>) -> Self::VerifyingKey;
}

#[cfg(feature = "v3")]
impl Version for V3 {
    const PASETO_HEADER: &'static str = "v3";
    const PASERK_HEADER: &'static str = "k3";
}

#[cfg(feature = "v4")]
impl Version for V4 {
    const PASETO_HEADER: &'static str = "v4";
    const PASERK_HEADER: &'static str = "k4";
}

#[cfg(feature = "v4")]
mod v4 {
    use chacha20::XChaCha20;
    use cipher::KeyIvInit;
    use generic_array::{
        sequence::Split,
        typenum::{IsLessOrEqual, LeEq, NonZero, U32, U56, U64},
        ArrayLength, GenericArray,
    };

    use crate::local::{GenericCipher, GenericMac, LocalVersion};
    use crate::{PublicVersion, V4};

    pub struct Hash;
    pub struct Cipher;

    impl<O> GenericMac<O> for Hash
    where
        O: ArrayLength<u8> + IsLessOrEqual<U64>,
        LeEq<O, U64>: NonZero,
    {
        type Mac = blake2::Blake2bMac<O>;
    }

    impl GenericCipher for Cipher {
        type KeyIvPair = U56;

        type Stream = XChaCha20;

        fn key_iv_init(pair: GenericArray<u8, Self::KeyIvPair>) -> Self::Stream {
            let (key, iv) = pair.split();
            XChaCha20::new(&key, &iv)
        }
    }

    impl LocalVersion for V4 {
        type Local = U32;

        type AuthKeySize = U32;
        type TagSize = U32;
        type Cipher = Cipher;
        type Mac = Hash;
    }

    pub struct SigningKey(ed25519_dalek::SigningKey);
    pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

    impl signature::Signer<GenericArray<u8, U64>> for SigningKey {
        fn try_sign(&self, msg: &[u8]) -> Result<GenericArray<u8, U64>, signature::Error> {
            self.0.try_sign(msg).map(|x| x.to_bytes().into())
        }
    }
    impl signature::Verifier<GenericArray<u8, U64>> for VerifyingKey {
        fn verify(
            &self,
            msg: &[u8],
            signature: &GenericArray<u8, U64>,
        ) -> Result<(), signature::Error> {
            let sig = ed25519_dalek::Signature::from_bytes(&(*signature).into());
            self.0.verify(msg, &sig)
        }
    }

    impl PublicVersion for V4 {
        /// Compressed edwards y point
        type Public = U32;
        /// Ed25519 scalar key, concatenated with the public key bytes
        type Secret = U64;

        type Signature = U64;
        type SigningKey = SigningKey;
        type VerifyingKey = VerifyingKey;

        fn signing_key(key: GenericArray<u8, Self::Secret>) -> Self::SigningKey {
            let (sk, _pk): (GenericArray<u8, U32>, _) = key.split();
            SigningKey(ed25519_dalek::SigningKey::from_bytes(&sk.into()))
        }
        fn verifying_key(key: GenericArray<u8, Self::Public>) -> Self::VerifyingKey {
            VerifyingKey(
                ed25519_dalek::VerifyingKey::from_bytes(&key.into())
                    .expect("validity of this public key should already be asserted"),
            )
        }
    }
}

#[cfg(feature = "v3")]
mod v3 {
    use cipher::KeyIvInit;
    use generic_array::{
        sequence::Split,
        typenum::{U32, U48, U49, U96},
        GenericArray,
    };

    use crate::local::{GenericCipher, GenericMac, LocalVersion};
    use crate::{PublicVersion, V3};

    pub struct Hash;
    pub struct Cipher;

    impl GenericMac<U48> for Hash {
        type Mac = hmac::Hmac<sha2::Sha384>;
    }

    impl GenericCipher for Cipher {
        type KeyIvPair = U48;

        type Stream = ctr::Ctr64BE<aes::Aes256>;

        fn key_iv_init(pair: GenericArray<u8, Self::KeyIvPair>) -> Self::Stream {
            let (key, iv) = pair.split();
            Self::Stream::new(&key, &iv)
        }
    }

    impl LocalVersion for V3 {
        type Local = U32;

        type AuthKeySize = U48;
        type TagSize = U48;
        type Cipher = Cipher;
        type Mac = Hash;
    }

    pub struct SigningKey(p384::ecdsa::SigningKey);
    pub struct VerifyingKey(p384::ecdsa::VerifyingKey);

    impl signature::Signer<GenericArray<u8, U96>> for SigningKey {
        fn try_sign(&self, msg: &[u8]) -> Result<GenericArray<u8, U96>, signature::Error> {
            self.0
                .try_sign(msg)
                .map(|x: p384::ecdsa::Signature| x.to_bytes())
        }
    }
    impl signature::Verifier<GenericArray<u8, U96>> for VerifyingKey {
        fn verify(
            &self,
            msg: &[u8],
            signature: &GenericArray<u8, U96>,
        ) -> Result<(), signature::Error> {
            let sig = p384::ecdsa::Signature::from_bytes(signature)?;
            self.0.verify(msg, &sig)
        }
    }

    impl PublicVersion for V3 {
        /// P-384 Public Key in compressed format
        type Public = U49;
        /// P-384 Secret Key (384 bits = 48 bytes)
        type Secret = U48;

        type Signature = U96;
        type SigningKey = SigningKey;
        type VerifyingKey = VerifyingKey;

        fn signing_key(key: GenericArray<u8, Self::Secret>) -> Self::SigningKey {
            SigningKey(
                p384::ecdsa::SigningKey::from_bytes(&key)
                    .expect("secret key validity should already be asserted"),
            )
        }
        fn verifying_key(key: GenericArray<u8, Self::Public>) -> Self::VerifyingKey {
            VerifyingKey(
                p384::ecdsa::VerifyingKey::from_sec1_bytes(&key)
                    .expect("secret key validity should already be asserted"),
            )
        }
    }
}

pub struct UnsecuredToken<V, T, M, F = (), E = JsonEncoding> {
    version_header: V,
    token_type: T,
    message: M,
    footer: F,
    encoding: E,
}

impl TokenType for Public {
    const TOKEN_TYPE: &'static str = "public";
}

#[cfg(feature = "v4")]
impl<M> UnsecuredToken<V4, Public, M> {
    pub fn new_v4_public(message: M) -> Self {
        Self {
            version_header: V4,
            token_type: Public,
            message,
            footer: (),
            encoding: JsonEncoding,
        }
    }
}
#[cfg(feature = "v3")]
impl<M> UnsecuredToken<V3, Public, M> {
    pub fn new_v3_public(message: M) -> Self {
        Self {
            version_header: V3,
            token_type: Public,
            message,
            footer: (),
            encoding: JsonEncoding,
        }
    }
}

impl<V, T, M, E> UnsecuredToken<V, T, M, (), E> {
    pub fn with_footer<F>(self, footer: F) -> UnsecuredToken<V, T, M, F, E> {
        UnsecuredToken {
            version_header: self.version_header,
            token_type: self.token_type,
            message: self.message,
            footer,
            encoding: self.encoding,
        }
    }
}

impl<V, T, M, F> UnsecuredToken<V, T, M, F, JsonEncoding> {
    pub fn with_encoding<E>(self, encoding: E) -> UnsecuredToken<V, T, M, F, E> {
        UnsecuredToken {
            version_header: self.version_header,
            token_type: self.token_type,
            message: self.message,
            footer: self.footer,
            encoding,
        }
    }
}

pub struct SecuredToken<V, T, F = (), E = JsonEncoding> {
    version_header: V,
    token_type: T,
    message: Vec<u8>,
    encoded_footer: Vec<u8>,
    footer: F,
    encoding: E,
}

pub type SymmetricKey<V> = Key<V, local::Local>;
pub type PublicKey<V> = Key<V, Public>;
pub type SecretKey<V> = Key<V, Secret>;

pub type UnencryptedToken<V, M, F, E> = UnsecuredToken<V, local::Local, M, F, E>;
pub type EncryptedToken<V, F, E> = SecuredToken<V, local::Local, F, E>;
pub type UnsignedToken<V, M, F, E> = UnsecuredToken<V, Public, M, F, E>;
pub type SignedToken<V, F, E> = SecuredToken<V, Public, F, E>;

impl<V: Version, T: TokenType, F, E: PayloadEncoding> fmt::Display for SecuredToken<V, T, F, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(V::PASETO_HEADER)?;
        f.write_str(E::SUFFIX)?;
        f.write_str(".")?;
        f.write_str(T::TOKEN_TYPE)?;
        f.write_str(".")?;
        f.write_str(&base64ct::Base64UrlUnpadded::encode_string(&self.message))?;
        f.write_str(".")?;
        f.write_str(&base64ct::Base64UrlUnpadded::encode_string(
            &self.encoded_footer,
        ))?;
        Ok(())
    }
}

// impl<V: LocalVersion, F: Footer, E: MessageEncoding> SecuredToken<V, Local, F, E> {}

// /// Internally used traits for encryption version configuration
// pub mod internal {
//     pub use crate::pbkw::{PwType, PwVersion, PwWrapType};
//     pub use crate::pke::SealedVersion;
//     pub use crate::wrap::{PieVersion, PieWrapType, WrapType};
// }

pub enum PasetoError {
    Base64DecodeError,
    InvalidKey,
}

fn write_b64<W: std::fmt::Write>(b: &[u8], w: &mut W) -> std::fmt::Result {
    let mut buffer = [0; 64];
    for chunk in b.chunks(48) {
        let s = base64ct::Base64UrlUnpadded::encode(chunk, &mut buffer).unwrap();
        w.write_str(s)?;
    }
    Ok(())
}

fn read_b64<L: GenericSequence<u8> + DerefMut<Target = [u8]> + Default>(
    s: &str,
) -> Result<L, PasetoError> {
    let expected_len = (s.len() + 3) / 4 * 3;
    if expected_len < <L::Length as Unsigned>::USIZE {
        return Err(PasetoError::Base64DecodeError);
    }

    let mut total = L::default();

    let len = base64ct::Base64UrlUnpadded::decode(s, &mut total)
        .map_err(|_| PasetoError::Base64DecodeError)?
        .len();

    if len != <L::Length as Unsigned>::USIZE {
        return Err(PasetoError::Base64DecodeError);
    }

    Ok(total)
}

#[cfg(any(test, fuzzing))]
pub mod fuzzing {
    use rand::{CryptoRng, RngCore};

    #[derive(Clone, Debug)]
    /// a consistent rng store
    pub struct FakeRng<const N: usize> {
        pub bytes: [u8; N],
        pub start: usize,
    }

    #[cfg(feature = "arbitrary")]
    impl<'a, const N: usize> arbitrary::Arbitrary<'a> for FakeRng<N>
    where
        [u8; N]: arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                bytes: <[u8; N]>::arbitrary(u)?,
                start: 0,
            })
        }
    }

    impl<const N: usize> RngCore for FakeRng<N> {
        fn next_u32(&mut self) -> u32 {
            unimplemented!()
        }

        fn next_u64(&mut self) -> u64 {
            unimplemented!()
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let remaining = N - self.start;
            let requested = dest.len();
            if requested > remaining {
                panic!("not enough entropy");
            }
            dest.copy_from_slice(&self.bytes[self.start..self.start + requested]);
            self.start += requested;
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    // not really
    impl<const N: usize> CryptoRng for FakeRng<N> {}

    // pub mod seal {
    //     pub use crate::pke::fuzz_tests::{V3SealInput, V4SealInput};
    // }
    // pub mod wrap {
    //     pub use crate::wrap::fuzz_tests::FuzzInput;
    // }
}
