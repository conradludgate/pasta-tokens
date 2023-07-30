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

use std::{fmt, ops::DerefMut};

type Bytes<N> = generic_array::GenericArray<u8, N>;

#[cfg(feature = "v3")]
#[derive(Default)]
pub struct V3;
#[cfg(feature = "v4")]
#[derive(Default)]
pub struct V4;

use base64ct::Encoding;

pub use key::{Key, KeyType};
use serde::{de::DeserializeOwned, Serialize};

mod base64ct2;
mod key;
pub mod local;
mod pae;
pub mod public;

/// General information about token types
pub trait TokenType: Default {
    /// "local" or "public"
    const TOKEN_TYPE: &'static str;
}

pub trait PayloadEncoding: Default {
    /// Suffix for this encoding type
    const SUFFIX: &'static str;
}

pub trait MessageEncoding<M: Message>: PayloadEncoding {
    fn encode(&self, s: &M) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
    fn decode(&self, from: &[u8]) -> Result<M, Box<dyn std::error::Error>>;
}

#[derive(Default)]
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

/// An implementation of [`Message`] that requires no additional validation.
pub struct AlwaysValid<T>(pub T);

/// Encoding scheme for PASETO footers.
///
/// Footers are allowed to be any encoding, but JSON is the standard.
/// You can use the `Json` type to encode using JSON.
///
/// Footers are also optional, so the `()` empty type is considered as a missing footer.
pub trait Footer: Sized {
    fn encode(&self) -> Vec<u8>;
    fn decode(footer: Option<&[u8]>) -> Result<Self, Box<dyn std::error::Error>>;
}

/// `Json` is a type wrapper to implement `Footer` for all types that implement
/// [`serde::Serialize`] and [`serde::Deserialize`]
struct Json<T>(pub T);

impl<T: Serialize + DeserializeOwned> Footer for Json<T> {
    fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(&self.0).expect("json serialization should not panic")
    }

    fn decode(footer: Option<&[u8]>) -> Result<Self, Box<dyn std::error::Error>> {
        match footer {
            None => Err("missing footer".into()),
            Some(x) => serde_json::from_slice(x).map(Self).map_err(|e| e.into()),
        }
    }
}

impl Footer for () {
    fn encode(&self) -> Vec<u8> {
        Vec::new()
    }

    fn decode(footer: Option<&[u8]>) -> Result<Self, Box<dyn std::error::Error>> {
        match footer {
            Some(x) => Err(format!("unexpected footer {x:?}").into()),
            None => Ok(()),
        }
    }
}

mod sealed {
    pub trait Sealed {}

    #[cfg(feature = "v3")]
    impl Sealed for crate::V3 {}

    #[cfg(feature = "v4")]
    impl Sealed for crate::V4 {}
}

/// General information about a PASETO/PASERK version.
///
/// This library supports only version [`V3`] and [`V4`].
pub trait Version: Default + sealed::Sealed {
    /// Header for PASETO
    const PASETO_HEADER: &'static str;
    /// Header for PASERK
    const PASERK_HEADER: &'static str;
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

/// An unsecured token.
///
/// This represents a PASETO without any encryption or signatures.
/// Using one of the following aliases is suggested
/// * [`VerifiedToken`] - A `public` PASETO without the signature.
/// * [`UnencryptedToken`] - A `local` PASETO without encryption.
///
/// This type is un-serializable as it isn't secured. For that you will want [`SecuredToken`].
///
/// To convert to a [`SecuredToken`], you will need to use either
/// * [`VerifiedToken::sign`]
/// * [`UnencryptedToken::encrypt`]
pub struct UnsecuredToken<V, T, M, F = (), E = JsonEncoding> {
    version_header: V,
    token_type: T,
    message: M,
    footer: F,
    encoding: E,
}

impl<V, T, M, E> UnsecuredToken<V, T, M, (), E> {
    /// Set the footer for this token.
    ///
    /// Footers are embedded into the token as base64 only. They are authenticated but not encrypted.
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
    /// Set the payload encoding for this token.
    ///
    /// The PASETO spec only allows JSON _for now_, but one day this might be extended.
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

/// A secured token.
///
/// This represents a PASETO that is signed or encrypted.
/// Using one of the following aliases is suggested
/// * [`SignedToken`] - A `public` PASETO that is signed.
/// * [`EncryptedToken`] - A `local` PASETO that is encryption.
///
/// This type has a payload that is currently inaccessible. To access it, you will need to
/// decrypt/verify the contents. For that you will want [`UnsecuredToken`].
///
/// To convert to an [`UnsecuredToken`], you will need to use either
/// * [`SignedToken::verify`]
/// * [`EncryptedToken::decrypt`]
pub struct SecuredToken<V, T, F = (), E = JsonEncoding> {
    version_header: V,
    token_type: T,
    message: Vec<u8>,
    encoded_footer: Vec<u8>,
    footer: F,
    encoding: E,
}

/// A symmetric key for `local` encrypted tokens
pub type SymmetricKey<V> = Key<V, local::Local>;
/// A public key for verifying `public` tokens
pub type PublicKey<V> = Key<V, public::Public>;
/// A secret key for signing `public` tokens
pub type SecretKey<V> = Key<V, public::Secret>;

/// An unencrypted PASETO.
pub type UnencryptedToken<V, M, F = (), E = JsonEncoding> =
    UnsecuredToken<V, local::Local, M, F, E>;
/// An encrypted PASETO.
pub type EncryptedToken<V, F = (), E = JsonEncoding> = SecuredToken<V, local::Local, F, E>;
/// A Verified PASETO that has either been parsed and verified, or is ready to be signed.
pub type VerifiedToken<V, M, F = (), E = JsonEncoding> = UnsecuredToken<V, public::Public, M, F, E>;
/// A Signed PASETO.
pub type SignedToken<V, F = (), E = JsonEncoding> = SecuredToken<V, public::Public, F, E>;

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

impl<V: Version, T: TokenType, F: Footer, E: PayloadEncoding> std::str::FromStr
    for SecuredToken<V, T, F, E>
{
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix(V::PASETO_HEADER).ok_or(())?;
        let s = s.strip_prefix(E::SUFFIX).ok_or(())?;
        let s = s.strip_prefix('.').ok_or(())?;
        let s = s.strip_prefix(T::TOKEN_TYPE).ok_or(())?;
        let s = s.strip_prefix('.').ok_or(())?;

        let (payload, footer) = match s.split_once('.') {
            Some((payload, footer)) => (payload, Some(footer)),
            None => (s, None),
        };

        let payload = base64ct::Base64UrlUnpadded::decode_vec(payload).map_err(|_| ())?;
        let encoded_footer = footer
            .map(base64ct::Base64UrlUnpadded::decode_vec)
            .transpose()
            .map_err(|_| ())?;
        let footer = F::decode(encoded_footer.as_deref()).map_err(|_| ())?;

        Ok(Self {
            version_header: V::default(),
            token_type: T::default(),
            message: payload,
            encoded_footer: encoded_footer.unwrap_or_default(),
            footer,
            encoding: E::default(),
        })
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
