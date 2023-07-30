#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! PASETO - **P**latform **A**gnostic **Se**curity **To**kens.
//!
//! > - [@conradludgate](https://github.com/conradludgate): "hmm, actually, I might switch to using something like paseto"
//! > - [@ellie](https://github.com/ellie): "It sounds like a type of pasta"
//!
//! Paseto is everything you love about JOSE (JWT, JWE, JWS) without any of the [many design deficits that plague the JOSE standards](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid).
//! See more about PASETO in the [specification](https://github.com/paseto-standard/paseto-spec)

use std::fmt;

type Bytes<N> = generic_array::GenericArray<u8, N>;

/// PASETO Version 3 (NIST)
#[cfg(feature = "v3")]
#[derive(Default)]
pub struct V3;

/// PASETO Version 4 (Sodium)
#[cfg(feature = "v4")]
#[derive(Default)]
pub struct V4;

use base64ct::Encoding;

pub use key::{Key, KeyType};

/// Purpose of the PASETO. Supports either `local` or
pub mod purpose {
    #[cfg(feature = "local")]
    #[cfg_attr(docsrs, doc(cfg(feature = "local")))]
    pub mod local;
    #[cfg(feature = "public")]
    #[cfg_attr(docsrs, doc(cfg(feature = "public")))]
    pub mod public;

    #[cfg(feature = "local")]
    pub use local::Local;
    #[cfg(feature = "public")]
    pub use public::{Public, Secret};

    /// Purpose of the PASETO.
    ///
    /// * `public` - signed tokens. payload included in plaintext
    /// * `local` - encrypted tokens. payload is not readable without key
    pub trait Purpose: Default {
        /// "local" or "public"
        const HEADER: &'static str;
    }
}

use purpose::Purpose;
use serde::{de::DeserializeOwned, Serialize};

mod key;
mod pae;

/// A payload encoding protocol. Currently only supports [`Json`]
pub trait PayloadEncoding: Default {
    /// Suffix for this encoding type
    const SUFFIX: &'static str;
}

/// Payload encoding implementation. Currently only supports [`Json`]
pub trait MessageEncoding<M>: PayloadEncoding {
    /// Encode the message
    fn encode(&self, s: &M) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
    /// Decode the message
    fn decode(&self, from: &[u8]) -> Result<M, Box<dyn std::error::Error>>;
}

impl PayloadEncoding for Json<()> {
    const SUFFIX: &'static str = "";
}
impl<M: Serialize + DeserializeOwned> MessageEncoding<M> for Json<()> {
    fn encode(&self, s: &M) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        serde_json::to_vec(s).map_err(From::from)
    }

    fn decode(&self, from: &[u8]) -> Result<M, Box<dyn std::error::Error>> {
        serde_json::from_slice(from).map_err(From::from)
    }
}

/// Encoding scheme for PASETO footers.
///
/// Footers are allowed to be any encoding, but JSON is the standard.
/// You can use the `Json` type to encode using JSON.
///
/// Footers are also optional, so the `()` empty type is considered as a missing footer.
pub trait Footer: Sized {
    /// Encode the footer to bytes
    fn encode(&self) -> Vec<u8>;
    /// Decode the footer from bytes
    fn decode(footer: &[u8]) -> Result<Self, Box<dyn std::error::Error>>;
}

/// `Json` is a type wrapper to implement `Footer` for all types that implement
/// [`serde::Serialize`] and [`serde::Deserialize`]
#[derive(Default)]
pub struct Json<T>(pub T);

impl<T: Serialize + DeserializeOwned> Footer for Json<T> {
    fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(&self.0).expect("json serialization should not panic")
    }

    fn decode(footer: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        match footer {
            x if x.is_empty() => Err("missing footer".into()),
            x => serde_json::from_slice(x).map(Self).map_err(|e| e.into()),
        }
    }
}

impl Footer for Vec<u8> {
    fn encode(&self) -> Vec<u8> {
        self.clone()
    }

    fn decode(footer: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(footer.to_owned())
    }
}

impl Footer for () {
    fn encode(&self) -> Vec<u8> {
        Vec::new()
    }

    fn decode(footer: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        match footer {
            x if x.is_empty() => Ok(()),
            x => Err(format!("unexpected footer {x:?}").into()),
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
pub struct UnsecuredToken<V, T, M, F = (), E = Json<()>> {
    version_header: V,
    token_type: T,
    pub message: M,
    pub footer: F,
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

impl<V, T, M, F> UnsecuredToken<V, T, M, F, Json<()>> {
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
pub struct SecuredToken<V, T, F = (), E = Json<()>> {
    version_header: V,
    token_type: T,
    payload: Vec<u8>,
    encoded_footer: Vec<u8>,
    footer: F,
    encoding: E,
}

/// A symmetric key for `local` encrypted tokens
#[cfg(feature = "local")]
pub type SymmetricKey<V> = Key<V, purpose::Local>;
/// A public key for verifying `public` tokens
#[cfg(feature = "public")]
pub type PublicKey<V> = Key<V, purpose::Public>;
/// A secret key for signing `public` tokens
#[cfg(feature = "public")]
pub type SecretKey<V> = Key<V, purpose::Secret>;

/// An unencrypted PASETO.
#[cfg(feature = "local")]
pub type UnencryptedToken<V, M, F = (), E = Json<()>> = UnsecuredToken<V, purpose::Local, M, F, E>;
/// An encrypted PASETO.
#[cfg(feature = "local")]
pub type EncryptedToken<V, F = (), E = Json<()>> = SecuredToken<V, purpose::Local, F, E>;
/// A Verified PASETO that has either been parsed and verified, or is ready to be signed.
#[cfg(feature = "public")]
pub type VerifiedToken<V, M, F = (), E = Json<()>> = UnsecuredToken<V, purpose::Public, M, F, E>;
/// A Signed PASETO.
#[cfg(feature = "public")]
pub type SignedToken<V, F = (), E = Json<()>> = SecuredToken<V, purpose::Public, F, E>;

impl<V: Version, T: Purpose, F, E: PayloadEncoding> fmt::Display for SecuredToken<V, T, F, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(V::PASETO_HEADER)?;
        f.write_str(E::SUFFIX)?;
        f.write_str(".")?;
        f.write_str(T::HEADER)?;
        f.write_str(".")?;
        f.write_str(&base64ct::Base64UrlUnpadded::encode_string(&self.payload))?;

        if !self.encoded_footer.is_empty() {
            f.write_str(".")?;
            f.write_str(&base64ct::Base64UrlUnpadded::encode_string(
                &self.encoded_footer,
            ))?;
        }

        Ok(())
    }
}

impl<V: Version, T: Purpose, F: Footer, E: PayloadEncoding> std::str::FromStr
    for SecuredToken<V, T, F, E>
{
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix(V::PASETO_HEADER).ok_or(())?;
        let s = s.strip_prefix(E::SUFFIX).ok_or(())?;
        let s = s.strip_prefix('.').ok_or(())?;
        let s = s.strip_prefix(T::HEADER).ok_or(())?;
        let s = s.strip_prefix('.').ok_or(())?;

        let (payload, footer) = match s.split_once('.') {
            Some((payload, footer)) => (payload, Some(footer)),
            None => (s, None),
        };

        let payload = base64ct::Base64UrlUnpadded::decode_vec(payload).map_err(|_| ())?;
        let encoded_footer = footer
            .map(base64ct::Base64UrlUnpadded::decode_vec)
            .transpose()
            .map_err(|_| ())?
            .unwrap_or_default();
        let footer = F::decode(&encoded_footer).map_err(|_| ())?;

        Ok(Self {
            version_header: V::default(),
            token_type: T::default(),
            payload,
            encoded_footer,
            footer,
            encoding: E::default(),
        })
    }
}

impl<V, T, F, E> SecuredToken<V, T, F, E> {
    /// View the footer for this token
    pub fn footer(&self) -> &F {
        &self.footer
    }
}

#[derive(Debug)]
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
