#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! PASETO - **P**latform **A**gnostic **Se**curity **To**kens.
//!
//! > - [@conradludgate](https://github.com/conradludgate): "hmm, actually, I might switch to using something like paseto"
//! > - [@ellie](https://github.com/ellie): "It sounds like a type of pasta"
//!
//! Paseto is everything you love about JOSE (JWT, JWE, JWS) without any of the [many design deficits that plague the JOSE standards](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid).
//! See more about PASETO in the [specification](https://github.com/paseto-standard/paseto-spec)
//!
//! ## Features
//!
//! * `v4`: Enables all V4 PASETO/PASERK functions.
//!   - `v4-paseto`
//!     - `v4-local`: V4 symmetric encrypted tokens
//!     - `v4-public`: V4 asymmetric signed tokens
//!   - `v4-paserk`
//!     - `v4-id`: V4 Key IDs
//!     - `v4-pke`: V4 Sealed Keys
//!     - `v4-pbkw`: V4 Password wrapped keys
//!     - `v4-wrap`: v4 Wrapped Keys
//! * `v3`: Enables all V3 PASETO/PASERK functions.
//!   - `v3-paseto`
//!     - `v3-local`: V3 symmetric encrypted tokens
//!     - `v3-public`: V3 asymmetric signed tokens
//!   - `v3-paserk`
//!     - `v3-id`: V3 Key IDs
//!     - `v3-pke`: V3 Sealed Keys
//!     - `v3-pbkw`: V3 Password wrapped keys
//!     - `v3-wrap`: v3 Wrapped Keys
//!
//! ## Examples
//!
//! ```
//! use pasta_tokens::{v4, paserk::k4, purpose::public::Public, Json};
//!
//! #[derive(serde::Serialize, serde::Deserialize)]
//! struct Footer {
//!     /// The ID of the key used to sign the PASETO.
//!     /// A footer should only contain types that are `SafeForFooter`
//!     kid: k4::KeyId<Public>,
//! }
//!
//! #[derive(serde::Serialize, serde::Deserialize)]
//! struct Payload {
//!     /// The expiration date of the token
//!     #[serde(with = "time::serde::rfc3339", rename = "exp")]
//!     expiration: time::OffsetDateTime,
//!     /// The subject of the token
//!     #[serde(rename = "sub")]
//!     user_id: uuid::Uuid,
//! }
//!
//! // load your secret key
//! let secret_key = hex::decode("407796f4bc4b8184e9fe0c54b336822d34823092ad873d87ba14c3efb9db8c1d").unwrap();
//! let secret_key = v4::SecretKey::from_secret_key(secret_key.try_into().unwrap());
//!
//! let user_id = uuid::Uuid::new_v4();
//!
//! // create the token payload and footer.
//! let token = v4::UnsignedToken::new(Payload {
//!         // expires in 1 hour
//!         expiration: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
//!         user_id,
//!     })
//!     .with_footer(Json(Footer {
//!         kid: secret_key.public_key().to_id(),
//!     }))
//!     // sign with the secret key
//!     .sign(&secret_key)
//!     .unwrap()
//!     .to_string();
//!
//! // Send off the token to the client
//! println!("{token}");
//! // "v4.public.eyJleHAiOiIyMDIzLTEwLTAxVDE0OjQ4OjI2LjM0NjA5MloiLCJzdWIiOiIxOTBhZjFmYS1lZGVlLTRiNGUtOGQxMC05ZmUwZjQ1ZGQ5OTQifXo-Vsr45NroJZ9pLkuN3xcxgFncGF3eject5GdZH7WwTEfCgmo6hD-zNh0txsLvZi1vC601oNCgXq_2cK4XKQw.eyJraWQiOiJrNC5waWQuQUdQQ09CUkI4UHowQ3dNOFFfQnNVUEw0OF8zZjRUbE0yc2Z0R3Y0ejkzVFkifQ"
//!
//! // load your public keys
//! let public_key = hex::decode("b7715bd661458d928654d3e832f53ff5c9480542e0e3d4c9b032c768c7ce6023").unwrap();
//! let public_key = v4::PublicKey::from_public_key(&public_key).unwrap();
//!
//! // keep a key cache of key IDs to public keys.
//! // this will let you securely rotate your secret keys
//! // and still validate multiple public keys safely
//! let keys = std::collections::HashMap::from([
//!     (public_key.to_id(), public_key)
//! ]);
//!
//! // Parse the token from the client
//! let token: v4::SignedToken<Json<Footer>> = token.parse().expect("should be a valid token format");
//!
//! // using the key ID, search for the public key
//! let key = &keys[&token.unverified_footer().0.kid];
//!
//! // verify the token signature
//! let token: v4::VerifiedToken<Payload, _> = token.verify(key).expect("token should be signed by us");
//!
//! // check if the token has expired
//! assert!(token.message.expiration > time::OffsetDateTime::now_utc());
//!
//! // proceed to use the payload as you wish!
//! assert_eq!(token.message.user_id, user_id);
//! ```

#[allow(dead_code)]
type Bytes<N> = generic_array::GenericArray<u8, N>;

/// PASETO V4 using only algorithms that are provided by libsodium
pub mod v4 {
    use crate::version::V4;
    /// A symmetric key for `local` encrypted tokens
    pub type SymmetricKey = crate::purpose::local::SymmetricKey<V4>;
    /// An decrypted PASETO.
    pub type DecryptedToken<M, F = (), E = crate::Json<()>> =
        crate::purpose::local::DecryptedToken<V4, M, F, E>;
    /// An encrypted PASETO.
    pub type EncryptedToken<F = (), E = crate::Json<()>> =
        crate::purpose::local::EncryptedToken<V4, F, E>;
    /// An unencrypted PASETO.
    pub type UnencryptedToken<M, F = (), E = crate::Json<()>> =
        crate::purpose::local::UnencryptedToken<V4, M, F, E>;

    /// A public key for verifying `public` tokens
    pub type PublicKey = crate::purpose::public::PublicKey<V4>;
    /// A secret key for signing `public` tokens
    pub type SecretKey = crate::purpose::public::SecretKey<V4>;
    /// A Verified PASETO that has been parsed and verified
    pub type VerifiedToken<M, F = (), E = crate::Json<()>> =
        crate::purpose::public::VerifiedToken<V4, M, F, E>;
    /// A Signed PASETO.
    pub type SignedToken<F = (), E = crate::Json<()>> =
        crate::purpose::public::SignedToken<V4, F, E>;
    /// A PASETO that is ready to be signed.
    pub type UnsignedToken<M, F = (), E = crate::Json<()>> =
        crate::purpose::public::UnsignedToken<V4, M, F, E>;
}

/// PASETO V3 using only NIST approved algorithms
pub mod v3 {
    use crate::version::V3;
    /// A symmetric key for `local` encrypted tokens
    pub type SymmetricKey = crate::purpose::local::SymmetricKey<V3>;
    /// An decrypted PASETO.
    pub type DecryptedToken<M, F = (), E = crate::Json<()>> =
        crate::purpose::local::DecryptedToken<V3, M, F, E>;
    /// An encrypted PASETO.
    pub type EncryptedToken<F = (), E = crate::Json<()>> =
        crate::purpose::local::EncryptedToken<V3, F, E>;
    /// An unencrypted PASETO.
    pub type UnencryptedToken<M, F = (), E = crate::Json<()>> =
        crate::purpose::local::UnencryptedToken<V3, M, F, E>;

    /// A public key for verifying `public` tokens
    pub type PublicKey = crate::purpose::public::PublicKey<V3>;
    /// A secret key for signing `public` tokens
    pub type SecretKey = crate::purpose::public::SecretKey<V3>;
    /// A Verified PASETO that has been parsed and verified
    pub type VerifiedToken<M, F = (), E = crate::Json<()>> =
        crate::purpose::public::VerifiedToken<V3, M, F, E>;
    /// A Signed PASETO.
    pub type SignedToken<F = (), E = crate::Json<()>> =
        crate::purpose::public::SignedToken<V3, F, E>;
    /// A PASETO that is ready to be signed.
    pub type UnsignedToken<M, F = (), E = crate::Json<()>> =
        crate::purpose::public::UnsignedToken<V3, M, F, E>;
}

pub mod purpose {
    //! Purpose of the PASETO. Supports either [`local`] or [`public`]

    pub mod local;
    pub mod public;

    pub use local::Local;
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

pub mod key;

// #[cfg(feature = "paserk")]
pub mod paserk;

pub mod version {
    //! Versions of PASETO. Supports [`V3`] or [`V4`]

    /// PASETO Version 3 (NIST)
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct V3;

    /// PASETO Version 4 (Sodium)
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct V4;

    /// General information about a PASETO/PASERK version.
    ///
    /// This library supports only version [`V3`] and [`V4`].
    pub trait Version: Default + crate::sealed::Sealed {
        /// Header for PASETO
        const PASETO_HEADER: &'static str;
        /// Header for PASERK
        const PASERK_HEADER: &'static str;
    }

    impl Version for V3 {
        const PASETO_HEADER: &'static str = "v3";
        const PASERK_HEADER: &'static str = "k3";
    }

    impl Version for V4 {
        const PASETO_HEADER: &'static str = "v4";
        const PASERK_HEADER: &'static str = "k4";
    }

    impl crate::sealed::Sealed for V3 {}

    impl crate::sealed::Sealed for V4 {}
}

/// PASETO Message encodings. Currently supports [`Json`]
///
/// PASETO serializes its payload as a JSON string.
/// Future documents MAY specify using PASETO with non-JSON encoding.
/// When this happens, a suffix will be appended to the version tag when a non-JSON encoding rule is used.
///
/// > For example, a future PASETO-CBOR proposal might define its versions as v1c, v2c, v3c, and v4c.
/// The underlying cryptography will be the same as v1, v2, v3, and v4 respectively.
/// Keys SHOULD be portable across different underlying encodings,
/// but tokens MUST NOT be transmutable between encodings without access to the symmetric key (local tokens) or secret key (public tokens).
pub mod encodings {
    use serde::{de::DeserializeOwned, Serialize};

    use crate::Json;

    /// A payload protocol. Currently only supports [`Json`]
    pub trait Payload: Default {
        /// Suffix for this encoding type
        const SUFFIX: &'static str;
    }

    /// Payload encoding implementation. Currently only supports [`Json`]
    pub trait MessageEncoding<M>: Payload {
        /// Encode the message
        fn encode(&self, s: &M) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>;
    }

    /// Payload decoding implementation. Currently only supports [`Json`]
    pub trait MessageDecoding<M>: Payload {
        /// Decode the message
        fn decode(&self, from: &[u8]) -> Result<M, Box<dyn std::error::Error + Send + Sync>>;
    }

    impl Payload for Json<()> {
        /// JSON is the standard payload and requires no version suffix
        const SUFFIX: &'static str = "";
    }

    impl<M: Serialize> MessageEncoding<M> for Json<()> {
        fn encode(&self, s: &M) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
            serde_json::to_vec(s).map_err(From::from)
        }
    }

    impl<M: DeserializeOwned> MessageDecoding<M> for Json<()> {
        fn decode(&self, from: &[u8]) -> Result<M, Box<dyn std::error::Error + Send + Sync>> {
            serde_json::from_slice(from).map_err(From::from)
        }
    }
}

mod pae;

/// Encoding scheme for PASETO footers.
///
/// Footers are allowed to be any encoding, but JSON is the standard.
/// You can use the `Json` type to encode serde structs using JSON.
///
/// Footers are also optional, so the `()` empty type is considered as a missing footer.
pub trait Footer: Sized {
    /// Encode the footer to bytes
    fn encode(&self) -> Vec<u8>;
    /// Decode the footer from bytes
    fn decode(footer: &[u8]) -> Result<Self, Box<dyn std::error::Error + Send + Sync>>;
}

/// `Json` is a type wrapper to implement `Footer` for all types that implement
/// [`serde::Serialize`] and [`serde::Deserialize`]
///
/// When using a JSON footer, you should be aware of the risks of parsing user provided JSON.
/// <https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md#storing-json-in-the-footer>.
///
/// Currently, this uses [`serde_json`] internally, which by default offers a stack-overflow protection limit on parsing JSON.
/// You should also parse into a known struct layout, and avoid arbitrary key-value mappings.
///
/// If you need stricter checks, you can make your own [`Footer`] encodings that give access to the bytes before
/// the footer is decoded.
#[derive(Default)]
pub struct Json<T>(pub T);

impl<T: serde::Serialize + serde::de::DeserializeOwned> Footer for Json<T> {
    fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(&self.0).expect("json serialization should not panic")
    }

    fn decode(footer: &[u8]) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
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

    fn decode(footer: &[u8]) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(footer.to_owned())
    }
}

impl Footer for () {
    fn encode(&self) -> Vec<u8> {
        Vec::new()
    }

    fn decode(footer: &[u8]) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        match footer {
            x if x.is_empty() => Ok(()),
            x => Err(format!("unexpected footer {x:?}").into()),
        }
    }
}

mod sealed {
    pub trait Sealed {}
}

#[derive(Default)]
struct TokenMetadata<V, T, E> {
    version_header: V,
    token_type: T,
    #[allow(dead_code)]
    encoding: E,
}

pub mod tokens {
    //! Generic Tokens

    use core::fmt;

    use base64ct::Encoding;

    use crate::{encodings::Payload, purpose, version, Footer, Json, PasetoError, TokenMetadata};

    /// A validated token.
    ///
    /// This represents a PASETO which has had signatures or encryption validated.
    /// Using one of the following aliases is suggested
    /// * [`VerifiedToken`](purpose::public::VerifiedToken) - A `public` PASETO which has had signature validated.
    /// * [`DecryptedToken`](purpose::local::DecryptedToken) - A `local` PASETO which has successfully been decrypted.
    ///
    /// This type is un-serializable as it isn't secured. For that you will want [`SecuredToken`].
    pub struct ValidatedToken<V, T, M, F = (), E = Json<()>> {
        pub(crate) meta: TokenMetadata<V, T, E>,
        /// The message that was contained in the token
        pub message: M,
        /// The footer that was sent with the token
        pub footer: F,
    }

    impl<V, T, M, E> TokenBuilder<V, T, M, (), E> {
        /// Set the footer for this token.
        ///
        /// Footers are embedded into the token as base64 only. They are authenticated but not encrypted.
        pub fn with_footer<F>(self, footer: F) -> TokenBuilder<V, T, M, F, E> {
            TokenBuilder(ValidatedToken {
                meta: self.0.meta,
                message: self.0.message,
                footer,
            })
        }
    }

    impl<V, T, M, F> TokenBuilder<V, T, M, F, Json<()>> {
        /// Set the payload encoding for this token.
        ///
        /// The PASETO spec only allows JSON _for now_, but one day this might be extended.
        pub fn with_encoding<E>(self, encoding: E) -> TokenBuilder<V, T, M, F, E> {
            TokenBuilder(ValidatedToken {
                message: self.0.message,
                footer: self.0.footer,
                meta: TokenMetadata {
                    version_header: self.0.meta.version_header,
                    token_type: self.0.meta.token_type,
                    encoding,
                },
            })
        }
    }

    /// A builder of tokens
    pub struct TokenBuilder<V, T, M, F = (), E = Json<()>>(
        pub(crate) ValidatedToken<V, T, M, F, E>,
    );

    /// A secured token.
    ///
    /// This represents a PASETO that is signed or encrypted.
    /// Using one of the following aliases is suggested
    /// * [`SignedToken`](purpose::public::SignedToken) - A `public` PASETO that is signed.
    /// * [`EncryptedToken`](purpose::local::EncryptedToken) - A `local` PASETO that is encryption.
    ///
    /// This type has a payload that is currently inaccessible. To access it, you will need to
    /// decrypt/verify the contents. For that you will want [`ValidatedToken`].
    ///
    /// To convert to an [`ValidatedToken`], you will need to use either
    /// * [`SignedToken::verify`](purpose::public::SignedToken::verify)
    /// * [`EncryptedToken::decrypt`](purpose::local::EncryptedToken::decrypt)
    pub struct SecuredToken<V, T, F = (), E = Json<()>> {
        #[allow(dead_code)]
        pub(crate) meta: TokenMetadata<V, T, E>,
        pub(crate) payload: Vec<u8>,
        pub(crate) encoded_footer: Vec<u8>,
        pub(crate) footer: F,
    }

    impl<V: version::Version, T: purpose::Purpose, F, E: Payload> fmt::Display
        for SecuredToken<V, T, F, E>
    {
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

    impl<V: version::Version, K: purpose::Purpose, F, E: Payload> serde::Serialize
        for SecuredToken<V, K, F, E>
    {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.collect_str(self)
        }
    }

    impl<'de, V: version::Version, K: purpose::Purpose, F: Footer, E: Payload>
        serde::Deserialize<'de> for SecuredToken<V, K, F, E>
    {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            struct FromStrVisitor<V, T, F, E>(std::marker::PhantomData<(V, T, F, E)>);
            impl<'de, V: version::Version, K: purpose::Purpose, F: Footer, E: Payload>
                serde::de::Visitor<'de> for FromStrVisitor<V, K, F, E>
            {
                type Value = SecuredToken<V, K, F, E>;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    write!(
                        formatter,
                        "a \"{}.{}.\" paseto",
                        V::PASETO_HEADER,
                        K::HEADER,
                    )
                }
                fn visit_str<Err>(self, v: &str) -> Result<Self::Value, Err>
                where
                    Err: serde::de::Error,
                {
                    v.parse().map_err(Err::custom)
                }
            }
            deserializer.deserialize_str(FromStrVisitor(std::marker::PhantomData))
        }
    }

    impl<V: version::Version, T: purpose::Purpose, F: Footer, E: Payload> std::str::FromStr
        for SecuredToken<V, T, F, E>
    {
        type Err = PasetoError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let s = s
                .strip_prefix(V::PASETO_HEADER)
                .ok_or(PasetoError::InvalidToken)?;
            let s = s.strip_prefix(E::SUFFIX).ok_or(PasetoError::InvalidToken)?;
            let s = s.strip_prefix('.').ok_or(PasetoError::InvalidToken)?;
            let s = s.strip_prefix(T::HEADER).ok_or(PasetoError::InvalidToken)?;
            let s = s.strip_prefix('.').ok_or(PasetoError::InvalidToken)?;

            let (payload, footer) = match s.split_once('.') {
                Some((payload, footer)) => (payload, Some(footer)),
                None => (s, None),
            };

            let payload = base64ct::Base64UrlUnpadded::decode_vec(payload)
                .map_err(|_| PasetoError::Base64DecodeError)?;
            let encoded_footer = footer
                .map(base64ct::Base64UrlUnpadded::decode_vec)
                .transpose()
                .map_err(|_| PasetoError::Base64DecodeError)?
                .unwrap_or_default();
            let footer = F::decode(&encoded_footer).map_err(PasetoError::PayloadError)?;

            Ok(Self {
                meta: TokenMetadata::default(),
                payload,
                encoded_footer,
                footer,
            })
        }
    }

    impl<V, T, F, E> SecuredToken<V, T, F, E> {
        /// View the **unverified** footer for this token
        pub fn unverified_footer(&self) -> &F {
            &self.footer
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
/// Error returned for all PASETO and PASERK operations that can fail
pub enum PasetoError {
    /// The token was not Base64 URL encoded correctly.
    Base64DecodeError,
    /// Could not decode the provided key string
    InvalidKey,
    /// The PASETO or PASERK was not of a valid form
    InvalidToken,
    /// Could not verify/decrypt the PASETO/PASERK.
    CryptoError,
    /// There was an error with payload processing
    PayloadError(Box<dyn std::error::Error + Send + Sync>),
}

impl std::error::Error for PasetoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PasetoError::PayloadError(x) => Some(&**x),
            _ => None,
        }
    }
}

impl std::fmt::Display for PasetoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasetoError::Base64DecodeError => f.write_str("The token could not be base64 decoded"),
            PasetoError::InvalidKey => f.write_str("Could not parse the key"),
            PasetoError::InvalidToken => f.write_str("Could not parse the token"),
            PasetoError::CryptoError => f.write_str("Token signature could not be validated"),
            PasetoError::PayloadError(x) => {
                write!(f, "there was an error with the payload encoding: {x}")
            }
        }
    }
}

#[cfg(fuzzing)]
pub mod fuzzing {
    use rand::{CryptoRng, RngCore};

    use crate::purpose::local::{DecryptedToken, EncryptedToken, Local, LocalVersion};
    use crate::purpose::public::{Secret, SignedToken, UnsignedToken, VerifiedToken};
    use crate::version::{V3, V4};
    use crate::{
        key::{Key, KeyType},
        purpose::local::UnencryptedToken,
        version::Version,
        Json,
    };

    #[derive(Clone, Debug)]
    /// a consistent rng store
    pub struct FakeRng<const N: usize> {
        pub bytes: [u8; N],
        pub start: usize,
    }

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

    #[derive(Debug)]
    pub struct FuzzInput<V: Version, K: KeyType<V>> {
        key: Key<V, K>,
        ephemeral: FakeRng<32>,
        data1: String,
        data2: String,
        data3: String,
    }

    impl<'a, V: Version, K: KeyType<V>> arbitrary::Arbitrary<'a> for FuzzInput<V, K>
    where
        Key<V, K>: arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                key: u.arbitrary()?,
                ephemeral: u.arbitrary()?,
                data1: u.arbitrary()?,
                data2: u.arbitrary()?,
                data3: u.arbitrary()?,
            })
        }
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    struct Data {
        data: String,
    }

    impl<V: LocalVersion> FuzzInput<V, Local> {
        pub fn run(self) {
            let token = UnencryptedToken::<V, Data>::new(Data {
                data: self.data1.clone(),
            })
            .with_footer(Json(Data {
                data: self.data2.clone(),
            }))
            .encrypt_with_assertions_and_rng(&self.key, self.data3.as_bytes(), self.ephemeral)
            .unwrap();
            let token: EncryptedToken<V, Json<Data>> = token.to_string().parse().unwrap();
            assert_eq!(token.unverified_footer().0.data, self.data2);
            let token: DecryptedToken<V, Data, Json<Data>> = token
                .decrypt_with_assertions(&self.key, self.data3.as_bytes())
                .unwrap();
            assert_eq!(token.message.data, self.data1);
        }
    }
    impl FuzzInput<V3, Secret> {
        pub fn run(self) {
            let token = UnsignedToken::<V3, Data>::new(Data {
                data: self.data1.clone(),
            })
            .with_footer(Json(Data {
                data: self.data2.clone(),
            }))
            .sign_with_assertions(&self.key, self.data3.as_bytes())
            .unwrap();
            let token: SignedToken<V3, Json<Data>> = token.to_string().parse().unwrap();
            assert_eq!(token.unverified_footer().0.data, self.data2);
            let token: VerifiedToken<V3, Data, Json<Data>> = token
                .verify_with_assertions(&self.key.public_key(), self.data3.as_bytes())
                .unwrap();
            assert_eq!(token.message.data, self.data1);
        }
    }
    impl FuzzInput<V4, Secret> {
        pub fn run(self) {
            let token = UnsignedToken::<V4, Data>::new(Data {
                data: self.data1.clone(),
            })
            .with_footer(Json(Data {
                data: self.data2.clone(),
            }))
            .sign_with_assertions(&self.key, self.data3.as_bytes())
            .unwrap();
            let token: SignedToken<V4, Json<Data>> = token.to_string().parse().unwrap();
            assert_eq!(token.unverified_footer().0.data, self.data2);
            let token: VerifiedToken<V4, Data, Json<Data>> = token
                .verify_with_assertions(&self.key.public_key(), self.data3.as_bytes())
                .unwrap();
            assert_eq!(token.message.data, self.data1);
        }
    }
}
