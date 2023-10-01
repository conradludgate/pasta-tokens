//! PASETO public signatures
//!
//! Example use cases:
//! * Transparent claims provided by a third party.
//!   + e.g. Authentication and authorization protocols (OAuth 2, OIDC).

mod impl_;

pub use impl_::*;

#[cfg(feature = "v4-public")]
mod v4;

#[cfg(feature = "v3-public")]
mod v3;

/// PASETO public signatures
///
/// Example use cases:
/// * Transparent claims provided by a third party.
///   + e.g. Authentication and authorization protocols (OAuth 2, OIDC).
#[derive(Debug, Default)]
pub struct Public;

/// Secret signing/decrypting keys
#[derive(Debug)]
pub struct Secret;

impl super::Purpose for Public {
    const HEADER: &'static str = "public";
}

/// A public key for verifying `public` tokens
pub type PublicKey<V> = crate::key::Key<V, Public>;
/// A secret key for signing `public` tokens
pub type SecretKey<V> = crate::key::Key<V, Secret>;

/// A Verified PASETO that has been parsed and verified
pub type VerifiedToken<V, M, F = (), E = crate::Json<()>> =
    crate::tokens::ValidatedToken<V, Public, M, F, E>;

/// A Signed PASETO.
pub type SignedToken<V, F = (), E = crate::Json<()>> = crate::tokens::SecuredToken<V, Public, F, E>;

/// A PASETO that is ready to be signed.
pub type UnsignedToken<V, M, F = (), E = crate::Json<()>> =
    crate::tokens::TokenBuilder<V, Public, M, F, E>;

impl<V: PublicVersion> crate::key::KeyType<V> for Public {
    type KeyLen = V::PublicKeySize;
    const KEY_HEADER: &'static str = "public.";
    const ID: &'static str = "pid.";
}

impl<V: PublicVersion> crate::key::KeyType<V> for Secret {
    type KeyLen = V::SecretKeySize;
    const KEY_HEADER: &'static str = "secret.";
    const ID: &'static str = "sid.";
}
