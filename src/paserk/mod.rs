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

use base64ct::Encoding;
use cipher::Unsigned;

use crate::PasetoError;

#[cfg(feature = "id")]
pub mod id;
#[cfg(feature = "pbkw")]
pub mod pbkw;
#[cfg(feature = "pke")]
pub mod pke;
pub mod plaintext;
#[cfg(feature = "wrap")]
pub mod wrap;

/// Whether the key serialization is safe to be added to a PASETO footer.
pub trait SafeForFooter {}

fn write_b64<W: std::fmt::Write>(b: &[u8], w: &mut W) -> std::fmt::Result {
    let mut buffer = [0; 64];
    for chunk in b.chunks(48) {
        let s = base64ct::Base64UrlUnpadded::encode(chunk, &mut buffer).unwrap();
        w.write_str(s)?;
    }
    Ok(())
}

fn read_b64<
    L: generic_array::sequence::GenericSequence<u8> + core::ops::DerefMut<Target = [u8]> + Default,
>(
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
