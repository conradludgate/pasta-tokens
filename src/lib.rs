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
//!     k[version].[type].[data]
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
//! let local_key = Key::<V4, Local>::new_random();
//! let kid: KeyId<V4, Local> = local_key.into();
//! // kid.to_string() => "k4.lid.XxPub51WIAEmbVTmrs-lFoFodxTSKk8RuYEJk3gl-DYB"
//! ```
//!
//! You can also parse the KeyId from a string to have a smaller in memory representation. It can be safely shared and stored.
//!
//! ### Plaintext: `local`/`public`/`ssecret`
//!
//! The [`PlaintextKey`] type represents the base64 encoded plaintext key types.
//!
//! ```
//! use rusty_paserk::{Key, Local, PlaintextKey, V4};
//!
//! let local_key = Key::<V4, Local>::new_random();
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
//! See the [`SealedKey`] type for more info.
//!
//! ### Wrap `local-wrap`/`secret-wrap`
//!
//! Using a local key, you can wrap a local or a secret key. It can be unwrapped using the same local key.
//!
//! See the [`PieWrappedKey`] type for more info.
//!
//! ### Password wrapping `local-pw`/`secret-pw`
//!
//! Not currently supported

pub use rusty_paseto::core::{V3, V4};
pub use id::KeyId;
pub use key::{Key, KeyType, Local, PlaintextKey, Public, Secret, Version};
pub use pke::{SealedKey, SealedVersion};
pub use wrap::{PieVersion, PieWrappedKey, WrapType};

mod id;
// mod pbkw;
mod key;
mod pke;
mod wrap;
