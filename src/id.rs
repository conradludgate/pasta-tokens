//! This operation calculates the unique ID for a given PASERK.
//!
//! <https://github.com/paseto-standard/paserk/blob/master/operations/ID.md>
//!
//! # Local IDs
//! ```
//! use rusty_paserk::id::EncodeId;
//! use rusty_paseto::core::{PasetoSymmetricKey, V4, Local, Key};
//!
//! let local_key = PasetoSymmetricKey::<V4, Local>::from(Key::try_new_random().unwrap());
//! let kid = local_key.encode_id();
//! // => "k4.lid.XxPub51WIAEmbVTmrs-lFoFodxTSKk8RuYEJk3gl-DYB"
//! ```
//!
//! # Secret IDs
//! ```
//! use rusty_paserk::id::EncodeId;
//! use rusty_paseto::core::{PasetoAsymmetricPrivateKey, V4, Public, Key};
//!
//! let secret_key = Key::try_new_random().unwrap();
//! let secret_key = PasetoAsymmetricPrivateKey::<V4, Public>::from(&secret_key);
//! let kid = secret_key.encode_id();
//! // => "k4.sid.p26RNihDPsk2QbglGMTmwMMqLYyeLY25UOQZXQDXwn61"
//! ```
//!
//! # Public IDs
//! ```
//! use rusty_paserk::id::EncodeId;
//! use rusty_paseto::core::{PasetoAsymmetricPublicKey, V4, Public, Key};
//!
//! let public_key = Key::try_new_random().unwrap();
//! let public_key = PasetoAsymmetricPublicKey::<V4, Public>::from(&public_key);
//! let kid = public_key.encode_id();
//! // => "k4.pid.yMgldRRLHBLkhmcp8NG8yZrtyldbYoAjQWPv_Ma1rzRu"
//! ```
use std::io::Write;

use base64::{write::EncoderStringWriter, URL_SAFE_NO_PAD};
use generic_array::typenum::U33;

#[cfg(feature = "v1")]
use rusty_paseto::core::V1;
#[cfg(feature = "v2")]
use rusty_paseto::core::V2;
#[cfg(feature = "v3")]
use rusty_paseto::core::V3;
#[cfg(feature = "v4")]
use rusty_paseto::core::V4;

/// Key ID encodings <https://github.com/paseto-standard/paserk/blob/master/operations/ID.md>
pub trait EncodeId {
    /// encode the key into it's key id
    fn encode_id(&self) -> String;
}

#[cfg(feature = "local")]
/// local-id <https://github.com/paseto-standard/paserk/blob/master/types/lid.md>
mod local {
    use rusty_paseto::core::{Local, PasetoSymmetricKey};

    use super::*;

    #[cfg(feature = "v1")]
    impl EncodeId for PasetoSymmetricKey<V1, Local> {
        fn encode_id(&self) -> String {
            encode_v1_v3("k1.lid.", self.as_ref())
        }
    }

    #[cfg(feature = "v2")]
    impl EncodeId for PasetoSymmetricKey<V2, Local> {
        fn encode_id(&self) -> String {
            encode_v2_v4("k2.lid.", self.as_ref())
        }
    }

    #[cfg(feature = "v3")]
    impl EncodeId for PasetoSymmetricKey<V3, Local> {
        fn encode_id(&self) -> String {
            encode_v1_v3("k3.lid.", self.as_ref())
        }
    }

    #[cfg(feature = "v4")]
    impl EncodeId for PasetoSymmetricKey<V4, Local> {
        fn encode_id(&self) -> String {
            encode_v2_v4("k4.lid.", self.as_ref())
        }
    }
}

#[cfg(feature = "public")]
/// public-id <https://github.com/paseto-standard/paserk/blob/master/types/pid.md>
/// secret-id <https://github.com/paseto-standard/paserk/blob/master/types/sid.md>
mod public {
    use rusty_paseto::core::{PasetoAsymmetricPrivateKey, PasetoAsymmetricPublicKey, Public};

    use super::*;

    #[cfg(feature = "v1")]
    impl EncodeId for PasetoAsymmetricPrivateKey<'_, V1, Public> {
        fn encode_id(&self) -> String {
            encode_v1_v3("k1.sid.", self.as_ref())
        }
    }

    #[cfg(feature = "v2")]
    impl EncodeId for PasetoAsymmetricPrivateKey<'_, V2, Public> {
        fn encode_id(&self) -> String {
            encode_v2_v4("k2.sid.", self.as_ref())
        }
    }

    #[cfg(feature = "v3")]
    impl EncodeId for PasetoAsymmetricPrivateKey<'_, V3, Public> {
        fn encode_id(&self) -> String {
            encode_v1_v3("k3.sid.", self.as_ref())
        }
    }

    #[cfg(feature = "v4")]
    impl EncodeId for PasetoAsymmetricPrivateKey<'_, V4, Public> {
        fn encode_id(&self) -> String {
            encode_v2_v4("k4.sid.", self.as_ref())
        }
    }

    #[cfg(feature = "v1")]
    impl EncodeId for PasetoAsymmetricPublicKey<'_, V1, Public> {
        fn encode_id(&self) -> String {
            encode_v1_v3("k1.pid.", self.as_ref())
        }
    }

    #[cfg(feature = "v2")]
    impl EncodeId for PasetoAsymmetricPublicKey<'_, V2, Public> {
        fn encode_id(&self) -> String {
            encode_v2_v4("k2.pid.", self.as_ref())
        }
    }

    #[cfg(feature = "v3")]
    impl EncodeId for PasetoAsymmetricPublicKey<'_, V3, Public> {
        fn encode_id(&self) -> String {
            encode_v1_v3("k3.pid.", self.as_ref())
        }
    }

    #[cfg(feature = "v4")]
    impl EncodeId for PasetoAsymmetricPublicKey<'_, V4, Public> {
        fn encode_id(&self) -> String {
            encode_v2_v4("k4.pid.", self.as_ref())
        }
    }
}

/// V1 and V3 keys use the same encoding
/// <https://github.com/paseto-standard/paserk/blob/master/operations/ID.md#versions-1-and-3>
#[cfg(any(feature = "v1", feature = "v3"))]
fn encode_v1_v3(header: &str, key: &[u8]) -> String {
    use sha2::digest::Digest;

    let mut derive_d = sha2::Sha384::new();
    derive_d.update(header);
    derive_d.update(key);
    let d = derive_d.finalize();
    let d = &d[..33];

    let mut enc = EncoderStringWriter::from(header.to_owned(), URL_SAFE_NO_PAD);
    enc.write_all(d).unwrap();
    enc.into_inner()
}

/// V2 and V4 keys use the same encoding
/// <https://github.com/paseto-standard/paserk/blob/master/operations/ID.md#versions-2-and-4>
#[cfg(any(feature = "v2", feature = "v4"))]
fn encode_v2_v4(header: &str, key: &[u8]) -> String {
    use blake2::digest::Digest;

    let mut derive_d = blake2::Blake2b::<U33>::new();
    derive_d.update(header);
    derive_d.update(key);
    let d = derive_d.finalize();

    let mut enc = EncoderStringWriter::from(header.to_owned(), URL_SAFE_NO_PAD);
    enc.write_all(&d).unwrap();
    enc.into_inner()
}
