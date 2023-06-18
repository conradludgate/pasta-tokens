//! Key ID encodings
//!
//! <https://github.com/paseto-standard/paserk/blob/master/operations/ID.md>

use std::io::Write;

use base64::{engine::general_purpose, write::EncoderStringWriter};
use generic_array::typenum::U33;

#[cfg(feature = "v1")]
use rusty_paseto::prelude::V1;
#[cfg(feature = "v2")]
use rusty_paseto::prelude::V2;
#[cfg(feature = "v3")]
use rusty_paseto::prelude::V3;
#[cfg(feature = "v4")]
use rusty_paseto::prelude::V4;

/// Key ID encodings <https://github.com/paseto-standard/paserk/blob/master/operations/ID.md>
pub trait EncodeId {
    /// encode the key into it's key id
    fn encode_id(&self) -> String;
}

#[cfg(feature = "local")]
/// local-id <https://github.com/paseto-standard/paserk/blob/master/types/lid.md>
mod local {
    use rusty_paseto::prelude::{Local, PasetoSymmetricKey};

    use super::*;

    #[cfg(feature = "v1")]
    impl EncodeId for PasetoSymmetricKey<V3, Local> {
        fn encode_id(&self) -> String {
            encode_v1_v3("k1.lid.", self.as_ref())
        }
    }

    #[cfg(feature = "v2")]
    impl EncodeId for PasetoSymmetricKey<V4, Local> {
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
    use rusty_paseto::prelude::{PasetoAsymmetricPrivateKey, PasetoAsymmetricPublicKey, Public};

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

    let mut enc = EncoderStringWriter::from_consumer(header.to_owned(), &general_purpose::URL_SAFE);
    enc.write_all(header.as_bytes()).unwrap();
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

    let mut enc = EncoderStringWriter::from_consumer(header.to_owned(), &general_purpose::URL_SAFE);
    enc.write_all(header.as_bytes()).unwrap();
    enc.write_all(&d).unwrap();
    enc.into_inner()
}
