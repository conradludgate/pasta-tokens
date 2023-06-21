use std::io::Write;

use base64::{decode_config_slice, write::EncoderStringWriter};
use rusty_paseto::core::PasetoError;
#[cfg(feature = "v1")]
use rusty_paseto::core::V1;
#[cfg(feature = "v2")]
use rusty_paseto::core::V2;
#[cfg(feature = "v3")]
use rusty_paseto::core::V3;
#[cfg(feature = "v4")]
use rusty_paseto::core::V4;

/// Key encodings
pub trait EncodeKey: Sized {
    fn encode_key(&self) -> String;

    fn decode_key(key: &str) -> Result<Self, PasetoError>;
}

#[cfg(feature = "local")]
/// local <https://github.com/paseto-standard/paserk/blob/master/types/local.md>
mod local {
    use rusty_paseto::core::{Key, Local, PasetoSymmetricKey};

    use super::*;

    #[cfg(feature = "v1")]
    impl EncodeKey for PasetoSymmetricKey<V1, Local> {
        fn encode_key(&self) -> String {
            encode_b64("k1.local.", self.as_ref())
        }
        fn decode_key(key: &str) -> Result<Self, PasetoError> {
            decode_b64("k1.local.", key)
                .map(Key::from)
                .map(PasetoSymmetricKey::from)
        }
    }

    #[cfg(feature = "v2")]
    impl EncodeKey for PasetoSymmetricKey<V2, Local> {
        fn encode_key(&self) -> String {
            encode_b64("k2.local.", self.as_ref())
        }
        fn decode_key(key: &str) -> Result<Self, PasetoError> {
            decode_b64("k2.local.", key)
                .map(Key::from)
                .map(PasetoSymmetricKey::from)
        }
    }

    #[cfg(feature = "v3")]
    impl EncodeKey for PasetoSymmetricKey<V3, Local> {
        fn encode_key(&self) -> String {
            encode_b64("k3.local.", self.as_ref())
        }
        fn decode_key(key: &str) -> Result<Self, PasetoError> {
            decode_b64("k3.local.", key)
                .map(Key::from)
                .map(PasetoSymmetricKey::from)
        }
    }

    #[cfg(feature = "v4")]
    impl EncodeKey for PasetoSymmetricKey<V4, Local> {
        fn encode_key(&self) -> String {
            encode_b64("k4.local.", self.as_ref())
        }
        fn decode_key(key: &str) -> Result<Self, PasetoError> {
            decode_b64("k4.local.", key)
                .map(Key::from)
                .map(PasetoSymmetricKey::from)
        }
    }
}

fn encode_b64(header: &str, key: &[u8]) -> String {
    let mut enc = EncoderStringWriter::from(header.to_owned(), base64::URL_SAFE_NO_PAD);
    enc.write_all(key).unwrap();
    enc.into_inner()
}

fn decode_b64(header: &str, key: &str) -> Result<[u8; 32], PasetoError> {
    let key = key.strip_prefix(header).ok_or(PasetoError::WrongHeader)?;
    let mut output = [0; 32];
    if decode_config_slice(key, base64::URL_SAFE_NO_PAD, &mut output)? < 32 {
        return Err(PasetoError::InvalidKey);
    }
    Ok(output)
}
