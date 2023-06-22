use cipher::Unsigned;
use generic_array::GenericArray;
use rand::{rngs::OsRng, CryptoRng, RngCore};
use rusty_paseto::core::PasetoError;

#[cfg(feature = "v3")]
use rusty_paseto::core::V3;
#[cfg(feature = "v4")]
use rusty_paseto::core::V4;

use crate::{Key, KeyType, Local, Public, Secret, Version};

#[cfg(feature = "v3")]
impl Key<V3, Secret> {
    /// Decode a PEM encoded SEC1 Ed25519 Secret Key
    ///
    /// ```
    /// use rusty_paserk::Key;
    ///
    /// let private_key = "-----BEGIN EC PRIVATE KEY-----
    /// MIGkAgEBBDAhUb6WGhABE1MTj0x7E/5acgyap23kh7hUAVoAavKyfhYcmI3n1Q7L
    /// JpHxNb792H6gBwYFK4EEACKhZANiAAT5H7mTSOyjfILDtSuavZfalI3doM8pRUlb
    /// TzNyYLqM9iVmajpc0JRXvKuBtGtYi7Yft+eqFr6BuzGrdb4Z1vkvRcI504m0qKiE
    /// zjhi6u4sNgzW23rrVkRYkb2oE3SJPko=
    /// -----END EC PRIVATE KEY-----";
    ///
    /// let _key = Key::from_sec1_pem(private_key).unwrap();
    /// ```
    pub fn from_sec1_pem(s: &str) -> Result<Self, PasetoError> {
        let sk = p384::SecretKey::from_sec1_pem(s).map_err(|_| PasetoError::Cryption)?;
        Ok(Self { key: sk.to_bytes() })
    }
}

#[cfg(feature = "v3")]
impl Key<V3, Public> {
    /// Decode a PEM encoded Ed25519 Public Key
    ///
    /// ```
    /// use rusty_paserk::Key;
    ///
    /// let public_key = "-----BEGIN PUBLIC KEY-----
    /// MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+R+5k0jso3yCw7Urmr2X2pSN3aDPKUVJ
    /// W08zcmC6jPYlZmo6XNCUV7yrgbRrWIu2H7fnqha+gbsxq3W+Gdb5L0XCOdOJtKio
    /// hM44YuruLDYM1tt661ZEWJG9qBN0iT5K
    /// -----END PUBLIC KEY-----";
    ///
    /// let _key = Key::from_public_key_pem(public_key).unwrap();
    /// ```
    pub fn from_public_key_pem(s: &str) -> Result<Self, PasetoError> {
        use p384::{pkcs8::DecodePublicKey, EncodedPoint};

        let pk = p384::PublicKey::from_public_key_pem(s).map_err(|_| PasetoError::Cryption)?;
        let pk: EncodedPoint = pk.into();
        let pk = pk.compress();
        let pk = pk.as_bytes();

        Ok(Self {
            key: *GenericArray::from_slice(pk),
        })
    }
}

impl<V: Version, K: KeyType<V>> TryFrom<&[u8]> for Key<V, K> {
    type Error = PasetoError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != <K::KeyLen as Unsigned>::USIZE {
            return Err(PasetoError::IncorrectSize);
        }
        let mut key: GenericArray<u8, K::KeyLen> = Default::default();
        key.copy_from_slice(value);
        Ok(Key { key })
    }
}

#[cfg(feature = "v3")]
impl From<[u8; 32]> for Key<V3, Local> {
    fn from(key: [u8; 32]) -> Self {
        Self { key: key.into() }
    }
}

#[cfg(feature = "v3")]
impl TryFrom<[u8; 48]> for Key<V3, Secret> {
    type Error = PasetoError;
    fn try_from(key: [u8; 48]) -> Result<Self, Self::Error> {
        use p384::SecretKey;
        let key = key.into();
        if SecretKey::from_bytes(&key).is_err() {
            Err(PasetoError::InvalidKey)
        } else {
            Ok(Self { key })
        }
    }
}

#[cfg(feature = "v3")]
impl Key<V3, Secret> {
    /// Get the corresponding V3 public key for this V3 secret key
    pub fn public_key(&self) -> Key<V3, Public> {
        use p384::{EncodedPoint, SecretKey};

        let sk = SecretKey::from_bytes(&self.key).unwrap();
        let pk: EncodedPoint = sk.public_key().into();
        let pk = pk.compress();
        let pk = pk.as_bytes();
        Key {
            key: *GenericArray::from_slice(pk),
        }
    }
}

#[cfg(feature = "v4")]
impl TryFrom<[u8; 64]> for Key<V4, Secret> {
    type Error = PasetoError;
    fn try_from(key: [u8; 64]) -> Result<Self, Self::Error> {
        use ed25519_dalek::SigningKey;
        match SigningKey::from_keypair_bytes(&key) {
            Ok(_) => {}
            Err(_) => return Err(PasetoError::InvalidKey),
        };
        Ok(Key { key: key.into() })
    }
}

#[cfg(feature = "v4")]
impl Key<V4, Secret> {
    /// Get the corresponding V4 public key for this V4 secret key
    pub fn public_key(&self) -> Key<V4, Public> {
        use generic_array::sequence::Split;
        let (_sk, pk): (
            GenericArray<u8, generic_array::typenum::U32>,
            GenericArray<u8, generic_array::typenum::U32>,
        ) = self.key.split();
        Key { key: pk }
    }
}

impl<V: Version, K: KeyType<V>> AsRef<[u8]> for Key<V, K> {
    fn as_ref(&self) -> &[u8] {
        &self.key
    }
}

impl<V: Version> Key<V, Local> {
    /// Generate a random local key using OS random
    pub fn new_os_random() -> Self {
        Self::new_random(&mut OsRng)
    }

    /// Generate a random local key using the provided random source
    pub fn new_random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut key = GenericArray::<u8, V::Local>::default();
        rng.fill_bytes(&mut key);
        Self { key }
    }
}

#[cfg(feature = "v4")]
impl Key<V4, Secret> {
    /// Generate a random V4 secret key using OS random
    pub fn new_os_random() -> Self {
        Self::new_random(&mut OsRng)
    }

    /// Generate a random V4 secret key using the provided random source
    pub fn new_random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut key = [0; 32];
        rng.fill_bytes(&mut key);
        Self {
            key: ed25519_dalek::SigningKey::from_bytes(&key)
                .to_keypair_bytes()
                .into(),
        }
    }
}

#[cfg(feature = "v3")]
impl Key<V3, Secret> {
    /// Generate a random V3 secret key using OS random
    pub fn new_os_random() -> Self {
        Self::new_random(&mut OsRng)
    }

    /// Generate a random V3 secret key using the provided random source
    pub fn new_random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self {
            key: p384::SecretKey::random(rng).to_bytes(),
        }
    }
}

#[cfg(feature = "v4")]
impl From<Key<V4, Local>>
    for rusty_paseto::core::PasetoSymmetricKey<V4, rusty_paseto::core::Local>
{
    fn from(key: Key<V4, Local>) -> Self {
        let key: [u8; 32] = key.key.into();
        let key: rusty_paseto::core::Key<32> = key.into();
        key.into()
    }
}

#[cfg(feature = "v3")]
impl From<Key<V3, Local>>
    for rusty_paseto::core::PasetoSymmetricKey<V3, rusty_paseto::core::Local>
{
    fn from(key: Key<V3, Local>) -> Self {
        let key: [u8; 32] = key.key.into();
        let key: rusty_paseto::core::Key<32> = key.into();
        key.into()
    }
}

#[cfg(feature = "v4")]
impl From<Key<V4, Public>> for rusty_paseto::core::Key<32> {
    fn from(key: Key<V4, Public>) -> Self {
        let key: [u8; 32] = key.key.into();
        key.into()
    }
}

#[cfg(feature = "v4")]
impl From<Key<V4, Secret>> for rusty_paseto::core::Key<64> {
    fn from(key: Key<V4, Secret>) -> Self {
        let key: [u8; 64] = key.key.into();
        key.into()
    }
}

#[cfg(feature = "v3")]
impl From<Key<V3, Public>> for rusty_paseto::core::Key<49> {
    fn from(key: Key<V3, Public>) -> Self {
        let key: [u8; 49] = key.key.into();
        key.into()
    }
}

#[cfg(feature = "v3")]
impl From<Key<V3, Secret>> for rusty_paseto::core::Key<48> {
    fn from(key: Key<V3, Secret>) -> Self {
        let key: [u8; 48] = key.key.into();
        key.into()
    }
}
