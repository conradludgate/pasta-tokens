use crate::version::Version;

use super::{Key, KeyType};

use generic_array::GenericArray;
use rand::{rngs::OsRng, CryptoRng, RngCore};

#[cfg(feature = "v3-public")]
impl crate::purpose::public::SecretKey<crate::version::V3> {
    /// Decode a PEM encoded SEC1 p384 Secret Key
    ///
    /// ```
    /// use pasta_tokens::key::Key;
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
    pub fn from_sec1_pem(s: &str) -> Result<Self, crate::PasetoError> {
        let sk = p384::SecretKey::from_sec1_pem(s).map_err(|_| crate::PasetoError::InvalidKey)?;
        Ok(Self {
            key: Box::new(sk.into()),
        })
    }

    /// Decode a secret key from raw bytes
    pub fn from_bytes(s: &[u8]) -> Result<Self, crate::PasetoError> {
        let sk =
            p384::ecdsa::SigningKey::from_slice(s).map_err(|_| crate::PasetoError::InvalidKey)?;
        Ok(Self { key: Box::new(sk) })
    }

    /// Get the corresponding V3 public key for this V3 secret key
    pub fn public_key(&self) -> crate::purpose::public::PublicKey<crate::version::V3> {
        Key {
            key: Box::new(*self.key.verifying_key()),
        }
    }
}

#[cfg(feature = "v3-public")]
impl crate::purpose::public::PublicKey<crate::version::V3> {
    /// Decode a PEM encoded p384 Public Key
    ///
    /// ```
    /// use pasta_tokens::key::Key;
    ///
    /// let public_key = "-----BEGIN PUBLIC KEY-----
    /// MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+R+5k0jso3yCw7Urmr2X2pSN3aDPKUVJ
    /// W08zcmC6jPYlZmo6XNCUV7yrgbRrWIu2H7fnqha+gbsxq3W+Gdb5L0XCOdOJtKio
    /// hM44YuruLDYM1tt661ZEWJG9qBN0iT5K
    /// -----END PUBLIC KEY-----";
    ///
    /// let _key = Key::from_public_key_pem(public_key).unwrap();
    /// ```
    pub fn from_public_key_pem(s: &str) -> Result<Self, crate::PasetoError> {
        use p384::pkcs8::DecodePublicKey;

        let pk = p384::ecdsa::VerifyingKey::from_public_key_pem(s)
            .map_err(|_| crate::PasetoError::InvalidKey)?;

        Ok(Self { key: Box::new(pk) })
    }

    /// Decode a public key from raw bytes
    pub fn from_sec1_bytes(s: &[u8]) -> Result<Self, crate::PasetoError> {
        let pk = p384::ecdsa::VerifyingKey::from_sec1_bytes(s)
            .map_err(|_| crate::PasetoError::InvalidKey)?;

        Ok(Self { key: Box::new(pk) })
    }
}

#[cfg(feature = "v4-public")]
impl crate::purpose::public::SecretKey<crate::version::V4> {
    /// Decode an Ed25519 Secret Keypair
    ///
    /// ```
    /// use pasta_tokens::key::Key;
    ///
    /// let private_key = "407796f4bc4b8184e9fe0c54b336822d34823092ad873d87ba14c3efb9db8c1db7715bd661458d928654d3e832f53ff5c9480542e0e3d4c9b032c768c7ce6023";
    /// let private_key = hex::decode(&private_key).unwrap();
    ///
    /// let _key = Key::from_keypair_bytes(&private_key).unwrap();
    /// ```
    pub fn from_keypair_bytes(key: &[u8]) -> Result<Self, crate::PasetoError> {
        use ed25519_dalek::SigningKey;
        let key: [u8; 64] = key.try_into().map_err(|_| crate::PasetoError::InvalidKey)?;
        let key =
            SigningKey::from_keypair_bytes(&key).map_err(|_| crate::PasetoError::InvalidKey)?;
        Ok(Key { key: Box::new(key) })
    }

    /// Create a new secret key from the byte array
    ///
    /// ```
    /// use pasta_tokens::key::Key;
    ///
    /// let private_key = "407796f4bc4b8184e9fe0c54b336822d34823092ad873d87ba14c3efb9db8c1d";
    /// let private_key = hex::decode(&private_key).unwrap();
    /// let private_key: [u8; 32] = private_key.try_into().unwrap();
    ///
    /// let _key = Key::from_secret_key(private_key);
    /// ```
    pub fn from_secret_key(key: [u8; 32]) -> Self {
        Self {
            key: Box::new(ed25519_dalek::SigningKey::from_bytes(&key)),
        }
    }

    /// Get the corresponding V4 public key for this V4 secret key
    pub fn public_key(&self) -> crate::purpose::public::PublicKey<crate::version::V4> {
        Key {
            key: Box::new(self.key.verifying_key()),
        }
    }
}

#[cfg(feature = "v4-public")]
impl crate::purpose::public::PublicKey<crate::version::V4> {
    /// Decode a PEM encoded SEC1 Ed25519 Secret Key
    ///
    /// ```
    /// use pasta_tokens::key::Key;
    ///
    /// let public_key = "b7715bd661458d928654d3e832f53ff5c9480542e0e3d4c9b032c768c7ce6023";
    /// let public_key = hex::decode(&public_key).unwrap();
    ///
    /// let _key = Key::from_public_key(&public_key);
    /// ```
    pub fn from_public_key(key: &[u8]) -> Result<Self, crate::PasetoError> {
        let key = key.try_into().map_err(|_| crate::PasetoError::InvalidKey)?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&key)
            .map_err(|_| crate::PasetoError::InvalidKey)?;

        Ok(Self { key: Box::new(key) })
    }
}

impl<V: Version, K: KeyType<V>> Key<V, K> {
    /// Get the raw bytes from this key
    pub fn to_bytes(&self) -> GenericArray<u8, K::KeyLen> {
        K::to_bytes(&self.key)
    }
}

#[cfg(feature = "v3-local")]
impl crate::purpose::local::SymmetricKey<crate::version::V3> {
    /// Create a V3 local key from raw bytes
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self {
            key: Box::new(key.into()),
        }
    }
}

#[cfg(feature = "v4-local")]
impl crate::purpose::local::SymmetricKey<crate::version::V4> {
    /// Create a V4 local key from raw bytes
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self {
            key: Box::new(key.into()),
        }
    }
}

impl<V: crate::purpose::local::LocalVersion> crate::purpose::local::SymmetricKey<V> {
    /// Generate a random local key using OS random
    pub fn new_os_random() -> Self {
        Self::new_random(&mut OsRng)
    }

    /// Generate a random local key using the provided random source
    pub fn new_random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut key = generic_array::GenericArray::<u8, V::KeySize>::default();
        rng.fill_bytes(&mut key);
        Self { key: Box::new(key) }
    }
}

#[cfg(feature = "v4-public")]
impl crate::purpose::public::SecretKey<crate::version::V4> {
    /// Generate a random V4 secret key using OS random
    pub fn new_os_random() -> Self {
        Self::new_random(&mut OsRng)
    }

    /// Generate a random V4 secret key using the provided random source
    pub fn new_random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut key = [0; 32];
        rng.fill_bytes(&mut key);
        Self {
            key: Box::new(ed25519_dalek::SigningKey::from_bytes(&key)),
        }
    }
}

#[cfg(feature = "v3-public")]
impl crate::purpose::public::SecretKey<crate::version::V3> {
    /// Generate a random V3 secret key using OS random
    pub fn new_os_random() -> Self {
        Self::new_random(&mut OsRng)
    }

    /// Generate a random V3 secret key using the provided random source
    pub fn new_random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self {
            key: Box::new(p384::ecdsa::SigningKey::random(rng)),
        }
    }
}
