use arbitrary::{Arbitrary, Result, Unstructured};

#[cfg(any(feature = "v3-local", feature = "v4-local"))]
use crate::purpose::local::Local;
#[cfg(any(feature = "v3-public", feature = "v4-public"))]
use crate::purpose::public::Secret;
#[cfg(any(feature = "v3-local", feature = "v3-public"))]
use crate::version::V3;
#[cfg(any(feature = "v4-local", feature = "v4-public"))]
use crate::version::V4;

#[cfg(feature = "v3-local")]
impl<'a> Arbitrary<'a> for super::Key<V3, Local> {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let key = <[u8; 32]>::arbitrary(u)?;
        Ok(Self {
            key: Box::new(key.into()),
        })
    }
}

#[cfg(feature = "v3-public")]
impl<'a> Arbitrary<'a> for super::Key<V3, Secret> {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let key = <[u8; 48]>::arbitrary(u)?;
        let key = Box::new(key.into());

        if p384::SecretKey::from_bytes(&key).is_err() {
            return Err(arbitrary::Error::IncorrectFormat);
        }

        Ok(Self { key })
    }
}

#[cfg(feature = "v4-local")]
impl<'a> Arbitrary<'a> for super::Key<V4, Local> {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let key = <[u8; 32]>::arbitrary(u)?;
        Ok(Self {
            key: Box::new(key.into()),
        })
    }
}

#[cfg(feature = "v4-public")]
impl<'a> Arbitrary<'a> for super::Key<V4, Secret> {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let key = <[u8; 32]>::arbitrary(u)?;
        Ok(Self {
            key: Box::new(
                ed25519_dalek::SigningKey::from_bytes(&key)
                    .to_keypair_bytes()
                    .into(),
            ),
        })
    }
}
