#[cfg(any(feature = "v3-local", feature = "v4-local"))]
use crate::purpose::local::Local;
#[cfg(any(feature = "v3-public", feature = "v4-public"))]
use crate::purpose::public::Secret;
#[cfg(any(feature = "v3-local", feature = "v3-public"))]
use crate::version::V3;
#[cfg(any(feature = "v4-local", feature = "v4-public"))]
use crate::version::V4;

#[cfg(feature = "v3-local")]
impl<'a> arbitrary::Arbitrary<'a> for super::Key<V3, Local> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let key = <[u8; 32]>::arbitrary(u)?;
        Ok(Self {
            key: Box::new(key.into()),
        })
    }
}

#[cfg(feature = "v3-public")]
impl<'a> arbitrary::Arbitrary<'a> for super::Key<V3, Secret> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let key = <[u8; 48]>::arbitrary(u)?;

        let key = p384::ecdsa::SigningKey::from_slice(&key)
            .map_err(|_| arbitrary::Error::IncorrectFormat)?;

        Ok(Self { key: Box::new(key) })
    }
}

#[cfg(feature = "v4-local")]
impl<'a> arbitrary::Arbitrary<'a> for super::Key<V4, Local> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let key = <[u8; 32]>::arbitrary(u)?;
        Ok(Self {
            key: Box::new(key.into()),
        })
    }
}

#[cfg(feature = "v4-public")]
impl<'a> arbitrary::Arbitrary<'a> for super::Key<V4, Secret> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let key = <[u8; 32]>::arbitrary(u)?;
        Ok(Self {
            key: Box::new(ed25519_dalek::SigningKey::from(key)),
        })
    }
}
