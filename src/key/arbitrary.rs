use arbitrary::{Arbitrary, Result, Unstructured};

#[cfg_attr(docsrs, doc(cfg(feature = "arbitrary")))]
#[cfg(feature = "v3")]
impl<'a> Arbitrary<'a> for super::Key<super::V3, super::Local> {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let key = <[u8; 32]>::arbitrary(u)?;
        Ok(Self { key: key.into() })
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "arbitrary")))]
#[cfg(feature = "v3")]
impl<'a> Arbitrary<'a> for super::Key<super::V3, super::Secret> {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let key = <[u8; 48]>::arbitrary(u)?;
        let key = key.into();

        if p384::SecretKey::from_bytes(&key).is_err() {
            return Err(arbitrary::Error::IncorrectFormat);
        }

        Ok(Self { key })
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "arbitrary")))]
#[cfg(feature = "v4")]
impl<'a> Arbitrary<'a> for super::Key<super::V4, super::Local> {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let key = <[u8; 32]>::arbitrary(u)?;
        Ok(Self { key: key.into() })
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "arbitrary")))]
#[cfg(feature = "v4")]
impl<'a> Arbitrary<'a> for super::Key<super::V4, super::Secret> {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let key = <[u8; 32]>::arbitrary(u)?;
        Ok(Self {
            key: ed25519_dalek::SigningKey::from_bytes(&key)
                .to_keypair_bytes()
                .into(),
        })
    }
}
