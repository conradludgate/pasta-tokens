//! PKE (Public-Key Encryption).
//! PASERK uses Public-Key encryption to wrap symmetric keys for use in local tokens.
//!
//! <https://github.com/paseto-standard/paserk/blob/master/operations/PKE.md>

use std::io::Write;

use base64::{write::EncoderStringWriter, URL_SAFE_NO_PAD};
use blake2::{Blake2b, Blake2bMac, Digest};
use chacha20::XChaCha20;
use cipher::{inout::InOutBuf, KeyIvInit, StreamCipher};
use digest::Mac;
use generic_array::typenum::{U24, U32};
use rand::rngs::OsRng;
use rusty_paseto::core::{
    Key, Local, PasetoAsymmetricPrivateKey, PasetoAsymmetricPublicKey, PasetoError,
    PasetoSymmetricKey, Public,
};
use sha2::Sha512;
use subtle::ConstantTimeEq;

// #[cfg(feature = "v1")]
// use rusty_paseto::core::V1;
#[cfg(feature = "v2")]
use rusty_paseto::core::V2;
// #[cfg(feature = "v3")]
// use rusty_paseto::core::V3;
#[cfg(feature = "v4")]
use rusty_paseto::core::V4;

pub trait Seal {
    type Version;

    fn seal(&self, ptk: &PasetoSymmetricKey<Self::Version, Local>) -> String;
}

pub trait Unseal {
    type Version;

    fn unseal(&self, key: &str) -> Result<PasetoSymmetricKey<Self::Version, Local>, PasetoError>;
}

#[cfg(feature = "v2")]
impl Seal for PasetoAsymmetricPublicKey<'_, V2, Public> {
    type Version = V2;

    fn seal(&self, ptk: &PasetoSymmetricKey<Self::Version, Local>) -> String {
        let h = "k2.seal.";
        seal(
            h,
            self.as_ref()
                .try_into()
                .expect("V2 public keys are 32 bytes"),
            ptk.as_ref()
                .try_into()
                .expect("V2 symmetric keys are 32 bytes"),
        )
    }
}

#[cfg(feature = "v2")]
impl Unseal for PasetoAsymmetricPrivateKey<'_, V2, Public> {
    type Version = V2;

    fn unseal(&self, key: &str) -> Result<PasetoSymmetricKey<Self::Version, Local>, PasetoError> {
        let h = "k2.seal.";
        unseal(
            h,
            self.as_ref()
                .try_into()
                .expect("V2 secret keys are 64 bytes"),
            key,
        )
        .map(PasetoSymmetricKey::from)
    }
}

#[cfg(feature = "v4")]
impl Seal for PasetoAsymmetricPublicKey<'_, V4, Public> {
    type Version = V4;

    fn seal(&self, ptk: &PasetoSymmetricKey<Self::Version, Local>) -> String {
        let h = "k4.seal.";
        seal(
            h,
            self.as_ref()
                .try_into()
                .expect("V4 public keys are 32 bytes"),
            ptk.as_ref()
                .try_into()
                .expect("V4 symmetric keys are 32 bytes"),
        )
    }
}

#[cfg(feature = "v4")]
impl Unseal for PasetoAsymmetricPrivateKey<'_, V4, Public> {
    type Version = V4;

    fn unseal(&self, key: &str) -> Result<PasetoSymmetricKey<Self::Version, Local>, PasetoError> {
        let h = "k4.seal.";
        unseal(
            h,
            self.as_ref()
                .try_into()
                .expect("V4 secret keys are 64 bytes"),
            key,
        )
        .map(PasetoSymmetricKey::from)
    }
}

fn seal(h: &str, pk: [u8; 32], ptk: [u8; 32]) -> String {
    // Given a plaintext data key (pdk), and an Ed25519 public key (pk).
    let pk = curve25519_dalek::edwards::CompressedEdwardsY::from_slice(&pk).unwrap();

    // step 1: Calculate the birationally-equivalent X25519 public key (xpk) from pk.
    // I wish the edwards point/montgomery point types were exposed by x/ed25519 libraries
    let xpk: x25519_dalek::PublicKey = pk.decompress().unwrap().to_montgomery().0.into();

    let esk = x25519_dalek::EphemeralSecret::random_from_rng(OsRng);
    let epk = x25519_dalek::PublicKey::from(&esk);

    let xk = esk.diffie_hellman(&xpk);

    let ek = Blake2b::<U32>::new()
        .chain_update([0x01])
        .chain_update(h.as_bytes())
        .chain_update(xk.as_bytes())
        .chain_update(epk.as_bytes())
        .chain_update(xpk.as_bytes())
        .finalize();

    let ak = Blake2b::<U32>::new()
        .chain_update([0x02])
        .chain_update(h.as_bytes())
        .chain_update(xk.as_bytes())
        .chain_update(epk.as_bytes())
        .chain_update(xpk.as_bytes())
        .finalize();

    let n = Blake2b::<U24>::new()
        .chain_update(epk.as_bytes())
        .chain_update(xpk.as_bytes())
        .finalize();

    let mut edk = [0; 32];
    XChaCha20::new(&ek, &n).apply_keystream_inout(InOutBuf::new(ptk.as_ref(), &mut edk).unwrap());

    let tag = Blake2bMac::<U32>::new_from_slice(&ak)
        .unwrap()
        .chain_update(h.as_bytes())
        .chain_update(epk.as_bytes())
        .chain_update(edk)
        .finalize()
        .into_bytes();

    let mut enc = EncoderStringWriter::from(h.to_owned(), URL_SAFE_NO_PAD);
    enc.write_all(&tag).unwrap();
    enc.write_all(epk.as_bytes()).unwrap();
    enc.write_all(&edk).unwrap();
    enc.into_inner()
}

fn unseal(h: &str, sk: &[u8; 64], wk: &str) -> Result<Key<32>, PasetoError> {
    let b = wk.strip_prefix(h).ok_or(PasetoError::WrongHeader)?;
    let mut output = [0; 96];
    base64::decode_config_slice(b, base64::URL_SAFE_NO_PAD, &mut output)?;
    let (t, b) = output.split_at(32);
    let (epk, edk) = b.split_at(32);

    let epk: [u8; 32] = epk.try_into().unwrap();
    let epk = x25519_dalek::PublicKey::from(epk);

    // expand sk
    let xsk = Sha512::default().chain_update(&sk[..32]).finalize()[..32]
        .try_into()
        .unwrap();
    let xsk = curve25519_dalek::Scalar::from_bits_clamped(xsk);
    let xsk = x25519_dalek::StaticSecret::from(xsk.to_bytes());
    let xpk: x25519_dalek::PublicKey = (&xsk).into();

    let xk = xsk.diffie_hellman(&epk);

    let ak = Blake2b::<U32>::new()
        .chain_update([0x02])
        .chain_update(h.as_bytes())
        .chain_update(xk.as_bytes())
        .chain_update(epk.as_bytes())
        .chain_update(xpk.as_bytes())
        .finalize();

    let t2 = Blake2bMac::<U32>::new_from_slice(&ak)
        .unwrap()
        .chain_update(h.as_bytes())
        .chain_update(epk.as_bytes())
        .chain_update(edk)
        .finalize()
        .into_bytes();

    // step 6: Compare t2 with t, using a constant-time compare function. If it does not match, abort.
    if t.ct_ne(&t2).into() {
        return Err(PasetoError::InvalidSignature);
    }

    let ek = Blake2b::<U32>::new()
        .chain_update([0x01])
        .chain_update(h.as_bytes())
        .chain_update(xk.as_bytes())
        .chain_update(epk.as_bytes())
        .chain_update(xpk.as_bytes())
        .finalize();

    let n = Blake2b::<U24>::new()
        .chain_update(epk.as_bytes())
        .chain_update(xpk.as_bytes())
        .finalize();

    let mut pdk = [0; 32];
    XChaCha20::new(&ek, &n).apply_keystream_inout(InOutBuf::new(edk, &mut pdk).unwrap());

    Ok(rusty_paseto::core::Key::from(pdk))
}
