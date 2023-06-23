use std::str::FromStr;

use rusty_paserk::{Key, KeyType, Local, PlaintextKey, Public, Secret, Version};
use rusty_paseto::core::{V3, V4};
use serde::Deserialize;

#[derive(Deserialize)]
struct Test {
    name: String,
    paserk: Option<String>,
    key: Option<String>,
}

#[derive(Deserialize)]
struct TestFile {
    name: String,
    tests: Vec<Test>,
}

fn key<V: Version, K: KeyType<V>>(test_file: TestFile)
where
    Key<V, K>: NewKey,
{
    for test in test_file.tests {
        match (test.key, test.paserk) {
            (Some(key), Some(paserk)) => {
                let key2: PlaintextKey<V, K> = paserk.parse().unwrap();
                let key = Key::<V, K>::from_key(&key);

                let paserk2 = PlaintextKey(key.clone()).to_string();
                dbg!(&paserk2);

                assert_eq!(
                    key, key2.0,
                    "{} > {}: decode failed",
                    test_file.name, test.name
                );

                assert_eq!(
                    paserk, paserk2,
                    "{} > {}: encode failed",
                    test_file.name, test.name
                );
            }
            (None, Some(paserk)) => {
                PlaintextKey::<V, K>::from_str(&paserk)
                    .map(|_| {})
                    .expect_err(&format!(
                        "{} > {}: decode succeeded",
                        test_file.name, test.name
                    ));
            }
            (Some(_), None) => {}
            (None, None) => {}
        }
    }
}

#[test]
fn local_v3() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k3.local.json")).unwrap();
    key::<V3, Local>(test_file);
}

#[test]
fn local_v4() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k4.local.json")).unwrap();
    key::<V4, Local>(test_file);
}

#[test]
fn public_v3() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k3.public.json")).unwrap();
    key::<V3, Public>(test_file);
}

#[test]
fn public_v4() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k4.public.json")).unwrap();
    key::<V4, Public>(test_file);
}

#[test]
fn secret_v3() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k3.secret.json")).unwrap();
    key::<V3, Secret>(test_file);
}

#[test]
fn secret_v4() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k4.secret.json")).unwrap();
    key::<V4, Secret>(test_file);
}

trait NewKey {
    fn from_key(s: &str) -> Self;
}

impl NewKey for Key<V3, Local> {
    fn from_key(s: &str) -> Self {
        let b = hex::decode(s).unwrap();
        Self::from_bytes(b.try_into().unwrap())
    }
}

impl NewKey for Key<V4, Local> {
    fn from_key(s: &str) -> Self {
        let b = hex::decode(s).unwrap();
        Self::from_bytes(b.try_into().unwrap())
    }
}

impl NewKey for Key<V3, Secret> {
    fn from_key(s: &str) -> Self {
        let b = hex::decode(s).unwrap();
        Self::from_bytes(&b).unwrap()
    }
}

impl NewKey for Key<V4, Secret> {
    fn from_key(s: &str) -> Self {
        let b = hex::decode(s).unwrap();
        Self::from_keypair_bytes(&b).unwrap()
    }
}

impl NewKey for Key<V3, Public> {
    fn from_key(s: &str) -> Self {
        let b = hex::decode(s).unwrap();
        Self::from_sec1_bytes(&b).unwrap()
    }
}

impl NewKey for Key<V4, Public> {
    fn from_key(s: &str) -> Self {
        let b = hex::decode(s).unwrap();
        Self::from_public_key(&b).unwrap()
    }
}
