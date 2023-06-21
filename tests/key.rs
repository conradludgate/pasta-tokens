use std::str::FromStr;

use rusty_paserk::key::{Key, KeyType, LocalKey, PlaintextKey, PublicKey, SecretKey, Version};
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

fn key<V: Version, K: KeyType<V>>(test_file: TestFile) {
    for test in test_file.tests {
        match (test.key, test.paserk) {
            (Some(key), Some(paserk)) => {
                let key2: PlaintextKey<V, K> = paserk.parse().unwrap();
                let key: Key<V, K> = hex::decode(key).unwrap().as_slice().try_into().unwrap();

                assert_eq!(
                    key, key2.0,
                    "{} > {}: decode failed",
                    test_file.name, test.name
                );

                let paserk2 = key2.to_string();

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
            (Some(key), None) => {
                let key = hex::decode(key).unwrap();
                Key::<V, K>::try_from(&*key)
                    .map(|_| {})
                    .expect_err(&format!(
                        "{} > {}: decode succeeded",
                        test_file.name, test.name
                    ));
            }
            (None, None) => {}
        }
    }
}

#[test]
fn local_v3() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k3.local.json")).unwrap();
    key::<V3, LocalKey>(test_file);
}

#[test]
fn local_v4() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k4.local.json")).unwrap();
    key::<V4, LocalKey>(test_file);
}

#[test]
fn public_v3() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k3.public.json")).unwrap();
    key::<V3, PublicKey>(test_file);
}

#[test]
fn public_v4() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k4.public.json")).unwrap();
    key::<V4, PublicKey>(test_file);
}

#[test]
fn secret_v3() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k3.secret.json")).unwrap();
    key::<V3, SecretKey>(test_file);
}

#[test]
fn secret_v4() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k4.secret.json")).unwrap();
    key::<V4, SecretKey>(test_file);
}
