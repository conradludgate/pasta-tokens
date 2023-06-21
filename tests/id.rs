use rusty_paserk::{
    id::KeyId,
    key::{Key, KeyType, LocalKey, PublicKey, SecretKey, Version},
};
use rusty_paseto::core::{V3, V4};
use serde::Deserialize;

#[derive(Deserialize)]
struct Test {
    name: String,
    paserk: Option<String>,
    key: String,
}

#[derive(Deserialize)]
struct TestFile {
    name: String,
    tests: Vec<Test>,
}

fn id<V: Version, K: KeyType<V>>(test_file: TestFile)
where
    KeyId<V, K>: From<Key<V, K>>,
{
    for test in test_file.tests {
        if let Some(paserk) = test.paserk {
            let key: Key<V, K> = hex::decode(test.key)
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap();
            let kid: KeyId<V, K> = key.into();
            let kid2: KeyId<V, K> = paserk.parse().unwrap();

            assert_eq!(kid, kid2, "{} > {}: kid failed", test_file.name, test.name);

            assert_eq!(
                kid.to_string(),
                paserk,
                "{} > {}: kid failed",
                test_file.name,
                test.name
            );
        }
    }
}

#[test]
fn local_v3() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k3.lid.json")).unwrap();
    id::<V3, LocalKey>(test_file);
}

#[test]
fn local_v4() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k4.lid.json")).unwrap();
    id::<V4, LocalKey>(test_file);
}

#[test]
fn public_v3() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k3.pid.json")).unwrap();
    id::<V3, PublicKey>(test_file);
}

#[test]
fn public_v4() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k4.pid.json")).unwrap();
    id::<V4, PublicKey>(test_file);
}
#[test]
fn secret_v3() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k3.sid.json")).unwrap();
    id::<V3, SecretKey>(test_file);
}

#[test]
fn secret_v4() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k4.sid.json")).unwrap();
    id::<V4, SecretKey>(test_file);
}
