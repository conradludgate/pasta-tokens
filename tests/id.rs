use rusty_paserk::{Key, KeyId, KeyType, Local, Public, Secret, Version};
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
    Key<V, K>: NewKey,
    KeyId<V, K>: From<Key<V, K>>,
{
    for test in test_file.tests {
        dbg!(&test_file.name, &test.name);
        if let Some(paserk) = test.paserk {
            let key = Key::<V, K>::from_key(&test.key);
            let kid: KeyId<V, K> = key.to_id();
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
    id::<V3, Local>(test_file);
}

#[test]
fn local_v4() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k4.lid.json")).unwrap();
    id::<V4, Local>(test_file);
}

#[test]
fn public_v3() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k3.pid.json")).unwrap();
    id::<V3, Public>(test_file);
}

#[test]
fn public_v4() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k4.pid.json")).unwrap();
    id::<V4, Public>(test_file);
}
#[test]
fn secret_v3() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k3.sid.json")).unwrap();
    id::<V3, Secret>(test_file);
}

#[test]
fn secret_v4() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k4.sid.json")).unwrap();
    id::<V4, Secret>(test_file);
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
