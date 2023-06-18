use rusty_paserk::id::EncodeId;
use rusty_paseto::core::{
    Key, Local, PasetoAsymmetricPrivateKey, PasetoAsymmetricPublicKey, PasetoSymmetricKey, Public,
    V1, V2, V3, V4,
};
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

fn local_id<Version>(test_file: TestFile)
where
    PasetoSymmetricKey<Version, Local>: EncodeId,
{
    for test in test_file.tests {
        if let Some(paserk) = test.paserk {
            let key = hex::decode(test.key).unwrap();
            let key = PasetoSymmetricKey::<Version, Local>::from(Key::from(&*key));
            let kid = key.encode_id();

            assert_eq!(
                kid, paserk,
                "{} > {}: kid failed",
                test_file.name, test.name
            )
        }
    }
}

#[test]
fn local_v1() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k1.lid.json")).unwrap();
    local_id::<V1>(test_file);
}

#[test]
fn local_v2() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k2.lid.json")).unwrap();
    local_id::<V2>(test_file);
}

#[test]
fn local_v3() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k3.lid.json")).unwrap();
    local_id::<V3>(test_file);
}

#[test]
fn local_v4() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k4.lid.json")).unwrap();
    local_id::<V4>(test_file);
}

#[test]
fn public_v2() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k2.pid.json")).unwrap();

    for test in test_file.tests {
        if let Some(paserk) = test.paserk {
            let key = hex::decode(test.key).unwrap();
            let key = Key::from(&*key);
            let key = PasetoAsymmetricPublicKey::<V2, Public>::from(&key);
            let kid = key.encode_id();

            assert_eq!(
                kid, paserk,
                "{} > {}: kid failed",
                test_file.name, test.name
            )
        }
    }
}

#[test]
fn public_v3() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k3.pid.json")).unwrap();

    for test in test_file.tests {
        if let Some(paserk) = test.paserk {
            let key = hex::decode(test.key).unwrap();
            let key = Key::<49>::from(&*key);
            let key = PasetoAsymmetricPublicKey::<V3, Public>::try_from(&key).unwrap();
            let kid = key.encode_id();

            assert_eq!(
                kid, paserk,
                "{} > {}: kid failed",
                test_file.name, test.name
            )
        }
    }
}

#[test]
fn public_v4() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k4.pid.json")).unwrap();

    for test in test_file.tests {
        if let Some(paserk) = test.paserk {
            let key = hex::decode(test.key).unwrap();
            let key = Key::from(&*key);
            let key = PasetoAsymmetricPublicKey::<V4, Public>::from(&key);
            let kid = key.encode_id();

            assert_eq!(
                kid, paserk,
                "{} > {}: kid failed",
                test_file.name, test.name
            )
        }
    }
}

#[test]
fn secret_v2() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k2.sid.json")).unwrap();

    for test in test_file.tests {
        if let Some(paserk) = test.paserk {
            let key = hex::decode(test.key).unwrap();
            let key = Key::from(&*key);
            let key = PasetoAsymmetricPrivateKey::<V2, Public>::from(&key);
            let kid = key.encode_id();

            assert_eq!(
                kid, paserk,
                "{} > {}: kid failed",
                test_file.name, test.name
            )
        }
    }
}

#[test]
fn secret_v3() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k3.sid.json")).unwrap();

    for test in test_file.tests {
        if let Some(paserk) = test.paserk {
            let key = hex::decode(test.key).unwrap();
            let key = Key::from(&*key);
            let key = PasetoAsymmetricPrivateKey::<V3, Public>::from(&key);
            let kid = key.encode_id();

            assert_eq!(
                kid, paserk,
                "{} > {}: kid failed",
                test_file.name, test.name
            )
        }
    }
}

#[test]
fn secret_v4() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k4.sid.json")).unwrap();

    for test in test_file.tests {
        if let Some(paserk) = test.paserk {
            let key = hex::decode(test.key).unwrap();
            let key = Key::from(&*key);
            let key = PasetoAsymmetricPrivateKey::<V4, Public>::from(&key);
            let kid = key.encode_id();

            assert_eq!(
                kid, paserk,
                "{} > {}: kid failed",
                test_file.name, test.name
            )
        }
    }
}
