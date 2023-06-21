use rusty_paserk::key::EncodeKey;
use rusty_paseto::core::{Local, PasetoSymmetricKey, V1, V2, V3, V4};
use serde::Deserialize;

#[derive(Deserialize)]
struct Test {
    name: String,
    paserk: String,
    key: Option<String>,
}

#[derive(Deserialize)]
struct TestFile {
    name: String,
    tests: Vec<Test>,
}

fn local_key<Version>(test_file: TestFile)
where
    PasetoSymmetricKey<Version, Local>: EncodeKey,
{
    for test in test_file.tests {
        if let Some(key) = test.key {
            let key2 = PasetoSymmetricKey::<Version, Local>::decode_key(&test.paserk).unwrap();
            let key = hex::decode(key).unwrap();

            assert_eq!(
                key,
                key2.as_ref(),
                "{} > {}: decode failed",
                test_file.name,
                test.name
            );

            let paserk2 = key2.encode_key();

            assert_eq!(
                test.paserk, paserk2,
                "{} > {}: encode failed",
                test_file.name, test.name
            );
        } else {
            PasetoSymmetricKey::<Version, Local>::decode_key(&test.paserk)
                .map(|_| {})
                .expect_err(&format!(
                    "{} > {}: decode succeeded",
                    test_file.name, test.name
                ));
        }
    }
}

#[test]
fn local_v1() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k1.local.json")).unwrap();
    local_key::<V1>(test_file);
}

#[test]
fn local_v2() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k2.local.json")).unwrap();
    local_key::<V2>(test_file);
}

#[test]
fn local_v3() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k3.local.json")).unwrap();
    local_key::<V3>(test_file);
}

#[test]
fn local_v4() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k4.local.json")).unwrap();
    local_key::<V4>(test_file);
}
