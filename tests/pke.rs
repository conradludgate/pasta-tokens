use rusty_paserk::{
    key::{Key, LocalKey, SecretKey},
    pke::SealedKey,
};
use rusty_paseto::core::{PasetoError, V4};
use serde::Deserialize;

#[derive(Deserialize)]
struct Test {
    #[serde(rename = "expect-fail")]
    expect_fail: bool,
    name: String,
    paserk: String,
    comment: Option<String>,
    unsealed: Option<String>,
    #[serde(rename = "sealing-public-key")]
    _sealing_public_key: String,
    #[serde(rename = "sealing-secret-key")]
    sealing_secret_key: String,
}

#[derive(Deserialize)]
struct TestFile {
    name: String,
    tests: Vec<Test>,
}

fn test(test_file: TestFile) {
    for test in test_file.tests {
        // let spk = hex::decode(test.sealing_public_key).unwrap();
        let ssk = hex::decode(test.sealing_secret_key).unwrap();
        // let spk = Key::from(&*spk);
        let ssk = Key::<V4, SecretKey>::try_from(&*ssk).unwrap();

        let result: Result<SealedKey<V4>, PasetoError> = test.paserk.parse();
        let result: Result<Key<V4, LocalKey>, PasetoError> = result.and_then(|s| s.unseal(&ssk));

        if test.expect_fail {
            result.map(|_| {}).expect_err(&format!(
                "{} > {}: {}",
                test_file.name,
                test.name,
                test.comment.unwrap()
            ));
        } else {
            let key = result.unwrap_or_else(|err| {
                panic!("{} > {}: unwrap failed {err:?}", test_file.name, test.name)
            });

            let unsealed = hex::decode(test.unsealed.unwrap()).unwrap();
            assert_eq!(
                key.as_ref(),
                &unsealed,
                "{} > {}: unseal failed",
                test_file.name,
                test.name
            )
        }
    }
}

#[test]
fn local_v4() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k4.seal.json")).unwrap();
    test(test_file)
}
