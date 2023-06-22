use rusty_paserk::{internal::SealedVersion, Key, Local, SealedKey, Secret};
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
    #[serde(rename = "sealing-secret-key")]
    sealing_secret_key: String,
}

#[derive(Deserialize)]
struct TestFile {
    name: String,
    tests: Vec<Test>,
}

fn run_test<V: SealedVersion>(name: &str, test: Test, ssk: Key<V, Secret>) {
    // let ssk = hex::decode(test.sealing_secret_key).unwrap();
    // let ssk = Key::<V, Secret>::try_from(&*ssk).unwrap();

    let result: Result<SealedKey<V>, PasetoError> = test.paserk.parse();
    let result: Result<Key<V, Local>, PasetoError> = result.and_then(|s| s.unseal(&ssk));

    if test.expect_fail {
        result.map(|_| {}).expect_err(&format!(
            "{} > {}: {}",
            name,
            test.name,
            test.comment.unwrap()
        ));
    } else {
        let key =
            result.unwrap_or_else(|err| panic!("{} > {}: unwrap failed {err:?}", name, test.name));

        let unsealed = hex::decode(test.unsealed.unwrap()).unwrap();
        assert_eq!(
            key.as_ref(),
            &unsealed,
            "{} > {}: unseal failed",
            name,
            test.name
        );
    }
}

#[test]
fn local_v4() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k4.seal.json")).unwrap();

    for test in test_file.tests {
        let ssk = hex::decode(&test.sealing_secret_key).unwrap();
        let ssk = Key::<V4, Secret>::try_from(&*ssk).unwrap();

        run_test(&test_file.name, test, ssk)
    }
}

#[test]
fn local_v3() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k3.seal.json")).unwrap();

    for test in test_file.tests {
        let ssk = Key::from_sec1_pem(&test.sealing_secret_key);
        let ssk = match (ssk, test.expect_fail) {
            (Ok(ssk), _) => ssk,
            (Err(_), true) => continue,
            (Err(e), false) => {
                panic!(
                    "{} > {}: key parse failed {:?}",
                    test_file.name, test.name, e
                );
            }
        };

        run_test(&test_file.name, test, ssk)
    }
}
