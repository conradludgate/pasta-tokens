use rusty_paserk::{
    internal::{PieVersion, PieWrapType},
    Key, Local, PieWrappedKey, Secret,
};
use rusty_paseto::core::{V3, V4};
use serde::Deserialize;

#[derive(Deserialize)]
struct Test {
    #[serde(rename = "expect-fail")]
    expect_fail: bool,
    name: String,
    paserk: String,
    comment: Option<String>,
    unwrapped: Option<String>,
    #[serde(rename = "wrapping-key")]
    wrapping_key: String,
}

#[derive(Deserialize)]
struct TestFile {
    name: String,
    tests: Vec<Test>,
}

fn wrap_test<V, K>(test_file: TestFile)
where
    V: PieVersion,
    K: PieWrapType<V>,
{
    for test in test_file.tests {
        let wrapping = hex::decode(test.wrapping_key).unwrap();
        let wrapping_key = Key::<V, Local>::try_from(&*wrapping).unwrap();

        if test.expect_fail {
            let Ok(wrapped_key): Result<PieWrappedKey<V, K>, _> = test.paserk.parse() else {
                // we expect errors here
                continue;
            };

            match wrapped_key.unwrap_key(&wrapping_key) {
                Err(_) => {}
                Ok(_) => {
                    panic!(
                        "{} > {}: {}",
                        test_file.name,
                        test.name,
                        test.comment.unwrap()
                    )
                }
            }
        } else {
            let unwrapped = hex::decode(test.unwrapped.unwrap()).unwrap();

            let Ok(wrapped_key): Result<PieWrappedKey<V, K>, _> = test.paserk.parse() else {
                panic!("{} > {}: unwrap parse failed", test_file.name, test.name)
            };

            match wrapped_key.unwrap_key(&wrapping_key) {
                Err(err) => panic!("{} > {}: {:?}", test_file.name, test.name, err),
                Ok(key) => {
                    assert_eq!(
                        key.as_ref(),
                        &unwrapped,
                        "{} > {}: unwrap failed",
                        test_file.name,
                        test.name
                    )
                }
            }
        }
    }
}

#[test]
fn local_v3() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k3.local-wrap.pie.json")).unwrap();
    wrap_test::<V3, Local>(test_file);
}

#[test]
fn local_v4() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k4.local-wrap.pie.json")).unwrap();
    wrap_test::<V4, Local>(test_file);
}

#[test]
fn secret_v3() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k3.secret-wrap.pie.json")).unwrap();
    wrap_test::<V3, Secret>(test_file);
}

#[test]
fn secret_v4() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k4.secret-wrap.pie.json")).unwrap();
    wrap_test::<V4, Secret>(test_file);
}
