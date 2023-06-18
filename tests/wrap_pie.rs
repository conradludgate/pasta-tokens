use rusty_paserk::wrap::{LocalWrapperExt, Pie, SecretWrapperExt};
use rusty_paseto::core::{Key, Local, PasetoSymmetricKey, V1, V2, V3, V4};
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

fn local_wrap_test<Version>(test_file: TestFile)
where
    Pie: LocalWrapperExt<Version>,
{
    for test in test_file.tests {
        let wrapping = hex::decode(test.wrapping_key).unwrap();
        let wrapping_key = PasetoSymmetricKey::<Version, Local>::from(Key::from(&*wrapping));
        let mut wrapped = test.paserk.into_bytes();

        if test.expect_fail {
            Pie::unwrap_local(&mut wrapped, &wrapping_key)
                .map(|_| {})
                .expect_err(&format!(
                    "{} > {}: {}",
                    test_file.name,
                    test.name,
                    test.comment.unwrap()
                ));
        } else {
            let key = Pie::unwrap_local(&mut wrapped, &wrapping_key).unwrap_or_else(|err| {
                panic!("{} > {}: unwrap failed {err:?}", test_file.name, test.name)
            });

            let unwrapped = hex::decode(test.unwrapped.unwrap()).unwrap();
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

#[test]
fn local_v1() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k1.local-wrap.pie.json")).unwrap();
    local_wrap_test::<V1>(test_file);
}

#[test]
fn local_v2() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k2.local-wrap.pie.json")).unwrap();
    local_wrap_test::<V2>(test_file);
}

#[test]
fn local_v3() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k3.local-wrap.pie.json")).unwrap();
    local_wrap_test::<V3>(test_file);
}

#[test]
fn local_v4() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k4.local-wrap.pie.json")).unwrap();
    local_wrap_test::<V4>(test_file);
}

fn secret_wrap_test<Version>(test_file: TestFile)
where
    Pie: SecretWrapperExt<Version>,
{
    for test in test_file.tests {
        let wrapping = hex::decode(test.wrapping_key).unwrap();
        let wrapping_key = PasetoSymmetricKey::<Version, Local>::from(Key::from(&*wrapping));
        let mut wrapped = test.paserk.into_bytes();

        if test.expect_fail {
            Pie::unwrap_secret(&mut wrapped, &wrapping_key)
                .map(|_| {})
                .expect_err(&format!(
                    "{} > {}: {}",
                    test_file.name,
                    test.name,
                    test.comment.unwrap()
                ));
        } else {
            let key = Pie::unwrap_secret(&mut wrapped, &wrapping_key).unwrap_or_else(|err| {
                panic!("{} > {}: unwrap failed {err:?}", test_file.name, test.name)
            });

            let unwrapped = hex::decode(test.unwrapped.unwrap()).unwrap();
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

// this test is weird :think:

// #[test]
// fn secret_v1() {
//     let test_file: TestFile =
//         serde_json::from_str(include_str!("test-vectors/k1.secret-wrap.pie.json")).unwrap();
//     secret_wrap_test::<V1>(test_file);
// }

#[test]
fn secret_v2() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k2.secret-wrap.pie.json")).unwrap();
    secret_wrap_test::<V2>(test_file);
}

// not supported for now

// #[test]
// fn secret_v3() {
//     let test_file: TestFile =
//         serde_json::from_str(include_str!("test-vectors/k3.secret-wrap.pie.json")).unwrap();
//     secret_wrap_test::<V3>(test_file);
// }

#[test]
fn secret_v4() {
    let test_file: TestFile =
        serde_json::from_str(include_str!("test-vectors/k4.secret-wrap.pie.json")).unwrap();
    secret_wrap_test::<V4>(test_file);
}
