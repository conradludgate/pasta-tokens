use std::{fs, str::FromStr};

use libtest_mimic::{Arguments, Failed, Trial};
use pasta_tokens::{EncryptedToken, Version, V3, V4};
// use rusty_paserk::{
//     internal::{PieVersion, PieWrapType, PwVersion, PwWrapType, SealedVersion},
//     Key, KeyId, KeyType, Local, PasetoError, PieWrappedKey, PlaintextKey, Public, PwWrappedKey,
//     SealedKey, Secret, Version, V3, V4,
// };
use serde::{
    de::{DeserializeOwned, Visitor},
    Deserialize,
};

fn main() {
    let args = Arguments::from_args();

    let mut tests = vec![];

    PasetoTest::add_all_tests(&mut tests);

    // IdTest::add_all_tests(&mut tests);
    // KeyTest::add_all_tests(&mut tests);
    // PbkwTest::add_all_tests(&mut tests);
    // PkeTest::add_all_tests(&mut tests);
    // PieWrapTest::add_all_tests(&mut tests);

    libtest_mimic::run(&args, tests).exit();
}

fn read_test<Test: DeserializeOwned>(v: &str) -> TestFile<Test> {
    let path = format!("tests/test-vectors/{v}");
    let file = fs::read_to_string(path).unwrap();
    serde_json::from_str(&file).unwrap()
}

#[derive(Deserialize)]
struct TestFile<T> {
    tests: Vec<Test<T>>,
}

#[derive(Deserialize)]
struct Test<T> {
    name: String,
    #[serde(flatten)]
    test_data: T,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
struct PasetoTest {
    token: String,
    footer: String,
    implicit_assertion: String,
    #[serde(flatten)]
    purpose: PasetoPurpose,
    #[serde(flatten)]
    result: TestResult,
}

impl PasetoTest {
    fn add_all_tests(tests: &mut Vec<Trial>) {
        Self::add_tests::<V3>(tests);
        // Self::add_tests::<V4>(tests);
    }

    fn add_tests<V: Version>(tests: &mut Vec<Trial>) {
        let test_file: TestFile<Self> = read_test(&format!("{}.json", V::PASETO_HEADER));
        for test in test_file.tests {
            tests.push(Trial::test(test.name, || test.test_data.test::<V>()));
        }
    }

    fn test<V: Version>(self) -> Result<(), Failed> {
        match self {
            PasetoTest {
                token,
                footer,
                implicit_assertion,
                purpose: PasetoPurpose::Local { nonce, key },
                result: TestResult::Failure { .. },
            } => {}
            PasetoTest {
                token,
                footer,
                implicit_assertion,
                purpose: PasetoPurpose::Local { nonce, key },
                result: TestResult::Success { payload, .. },
            } => {}
            PasetoTest {
                token,
                footer,
                implicit_assertion,
                purpose:
                    PasetoPurpose::Public {
                        public_key,
                        secret_key,
                    },
                result: TestResult::Failure { .. },
            } => {}
            PasetoTest {
                token,
                footer,
                implicit_assertion,
                purpose:
                    PasetoPurpose::Public {
                        public_key,
                        secret_key,
                    },
                result: TestResult::Success { payload, .. },
            } => {}
        }

        Ok(())

        // if let Some(paserk) = self.paserk {
        //     let key = Key::<V, K>::from_key(&self.key);
        //     let kid: KeyId<V, K> = key.to_id();
        //     let kid2: KeyId<V, K> = paserk.parse().unwrap();

        //     if kid != kid2 {
        //         return Err("decode failed".into());
        //     }
        //     if kid.to_string() != paserk {
        //         return Err("encode failed".into());
        //     }
        // }
        // Ok(())
    }
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum PasetoPurpose {
    #[serde(rename_all = "kebab-case")]
    Local { nonce: String, key: String },
    #[serde(rename_all = "kebab-case")]
    Public {
        public_key: String,
        secret_key: String,
    },
}

#[derive(Debug)]
struct Bool<const B: bool>;

impl<'a, const B: bool> Deserialize<'a> for Bool<B> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        struct BoolVisitor<const B: bool>;

        impl<'a, const B: bool> Visitor<'a> for BoolVisitor<B> {
            type Value = Bool<B>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "{B}")
            }

            fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                (v == B)
                    .then_some(Bool)
                    .ok_or_else(|| E::custom(format!("expected {B}, got {v}")))
            }
        }

        deserializer.deserialize_bool(BoolVisitor)
    }
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum TestResult {
    #[serde(rename_all = "kebab-case")]
    Success {
        expect_fail: Bool<false>,
        payload: String,
    },
    #[serde(rename_all = "kebab-case")]
    Failure {
        expect_fail: Bool<true>,
        payload: (),
    },
}

// #[derive(Deserialize)]
// struct IdTest {
//     paserk: Option<String>,
//     key: String,
// }

// impl IdTest {
//     fn add_all_tests(tests: &mut Vec<Trial>) {
//         Self::add_tests::<V3, Local>(tests);
//         Self::add_tests::<V4, Local>(tests);
//         Self::add_tests::<V3, Secret>(tests);
//         Self::add_tests::<V4, Secret>(tests);
//         Self::add_tests::<V3, Public>(tests);
//         Self::add_tests::<V4, Public>(tests);
//     }

//     fn add_tests<V: Version, K: KeyType<V>>(tests: &mut Vec<Trial>)
//     where
//         Key<V, K>: NewKey,
//         KeyId<V, K>: From<Key<V, K>>,
//     {
//         let test_file: TestFile<Self> = read_test(&format!("{}{}json", V::KEY_HEADER, K::ID));
//         for test in test_file.tests {
//             tests.push(Trial::test(test.name, || test.test_data.test::<V, K>()));
//         }
//     }

//     fn test<V: Version, K: KeyType<V>>(self) -> Result<(), Failed>
//     where
//         Key<V, K>: NewKey,
//         KeyId<V, K>: From<Key<V, K>>,
//     {
//         if let Some(paserk) = self.paserk {
//             let key = Key::<V, K>::from_key(&self.key);
//             let kid: KeyId<V, K> = key.to_id();
//             let kid2: KeyId<V, K> = paserk.parse().unwrap();

//             if kid != kid2 {
//                 return Err("decode failed".into());
//             }
//             if kid.to_string() != paserk {
//                 return Err("encode failed".into());
//             }
//         }
//         Ok(())
//     }
// }

// #[derive(Deserialize)]
// struct KeyTest {
//     paserk: Option<String>,
//     key: Option<String>,
//     comment: Option<String>,
// }

// impl KeyTest {
//     fn add_all_tests(tests: &mut Vec<Trial>) {
//         Self::add_tests::<V3, Local>(tests);
//         Self::add_tests::<V4, Local>(tests);
//         Self::add_tests::<V3, Secret>(tests);
//         Self::add_tests::<V4, Secret>(tests);
//         Self::add_tests::<V3, Public>(tests);
//         Self::add_tests::<V4, Public>(tests);
//     }

//     fn add_tests<V: Version, K: KeyType<V>>(tests: &mut Vec<Trial>)
//     where
//         Key<V, K>: NewKey,
//     {
//         let test_file: TestFile<Self> = read_test(&format!("{}{}json", V::KEY_HEADER, K::HEADER));
//         for test in test_file.tests {
//             tests.push(Trial::test(test.name, || test.test_data.test::<V, K>()));
//         }
//     }

//     fn test<V: Version, K: KeyType<V>>(self) -> Result<(), Failed>
//     where
//         Key<V, K>: NewKey,
//     {
//         match (self.key, self.paserk) {
//             (Some(key), Some(paserk)) => {
//                 let key2: PlaintextKey<V, K> = paserk.parse().unwrap();
//                 let key = Key::<V, K>::from_key(&key);

//                 let paserk2 = PlaintextKey(key.clone()).to_string();
//                 if key != key2.0 {
//                     return Err("decode failed".into());
//                 }
//                 if paserk != paserk2 {
//                     return Err("encode failed".into());
//                 }
//                 Ok(())
//             }
//             (None, Some(paserk)) => match PlaintextKey::<V, K>::from_str(&paserk) {
//                 Ok(_) => Err(self.comment.unwrap().into()),
//                 Err(_) => Ok(()),
//             },
//             (Some(_), None) => Ok(()),
//             (None, None) => Ok(()),
//         }
//     }
// }

// #[derive(Deserialize)]
// struct PbkwTest {
//     #[serde(rename = "expect-fail")]
//     expect_fail: bool,
//     paserk: String,
//     comment: Option<String>,
//     unwrapped: Option<String>,
//     password: String,
// }

// impl PbkwTest {
//     fn add_all_tests(tests: &mut Vec<Trial>) {
//         Self::add_tests::<V3, Local>(tests);
//         Self::add_tests::<V4, Local>(tests);
//         Self::add_tests::<V3, Secret>(tests);
//         Self::add_tests::<V4, Secret>(tests);
//     }

//     fn add_tests<V: PwVersion, K: PwWrapType<V>>(tests: &mut Vec<Trial>) {
//         let test_file: TestFile<Self> =
//             read_test(&format!("{}{}json", V::KEY_HEADER, K::WRAP_HEADER));
//         for test in test_file.tests {
//             tests.push(Trial::test(test.name, || test.test_data.test::<V, K>()));
//         }
//     }

//     fn test<V: PwVersion, K: PwWrapType<V>>(self) -> Result<(), Failed> {
//         let wrapped_key: PwWrappedKey<V, K> = match self.paserk.parse() {
//             Ok(wrapped_key) => wrapped_key,
//             Err(_) if self.expect_fail => return Ok(()),
//             Err(e) => return Err(e.to_string().into()),
//         };

//         if self.expect_fail {
//             match wrapped_key.unwrap_key(self.password.as_bytes()) {
//                 Err(_) => Ok(()),
//                 Ok(_) => Err(self.comment.unwrap().into()),
//             }
//         } else {
//             let unwrapped = hex::decode(self.unwrapped.unwrap()).unwrap();

//             match wrapped_key.unwrap_key(self.password.as_bytes()) {
//                 Err(err) => Err(err.to_string().into()),
//                 Ok(key) if key.as_ref() != unwrapped => Err("key mismatch".into()),
//                 Ok(_) => Ok(()),
//             }
//         }
//     }
// }

// #[derive(Deserialize)]
// struct PkeTest {
//     #[serde(rename = "expect-fail")]
//     expect_fail: bool,
//     paserk: String,
//     // comment: Option<String>,
//     unsealed: Option<String>,
//     #[serde(rename = "sealing-secret-key")]
//     sealing_secret_key: String,
// }

// impl PkeTest {
//     fn add_all_tests(tests: &mut Vec<Trial>) {
//         Self::add_tests::<V3>(tests);
//         Self::add_tests::<V4>(tests);
//     }

//     fn add_tests<V: SealedVersion>(tests: &mut Vec<Trial>)
//     where
//         Key<V, Secret>: NewKey2,
//     {
//         let test_file: TestFile<Self> = read_test(&format!("{}seal.json", V::KEY_HEADER));
//         for test in test_file.tests {
//             tests.push(Trial::test(test.name, || test.test_data.test::<V>()));
//         }
//     }

//     fn test<V: SealedVersion>(self) -> Result<(), Failed>
//     where
//         Key<V, Secret>: NewKey2,
//     {
//         let result: Result<SealedKey<V>, PasetoError> = self.paserk.parse();

//         let sealed_key = match result {
//             Ok(sealed_key) => sealed_key,
//             Err(_) if self.expect_fail => return Ok(()),
//             Err(e) => return Err(e.to_string().into()),
//         };

//         let ssk = Key::from_key2(&self.sealing_secret_key);
//         let key = match sealed_key.unseal(&ssk) {
//             Ok(key) => key,
//             Err(_) if self.expect_fail => return Ok(()),
//             Err(e) => return Err(e.to_string().into()),
//         };

//         let unsealed = hex::decode(self.unsealed.unwrap()).unwrap();

//         if key.as_ref() != unsealed {
//             return Err("unseal failed".into());
//         }
//         Ok(())
//     }
// }

// #[derive(Deserialize)]
// struct PieWrapTest {
//     #[serde(rename = "expect-fail")]
//     expect_fail: bool,
//     paserk: String,
//     comment: Option<String>,
//     unwrapped: Option<String>,
//     #[serde(rename = "wrapping-key")]
//     wrapping_key: String,
// }

// impl PieWrapTest {
//     fn add_all_tests(tests: &mut Vec<Trial>) {
//         Self::add_tests::<V3, Local>(tests);
//         Self::add_tests::<V4, Local>(tests);
//         Self::add_tests::<V3, Secret>(tests);
//         Self::add_tests::<V4, Secret>(tests);
//     }

//     fn add_tests<V: PieVersion, K: PieWrapType<V>>(tests: &mut Vec<Trial>)
//     where
//         Key<V, Local>: NewKey,
//     {
//         let test_file: TestFile<Self> =
//             read_test(&format!("{}{}pie.json", V::KEY_HEADER, K::WRAP_HEADER));
//         for test in test_file.tests {
//             tests.push(Trial::test(test.name, || test.test_data.test::<V, K>()));
//         }
//     }

//     fn test<V: PieVersion, K: PieWrapType<V>>(self) -> Result<(), Failed>
//     where
//         Key<V, Local>: NewKey,
//     {
//         let wrapping_key = Key::<V, Local>::from_key(&self.wrapping_key);

//         let wrapped_key: PieWrappedKey<V, K> = match self.paserk.parse() {
//             Ok(wrapped_key) => wrapped_key,
//             Err(_) if self.expect_fail => return Ok(()),
//             Err(e) => return Err(e.to_string().into()),
//         };

//         if self.expect_fail {
//             match wrapped_key.unwrap_key(&wrapping_key) {
//                 Err(_) => Ok(()),
//                 Ok(_) => Err(self.comment.unwrap().into()),
//             }
//         } else {
//             let unwrapped = hex::decode(self.unwrapped.unwrap()).unwrap();

//             match wrapped_key.unwrap_key(&wrapping_key) {
//                 Err(err) => Err(err.to_string().into()),
//                 Ok(key) if key.as_ref() != unwrapped => Err("key mismatch".into()),
//                 Ok(_) => Ok(()),
//             }
//         }
//     }
// }

// trait NewKey {
//     fn from_key(s: &str) -> Self;
// }

// impl NewKey for Key<V3, Local> {
//     fn from_key(s: &str) -> Self {
//         let b = hex::decode(s).unwrap();
//         Self::from_bytes(b.try_into().unwrap())
//     }
// }

// impl NewKey for Key<V4, Local> {
//     fn from_key(s: &str) -> Self {
//         let b = hex::decode(s).unwrap();
//         Self::from_bytes(b.try_into().unwrap())
//     }
// }

// impl NewKey for Key<V3, Secret> {
//     fn from_key(s: &str) -> Self {
//         let b = hex::decode(s).unwrap();
//         Self::from_bytes(&b).unwrap()
//     }
// }

// impl NewKey for Key<V4, Secret> {
//     fn from_key(s: &str) -> Self {
//         let b = hex::decode(s).unwrap();
//         Self::from_keypair_bytes(&b).unwrap()
//     }
// }

// impl NewKey for Key<V3, Public> {
//     fn from_key(s: &str) -> Self {
//         let b = hex::decode(s).unwrap();
//         Self::from_sec1_bytes(&b).unwrap()
//     }
// }

// impl NewKey for Key<V4, Public> {
//     fn from_key(s: &str) -> Self {
//         let b = hex::decode(s).unwrap();
//         Self::from_public_key(&b).unwrap()
//     }
// }

// trait NewKey2 {
//     fn from_key2(s: &str) -> Self;
// }

// impl NewKey2 for Key<V3, Secret> {
//     fn from_key2(s: &str) -> Self {
//         Self::from_sec1_pem(s).unwrap()
//     }
// }

// impl NewKey2 for Key<V4, Secret> {
//     fn from_key2(s: &str) -> Self {
//         let b = hex::decode(s).unwrap();
//         Self::from_keypair_bytes(&b).unwrap()
//     }
// }
