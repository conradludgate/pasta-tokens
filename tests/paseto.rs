use std::fs;

use libtest_mimic::{Arguments, Failed, Trial};
use pasta_tokens::purpose::local::{EncryptedToken, LocalVersion, SymmetricKey, UnencryptedToken};
use pasta_tokens::purpose::public::{PublicKey, PublicVersion, SecretKey, SignedToken};
use pasta_tokens::version::{V3, V4};
use serde::{
    de::{DeserializeOwned, Visitor},
    Deserialize,
};

fn main() {
    let mut args = Arguments::from_args();
    args.test_threads = Some(1);

    let mut tests = vec![];

    PasetoTest::add_all_tests(&mut tests);
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
        Self::add_tests::<V4>(tests);
    }

    fn add_tests<V: LocalVersion + PublicVersion>(tests: &mut Vec<Trial>)
    where
        PublicKey<V>: ParseKey,
        SecretKey<V>: ParseKey,
        SymmetricKey<V>: ParseKey,
    {
        let test_file: TestFile<Self> = read_test(&format!("{}.json", V::PASETO_HEADER));
        for test in test_file.tests {
            tests.push(Trial::test(test.name, || test.test_data.test::<V>()));
        }
    }

    fn test<V: LocalVersion + PublicVersion>(self) -> Result<(), Failed>
    where
        PublicKey<V>: ParseKey,
        SecretKey<V>: ParseKey,
        SymmetricKey<V>: ParseKey,
    {
        match self {
            PasetoTest {
                token,
                footer,
                implicit_assertion,
                purpose: PasetoPurpose::Local { key, .. },
                result: TestResult::Failure { .. },
            } => {
                let key = SymmetricKey::<V>::from_key(&key);

                let Ok(token): Result<EncryptedToken<V, Vec<u8>>, _> = token.parse() else {
                    return Ok(());
                };
                assert_eq!(token.footer(), footer.as_bytes());

                match token.decrypt::<serde_json::Value>(&key, implicit_assertion.as_bytes()) {
                    Ok(_) => Err("decrypting token should fail".into()),
                    Err(_) => Ok(()),
                }
            }
            PasetoTest {
                token: token_str,
                footer,
                implicit_assertion,
                purpose: PasetoPurpose::Local { nonce, key },
                result: TestResult::Success { payload, .. },
            } => {
                let key = SymmetricKey::<V>::from_key(&key);
                let token: EncryptedToken<V, Vec<u8>> = token_str.parse().unwrap();
                assert_eq!(token.footer(), footer.as_bytes());

                let decrypted_token = token
                    .decrypt::<serde_json::Value>(&key, implicit_assertion.as_bytes())
                    .unwrap();

                let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
                assert_eq!(decrypted_token.message, payload);

                let nonce = hex::decode(nonce).unwrap().try_into().unwrap();

                let token = UnencryptedToken::new(decrypted_token.message)
                    .with_footer(decrypted_token.footer)
                    .encrypt_with_nonce(&key, nonce, implicit_assertion.as_bytes())
                    .unwrap();

                assert_eq!(token.to_string(), token_str);

                Ok(())
            }
            PasetoTest {
                token,
                footer,
                implicit_assertion,
                purpose: PasetoPurpose::Public { public_key, .. },
                result: TestResult::Failure { .. },
            } => {
                let public_key = PublicKey::<V>::from_key(&public_key);

                let Ok(token): Result<SignedToken<V, Vec<u8>>, _> = token.parse() else {
                    return Ok(());
                };
                assert_eq!(token.footer(), footer.as_bytes());

                match token.verify::<serde_json::Value>(&public_key, implicit_assertion.as_bytes())
                {
                    Ok(_) => Err("verifying token should fail".into()),
                    Err(_) => Ok(()),
                }
            }
            PasetoTest {
                token: token_str,
                footer,
                implicit_assertion,
                purpose:
                    PasetoPurpose::Public {
                        public_key,
                        secret_key,
                    },
                result: TestResult::Success { payload, .. },
            } => {
                let public_key = PublicKey::<V>::from_key(&public_key);
                let secret_key = SecretKey::<V>::from_key(&secret_key);

                let token: SignedToken<V, Vec<u8>> = token_str.parse().unwrap();
                assert_eq!(token.footer(), footer.as_bytes());

                let token = token
                    .verify::<serde_json::Value>(&public_key, implicit_assertion.as_bytes())
                    .unwrap();

                let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
                assert_eq!(token.message, payload);

                let token = token
                    .sign(&secret_key, implicit_assertion.as_bytes())
                    .unwrap();

                assert_eq!(token.to_string(), token_str);

                Ok(())
            }
        }
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
        #[allow(dead_code)]
        expect_fail: Bool<false>,
        payload: String,
    },
    #[serde(rename_all = "kebab-case")]
    Failure {
        #[allow(dead_code)]
        expect_fail: Bool<true>,
        #[allow(dead_code)]
        payload: (),
    },
}

trait ParseKey {
    fn from_key(s: &str) -> Self;
}

impl ParseKey for SymmetricKey<V3> {
    fn from_key(s: &str) -> Self {
        let b = hex::decode(s).unwrap();
        Self::from_bytes(b.try_into().unwrap())
    }
}

impl ParseKey for SymmetricKey<V4> {
    fn from_key(s: &str) -> Self {
        let b = hex::decode(s).unwrap();
        Self::from_bytes(b.try_into().unwrap())
    }
}

impl ParseKey for SecretKey<V3> {
    fn from_key(s: &str) -> Self {
        let b = hex::decode(s).unwrap();
        Self::from_bytes(&b).unwrap()
    }
}

impl ParseKey for SecretKey<V4> {
    fn from_key(s: &str) -> Self {
        let b = hex::decode(s).unwrap();
        Self::from_keypair_bytes(&b).unwrap()
    }
}

impl ParseKey for PublicKey<V3> {
    fn from_key(s: &str) -> Self {
        let b = hex::decode(s).unwrap();
        Self::from_sec1_bytes(&b).unwrap()
    }
}

impl ParseKey for PublicKey<V4> {
    fn from_key(s: &str) -> Self {
        let b = hex::decode(s).unwrap();
        Self::from_public_key(&b).unwrap()
    }
}
