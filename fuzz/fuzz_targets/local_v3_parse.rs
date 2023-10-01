#![no_main]

use libfuzzer_sys::fuzz_target;
use pasta_tokens::{purpose::local::EncryptedToken, version::V3, Json};
use std::str::FromStr;

#[derive(serde::Serialize, serde::Deserialize)]
struct Footer {
    kid: String,
}

fuzz_target!(|data: &str| {
    let _ = EncryptedToken::<V3, Json<Footer>>::from_str(data);
    // fuzzed code goes hereå
});
