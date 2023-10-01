#![no_main]

use libfuzzer_sys::fuzz_target;
use pasta_tokens::{purpose::public::SignedToken, version::V3, Json};
use std::str::FromStr;

#[derive(serde::Serialize, serde::Deserialize)]
struct Footer {
    kid: String,
}

fuzz_target!(|data: &str| {
    let _ = SignedToken::<V3, Json<Footer>>::from_str(data);
    // fuzzed code goes hereå
});
