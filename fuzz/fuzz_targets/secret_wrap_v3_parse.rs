#![no_main]

use libfuzzer_sys::fuzz_target;
use pasta_tokens::{paserk::wrap::PieWrappedKey, purpose::public::Secret, version::V3};
use std::str::FromStr;

fuzz_target!(|data: &str| {
    let _ = PieWrappedKey::<V3, Secret>::from_str(data);
    // fuzzed code goes here
});
