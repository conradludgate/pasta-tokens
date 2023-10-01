#![no_main]

use libfuzzer_sys::fuzz_target;
use pasta_tokens::{paserk::wrap::PieWrappedKey, purpose::local::Local, version::V4};
use std::str::FromStr;

fuzz_target!(|data: &str| {
    let _ = PieWrappedKey::<V4, Local>::from_str(data);
    // fuzzed code goes here
});
