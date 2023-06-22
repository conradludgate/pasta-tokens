#![no_main]

use libfuzzer_sys::fuzz_target;
use std::str::FromStr;
use rusty_paserk::{PieWrappedKey, V4, Secret};

fuzz_target!(|data: &str| {
    let _ = PieWrappedKey::<V4, Secret>::from_str(data);
    // fuzzed code goes here
});
