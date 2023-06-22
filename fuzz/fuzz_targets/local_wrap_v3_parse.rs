#![no_main]

use libfuzzer_sys::fuzz_target;
use std::str::FromStr;
use rusty_paserk::{PieWrappedKey, V3, Local};

fuzz_target!(|data: &str| {
    let _ = PieWrappedKey::<V3, Local>::from_str(data);
    // fuzzed code goes here
});
