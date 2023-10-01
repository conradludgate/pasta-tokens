#![no_main]

use libfuzzer_sys::fuzz_target;
use pasta_tokens::{paserk::wrap::fuzz_tests::FuzzInput, version::V3, purpose::local::Local};

fuzz_target!(|data: FuzzInput<V3, Local>| {
    data.run();
});
