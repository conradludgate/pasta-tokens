#![no_main]

use libfuzzer_sys::fuzz_target;
use pasta_tokens::{paserk::wrap::fuzz_tests::FuzzInput, purpose::local::Local, version::V4};

fuzz_target!(|data: FuzzInput<V4, Local>| {
    data.run();
});
