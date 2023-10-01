#![no_main]

use libfuzzer_sys::fuzz_target;
use pasta_tokens::{fuzzing::FuzzInput, purpose::public::Secret, version::V3};

fuzz_target!(|data: FuzzInput<V3, Secret>| {
    data.run();
});
