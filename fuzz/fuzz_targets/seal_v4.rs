#![no_main]

use libfuzzer_sys::fuzz_target;
use pasta_tokens::paserk::pke::fuzz_tests::V4SealInput;

fuzz_target!(|data: V4SealInput| {
    data.run();
});
