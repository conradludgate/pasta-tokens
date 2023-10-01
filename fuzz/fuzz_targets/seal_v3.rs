#![no_main]

use libfuzzer_sys::fuzz_target;
use pasta_tokens::paserk::pke::fuzz_tests::V3SealInput;

fuzz_target!(|data: V3SealInput| {
    data.run();
});
