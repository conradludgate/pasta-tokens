#![no_main]

use libfuzzer_sys::fuzz_target;
use rusty_paserk::fuzzing::seal::V3SealInput;

fuzz_target!(|data: V3SealInput| {
    data.run();
});
