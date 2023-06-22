#![no_main]

use libfuzzer_sys::fuzz_target;
use rusty_paserk::fuzzing::seal::V4SealInput;

fuzz_target!(|data: V4SealInput| {
    data.run();
});
