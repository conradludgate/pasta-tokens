#![no_main]

use libfuzzer_sys::fuzz_target;
use rusty_paserk::fuzzing::wrap::FuzzInput;
use rusty_paserk::{V4, Secret};

fuzz_target!(|data: FuzzInput<V4, Secret>| {
    data.run();
});
