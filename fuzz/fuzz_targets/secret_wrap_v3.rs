#![no_main]

use libfuzzer_sys::fuzz_target;
use rusty_paserk::fuzzing::wrap::FuzzInput;
use rusty_paserk::{V3, Secret};

fuzz_target!(|data: FuzzInput<V3, Secret>| {
    data.run();
});
