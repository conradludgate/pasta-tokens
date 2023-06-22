#![no_main]

use libfuzzer_sys::fuzz_target;
use rusty_paserk::fuzzing::wrap::FuzzInput;
use rusty_paserk::{V3, Local};

fuzz_target!(|data: FuzzInput<V3, Local>| {
    data.run();
});
