//! Test runner.

use core::ops::{Deref, FnOnce};
use libtest_mimic::{Arguments, Failed, Trial};
use std::env;

/// Command-line arguments to ignore, because they are not supported by libtest-mimic.
const IGNORED_ARGS: [&str; 2] = ["-Zunstable-options", "--report-time"];

/// Runs all tests.
pub fn main(tests: Vec<Trial>) {
    let args = Arguments::from_iter(env::args().filter(|arg| !IGNORED_ARGS.contains(&arg.deref())));
    libtest_mimic::run(&args, tests).exit();
}

/// Runs the given test.
pub fn run(test: impl FnOnce()) -> Result<(), Failed> {
    test();
    Ok(())
}
