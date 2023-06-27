//! Test runner.

use core::ops::{Deref, FnOnce};
use libtest_mimic::{Arguments, Failed, Trial};
use linkme::distributed_slice;
use log::Level;
use std::env;

/// Command-line arguments to ignore, because they are not supported by libtest-mimic.
const IGNORED_ARGS: [&str; 2] = ["-Zunstable-options", "--report-time"];

/// The collection of all tests to run.
#[doc(hidden)]
#[distributed_slice]
pub static IGNORABLETEST_TESTS: [fn() -> Trial] = [..];

/// Runs all tests.
pub fn main() {
    logger::init(logger::Config::default().with_min_level(Level::Debug));
    let args = Arguments::from_iter(env::args().filter(|arg| !IGNORED_ARGS.contains(&arg.deref())));
    let tests = IGNORABLETEST_TESTS.iter().map(|test| test()).collect();
    libtest_mimic::run(&args, tests).exit();
}

/// Runs the given test.
pub fn run(test: impl FnOnce()) -> Result<(), Failed> {
    test();
    Ok(())
}
