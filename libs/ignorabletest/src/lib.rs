//! Test harness which supports ignoring tests at runtime.

pub mod runner;

#[doc(hidden)]
pub use libtest_mimic as _libtest_mimic;
#[doc(hidden)]
pub use paste as _paste;

/// Macro to generate the main function for the test harness.
#[macro_export]
macro_rules! test_main {
    ($tests:expr) => {
        #[cfg(test)]
        fn main() {
            ignorabletest::runner::main($tests)
        }
    };
}

/// Macro to generate a function which returns a list of tests to be run.
///
/// # Usage
/// ```
/// list_tests!{all_tests: [test_this, test_that]};
///
/// test!(test_this);
/// fn test_this() {
///   // ...
/// }
///
/// test!(test_that);
/// fn test_that() {
///   // ...
/// }
/// ```
#[macro_export]
macro_rules! list_tests {
    {$function_name:ident: [$( $test_name:ident ),* $(,)? ]} => {
        pub fn $function_name() -> ::std::vec::Vec<$crate::_libtest_mimic::Trial> {
            vec![
                $( $crate::_paste::paste!([<__test_ $test_name>]()) ),*
            ]
        }
    };
}

/// Macro to generate a wrapper function for a single test.
///
/// # Usage
///
/// ```
/// test!(test_string_equality);
/// fn test_string_equality() {
///   assert_eq!("", "");
/// }
/// ```
#[macro_export]
macro_rules! test {
    ($test_name:ident) => {
        $crate::_paste::paste!(
            fn [< __test_ $test_name >]() -> $crate::_libtest_mimic::Trial {
                $crate::_libtest_mimic::Trial::test(
                    ::std::stringify!($test_name),
                    move || ignorabletest::runner::run($test_name),
                )
            }
        );
    };
    ($test_name:ident, ignore_if: $ignore_expr:expr) => {
        $crate::_paste::paste!(
            fn [< __test_ $test_name >]() -> $crate::_libtest_mimic::Trial {
                $crate::_libtest_mimic::Trial::test(
                    ::std::stringify!($test_name),
                    move || ignorabletest::runner::run($test_name),
                ).with_ignored_flag($ignore_expr)
            }
        );
    };
}
