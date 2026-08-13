//! Strictness boundary tests — real-world scenarios that must not cross normal limits.
//!
//! Fixtures under `tests/test_files/` are staged into temp directories with neutral
//! module names so the test/migration prefilter (which keys off import text containing
//! "test") does not exclude them.

mod helpers;

mod ast_provenance;
mod cross_file_taint;
mod django_security;
mod false_positive_regressions;
mod language_coverage;
mod sanitizer_and_scope;
mod search_conditions;
mod taint_true_negatives;
mod taint_true_positives;
