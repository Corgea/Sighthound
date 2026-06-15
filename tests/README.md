# Test Organization

This directory contains all tests for Sighthound, organized into three suites.

## Directory Structure

- **unit/**: Tests for individual components
  - `injection_pattern_tests.rs`: Injection pattern detection
  - `django_xss_prevention_tests.rs`: Django XSS prevention
  - `file_pattern_tests.rs`: File pattern matching
  - `directory_loading_tests.rs`: Directory loading
  - `rule_deserialization_tests.rs`: Rule deserialization
  - `pattern_matching_tests.rs`: Pattern matching

- **integration/**: Tests for multiple components working together
  - `integration_tests.rs`: Rule parsing, scanning, and results integration

- **end_to_end/**: Full scanner flows
  - `end_to_end_injection_tests.rs`: End-to-end injection detection

- **strictness/**: Boundary and strictness contracts (Tier 1 + Tier 2)
  - `cross_file_taint.rs`: Phantom flows, config safety, valid chains
  - `taint_true_negatives.rs` / `taint_true_positives.rs`: Accuracy corpus
  - `false_positive_regressions.rs`: Documented FP regressions (e.g. cleartext)
  - `search_conditions.rs`: `shell=True`, Java XSS `Html.escape`
  - `sanitizer_and_scope.rs`: Sanitizer respect, scope boundaries
  - `django_security.rs`: Django fixture with production rules
  - `language_coverage.rs`: PHP taint, Go/Ruby non-secret checks, C# mode parity, fixture-discovery flag

## Test Fixtures

Sample code and scenarios live under `tests/test_files/`:

- `python/`, `javascript/`, etc. — language-specific fixtures
- `false_positives/` — patterns that must not be flagged
- `multi_file_taint_tests/` — cross-file taint scenarios
- `strictness_languages/` — focused PHP/Go/Ruby/C# strictness fixtures

## Running Tests

```bash
cargo test                       # all suites
cargo test --test unit_tests
cargo test --test integration_tests
cargo test --test end_to_end_tests
cargo test --test strictness_tests
cargo test pattern_matching      # filter by test name
```

Strictness tests stage fixtures into temp directories with neutral module names
so the test/migration prefilter does not skip files whose imports contain `test`.

For direct CLI validation against checked-in fixtures under `tests/`, use:

```bash
sighthound tests <language> <rules_path> --use-file-rules --include-test-fixtures
```

## Benchmark Gates

```bash
python3 tests/test_files/multi_file_taint_tests/run_comprehensive_tests.py
python3 tests/test_files/accuracy_tests/run_accuracy_tests.py
```

Both benchmark runners stage fixtures into temporary directories, parse the
scanner's current JSON finding array, and exit non-zero on expectation
mismatches. The accuracy benchmark reports precision, recall, F1, and accuracy.
