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

## Test Fixtures

Sample code and scenarios live under `tests/test_files/`:

- `python/`, `javascript/`, etc. — language-specific fixtures
- `false_positives/` — patterns that must not be flagged
- `multi_file_taint_tests/` — cross-file taint scenarios

## Running Tests

```bash
cargo test                       # all suites
cargo test --test unit_tests
cargo test --test integration_tests
cargo test --test end_to_end_tests
cargo test pattern_matching      # filter by test name
```
