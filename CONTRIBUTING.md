# Contributing to Sighthound

Thank you for your interest in contributing! This document covers how to build,
test, and submit changes.

## Getting started

### Prerequisites

- Rust 1.89 or newer (see `rust-toolchain.toml`)
- Git

### Build

```bash
git clone https://github.com/Corgea/Sighthound.git
cd Sighthound
cargo build --release
```

The binary is at `target/release/sighthound`.

### Run tests

```bash
cargo test                    # all suites
cargo test --test unit_tests
cargo test --test integration_tests
cargo test --test end_to_end_tests
```

Test fixtures live under `tests/test_files/`.

### Formatting and linting

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
```

CI runs both checks on every pull request.

## Contributing rules

Security rules are RON files under `rules/<language>/`. See the
[Rule Writing Guide](rules/RULE_WRITING_GUIDE.md) for the full schema.

When adding or modifying rules:

1. Add or update test fixtures under `tests/test_files/` that demonstrate the
   vulnerability (true positive) or safe pattern (false negative).
2. Run the relevant test suites to confirm detection behavior.
3. Rebuild if testing embedded rules, or use `--use-file-rules` during development.

## Pull request guidelines

- Keep changes focused — one logical change per PR when possible.
- Update documentation if you change CLI flags, rule schema, or behavior.
- Add a CHANGELOG entry under `## Unreleased` for user-visible changes.
- Do not include real secrets, API keys, or credentials in test fixtures. Use
  obviously synthetic values (e.g. `AKIAFAKEKEY00000000`).

## Security

Please report security vulnerabilities in Sighthound privately. See
[SECURITY.md](SECURITY.md) — do not file them as public issues.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating, you agree to uphold it.
