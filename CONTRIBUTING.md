# Contributing to Sighthound

Thanks for your interest in improving Sighthound. This guide covers the build
and contribution workflow.

## Prerequisites

- Rust stable 1.88+ via [rustup](https://rustup.rs/) (the dev harness uses
  edition 2024)
- Git

For full CI parity, install the tools CI uses:

```bash
make tools    # llvm-tools-preview component + cargo-audit, cargo-llvm-cov, cargo-modules
```

`cargo-audit` is required — `make ci` fails without it. The others degrade to a
skipped check, but installing them gives you the exact CI result. The complexity
gate additionally uses [uv](https://docs.astral.sh/uv/) (`uvx`); it is advisory,
so skipping it never blocks.

## Setup

```bash
git clone https://github.com/Corgea/Sighthound.git
cd Sighthound
make bootstrap                 # install git pre-commit + pre-push hooks
cargo build --release          # binary at target/release/sighthound
```

## Before you open a PR

```bash
make ci
```

This is the exact command CI runs: clippy (`-D warnings`) → `cargo fmt --check` →
`cargo audit` → complexity (advisory) → `cargo test` → acceptance → coverage →
CRAP (advisory) → architecture check. If `make ci` passes locally, CI passes.

Faster inner-loop targets:

| Target           | Action                                            |
|------------------|---------------------------------------------------|
| `make check`     | auto-fix clippy + format, run tests               |
| `make fix`       | `cargo clippy --fix` + `cargo fmt`                |
| `make lint`      | clippy + `fmt --check` (read-only)                |
| `make test`      | `cargo test`                                      |
| `make ci`        | full CI pipeline — run before every PR            |
| `make bootstrap` | install git hooks                                 |

The hooks from `make bootstrap` run `make pre-commit` (staged Rust files) and
`make pre-push` (lint + acceptance + arch) automatically, catching most CI
failures before they leave your machine.

## Tests

`cargo test` runs the unit, integration, and end-to-end harnesses and is a
blocking CI gate — keep it green.

```bash
cargo test                     # all harnesses
cargo test --test unit_tests   # a single harness
```

## Multi-platform builds

`build_all_platforms.sh` produces Linux x64/arm64 (via Docker + buildx) and a
native macOS binary; the `Dockerfile` provides a containerized build. These
require Docker with buildx.

## Writing rules

Rules are RON (Rusty Object Notation) files under `rules/<lang>/`. See the
[Rule Writing Guide](rules/RULE_WRITING_GUIDE.md) for the rule format and
authoring guidance.

## Pull request workflow

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/your-feature`.
3. Make your changes and add tests.
4. Run `make ci` — the same command CI runs — and confirm it passes.
5. Submit a pull request.

By contributing, you agree your contributions are licensed under the MIT
License (see [LICENSE](LICENSE)) and that you will follow our
[Code of Conduct](CODE_OF_CONDUCT.md).
