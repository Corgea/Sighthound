# Sighthound

<div align="center">

![Sighthound Logo](assets/logo.png)

Tree-sitter based static vulnerability scanner with pattern matching and taint-flow analysis.

[![Rust](https://img.shields.io/badge/rust-1.85+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/Corgea/Sighthound/actions/workflows/ci.yml/badge.svg)](https://github.com/Corgea/Sighthound/actions/workflows/ci.yml)

</div>

> **Want Sighthound without the setup?** [Sign up for Corgea](https://corgea.app),
> where Sighthound is built in alongside AI SAST, secrets, container, dependency,
> and IaC scanning—with false-positive reduction and automated fixes.

## What It Does

- Scans source code for security issues using AST-aware rules.
- Supports pattern mode and taint mode (source to sink tracking).
- Handles multi-file projects and parallel execution.
- Outputs findings as text, JSON, CSV, or SARIF.
- Loads embedded rule packs by file extension, with optional file-based custom rules.

## Language Support

| Language | Extensions | Parser | Bundled Rules |
|---|---|---|---|
| Python | `.py`, `.pyw`, `.pyi`, `.pyx` | Yes | Yes |
| JavaScript | `.js`, `.mjs`, `.cjs`, `.jsx`, `.vue`, `.svelte` | Yes | Yes |
| TypeScript / TSX | `.ts`, `.tsx`, `.mts`, `.cts` | Yes | Yes (JS rules) |
| Java | `.java` | Yes | Yes |
| PHP | `.php`, `.phtml` | Yes | Yes |
| C# | `.cs`, `.csx` | Yes | Yes |
| Go | `.go` | Yes | Yes |
| Ruby | `.rb` | Yes | Yes |
| ObjectScript | `.cls`, `.mac`, `.inc`, `.int`, `.rtn` | Yes (class and routine grammars) | Yes |
| HTML | `.html`, `.htm`, `.twig`, `.ejs`, `.hbs`, ... | Yes | Yes |
| Django templates | `.html` (Django syntax) | Yes | Yes (HTML rules) |

Not currently supported: Razor (`.cshtml`), C/C++ (`.c`, `.h`).

## Installation

Prerequisites:
- Rust 1.85+
- Git

Build from source:

```bash
git clone https://github.com/Corgea/Sighthound.git
cd Sighthound
cargo build --release
```

Binary path: `target/release/sighthound`

Linux-container-compatible release export:

```bash
DOCKER_BUILDKIT=1 docker build \
  --target export \
  --output type=local,dest=./sighthound_release \
  .
```

Or run `./build_all_platforms.sh`.

### Agent skill

Using Claude Code, Cursor, Codex, or another coding agent? Install the
[Sighthound skill](https://github.com/Corgea/skills) so your agent knows how
to install the scanner, run it, and act on its findings:

```bash
npx skills add corgea/skills --skill sighthound
```

## Quick Start

```bash
# Auto-detect languages and run embedded rules
cargo run --bin sighthound -- /path/to/project

# Explicit language + custom rules path
cargo run --bin sighthound -- /path/to/project python rules/python

# Taint-only scan and JSON output
cargo run --bin sighthound -- --taint-analysis --output-format json /path/to/project > findings.json

# SARIF output for GitHub Code Scanning
cargo run --bin sighthound -- --output-format sarif /path/to/project > results.sarif
```

CLI shape:

```bash
sighthound [OPTIONS] <ROOT_DIR> [LANGUAGE] [RULES_PATH]
```

Run `sighthound --help` for the full option list.

## GitHub Code Scanning

The `sarif` output format writes SARIF 2.1.0, which GitHub Code Scanning
ingests directly. Upload it from a workflow so findings appear inline on the
pull request and in the repository's Security tab:

Run the scan from the repository root and use `.` (or the repository root's
absolute path) as `<ROOT_DIR>` so SARIF artifact URIs stay repository-relative.

```yaml
- name: Run Sighthound
  run: sighthound --output-format sarif . > results.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Rules

Rules are written in RON and support both:
- `mode: "search"` for pattern matching
- `mode: "taint"` for source/sink/sanitizer analysis

Start here:
- [Rule Writing Guide](rules/RULE_WRITING_GUIDE.md)
- [Bundled rules directory](rules)

## Development

Core commands:

```bash
make check        # fix + format + lint + test + suppression report
make pre-commit   # staged Rust files (hook)
make pre-push     # push gate checks
make ci           # strict CI pipeline
```

Additional quality gates:

```bash
make complexity
make audit
make acceptance
cargo harness coverage --min=0
cargo harness crap --max=30
```

## Limitations

- Runtime-only vulnerabilities in dynamic code paths may be missed.
- Very large files can increase scan time.
- Multi-file taint is supported but still an area to harden further.

## Contributing

- [Contributing Guide](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Policy](SECURITY.md)

## License

- [MIT License](LICENSE)
- [Third-Party Notices](THIRD-PARTY-NOTICES.md)
