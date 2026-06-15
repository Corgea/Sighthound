# Sighthound

<div align="center">

![Sighthound Logo](assets/logo.png)

A fast, AST-based static analysis scanner for finding security vulnerabilities
in source code. Built in Rust on top of [tree-sitter](https://tree-sitter.github.io/).

[![CI](https://github.com/Corgea/Sighthound/actions/workflows/ci.yml/badge.svg)](https://github.com/Corgea/Sighthound/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-1.89+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE-APACHE)

</div>

## Overview

Sighthound parses source into a syntax tree and applies two kinds of rules:

- **Search rules** match dangerous call sites, APIs, and patterns directly in
  the AST (e.g. `os.system(...)`, `eval(...)`, raw SQL string building).
- **Taint rules** track untrusted data from sources (request parameters, CLI
  args, file reads) to sinks (command execution, query builders, template
  rendering), both within a file and across files.

Rules are written in [RON](https://github.com/ron-rs/ron) and ship embedded in
the binary, so a scan needs no external configuration.

## Supported languages

| Language               | Extensions                               |
| ---------------------- | ---------------------------------------- |
| Python (incl. Django)  | `.py`, Django templates in `.html`       |
| JavaScript             | `.js`, `.jsx`                            |
| TypeScript / TSX       | `.ts`, `.tsx`                           |
| Java                   | `.java`                                  |
| Go                     | `.go`                                    |
| C#                     | `.cs`                                    |
| Ruby                   | `.rb`                                     |
| PHP                    | `.php`, `.phtml`                         |
| HTML                   | `.html`                                  |

Each language is a Cargo feature; all are enabled by default. Disable
`--no-default-features` and opt in to a subset to produce a smaller binary.

## Installation

Requires Rust 1.89 or newer.

```bash
git clone https://github.com/Corgea/Sighthound.git
cd Sighthound
cargo build --release
```

Or install from crates.io:

```bash
cargo install sighthound
```

The binary is written to `target/release/sighthound`.

### Cross-platform / container builds

`build_all_platforms.sh` cross-compiles release binaries. To produce a
Linux binary via Docker:

```bash
DOCKER_BUILDKIT=1 docker build \
  --target export \
  --output type=local,dest=./sighthound_release \
  .
```

## Usage

```bash
# Auto-detect languages and scan a project with the embedded rules
sighthound /path/to/project

# Scan a single language with a specific rule file or directory
sighthound /path/to/project python rules/python --use-file-rules

# Run only taint (data-flow) analysis
sighthound --taint-analysis /path/to/project

# Run only pattern/search analysis
sighthound --simple-analysis /path/to/project

# Machine-readable output
sighthound --output-format json /path/to/project > findings.json
```

By default Sighthound runs both search and taint analysis and prints a
human-readable report. Coloured output is automatically disabled when stdout
is not a terminal or when `NO_COLOR` is set.

### Example

```
sighthound  scanning /path/to/project
  languages   python, javascript  (detected in 4.1ms)
  mode        parallel (8 threads)

  scanned 1,247 files · 127 rules · 2 languages
  discovery 4.1ms · analysis 1.21s

Findings

/path/to/project/app.py

    ● Command Injection (cwe-78) line 42
    source HTTP Request (request.args)
    sink   Command Execution (os.system)

        40 |     cmd = request.args["cmd"]
        41 |     # build and run
    >>  42 |     os.system("ls " + cmd)

Summary
  ● 1 critical   ● 2 high

     2  Command Injection
     1  SQL Injection

  3 findings in 1.23s
```

## Options

```
sighthound [OPTIONS] <ROOT_DIR> [LANGUAGE] [RULES_PATH]

Arguments:
  <ROOT_DIR>      Directory to scan
  [LANGUAGE]      Language to scan (used with a rules path for explicit mode)
  [RULES_PATH]    Path to a .ron rule file or a directory of rule files

Options:
  -o, --output-format <FORMAT>   text | json | csv               [default: text]
  -v, --verbose                  Verbose (debug-level) logging
  -s, --summary-only             Print only the summary, not individual findings
      --taint-analysis           Run only taint analysis
      --simple-analysis          Run only pattern/search analysis
      --use-file-rules           Load rules from disk instead of the embedded set
      --rules-dir <DIR>          Rules directory to use with --use-file-rules
      --skip-minified <BOOL>     Skip minified JS files               [default: true]
      --code-type <TYPE>         frontend | backend | both
      --language-filter <LANG>   Restrict scanning to one language
      --single-threaded          Disable parallel processing
      --threads <N>              Worker thread count                  [default: CPU cores]
      --version                  Print version information
  -h, --help                     Print help
```

Logging level can also be set with `RUST_LOG` (e.g. `RUST_LOG=debug`), and the
thread count with `RAYON_NUM_THREADS`.

## Rules

Rules live under `rules/<language>/` and are written in RON. A rule is either a
`search` rule or a `taint` rule:

```ron
(
    rules: [
        (
            id: Some("python-cmd-injection"),
            name: Some("Command Injection"),
            category: Some("injection"),
            mode: "taint",
            sources: Some(["request.args", "request.form", "input(", "sys.argv"]),
            sinks: Some(["os.system", "subprocess.call", "os.popen"]),
            sanitizers: Some(["shlex.quote"]),
            finding_type: Some("Command Injection"),
            severity: Some("Critical"),
            confidence: Some("High"),
            cwe_id: Some("cwe-78"),
            file_types: Some((extensions: Some([".py"]))),
        ),
    ]
)
```

See the [Rule Writing Guide](rules/RULE_WRITING_GUIDE.md) for the full schema,
including search patterns, AST conditions, and file-type filters. After editing
rules under `rules/`, rebuild to refresh the embedded set, or scan with
`--use-file-rules` to load them directly.

## Architecture

```
src/
├── main.rs              CLI entry point
├── lib.rs               Library exports
├── cli.rs               Argument parsing
├── models.rs            Core types (Finding, TaintFlow, UnifiedRule, ...)
├── language.rs          Per-language tree-sitter support
├── rules.rs             Rule loading and pattern matching
├── parser.rs            Tree-sitter AST helpers
├── config.rs            Defaults and skip lists
├── ui.rs                Terminal output formatting
├── code_type_detector.rs  Frontend/backend classification
└── scanner/
    ├── core.rs          Scanning engine and reporting
    ├── modes.rs         Auto-detection / explicit / taint scan modes
    ├── conditions.rs    AST condition evaluation
    ├── utils.rs         File discovery and language detection
    └── prefilter.rs     Early file/function filtering
```

A scan flows from file discovery, to language detection, to rule loading, to
AST parsing, then runs search and taint passes in parallel and filters the
combined results before printing.

## Testing

```bash
cargo test                       # all suites
cargo test --test unit_tests
cargo test --test integration_tests
cargo test --test end_to_end_tests
```

Sample inputs live under `tests/test_files/`, organised into true positives,
true negatives, edge cases, and multi-file taint scenarios.

## Library API

Sighthound can be used as a Rust library. See `examples/basic_scan.rs` for a
minimal programmatic scan:

```rust
use sighthound::{run_auto_detection_scan, Cli};

let cli = Cli::parse_from(["sighthound", "/path/to/project"]);
let findings = run_auto_detection_scan(&cli, "/path/to/project", false)?;
```

The library API is **unstable** before v1.0 — minor releases may include
breaking changes to public modules.

## Known limitations

- Minified/bundled JavaScript is skipped by filename heuristics
  (`--skip-minified`); disabling it can increase noise.
- Cross-file taint analysis is best-effort and still being hardened.
- Runtime-only or reflection-based vulnerabilities are out of scope for static
  pattern matching.
- Very large single files (>10 MB) can slow analysis.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Embedded rules under `rules/` are distributed under the same
license as the project. The Sighthound logo in `assets/logo.png` is © Corgea and
included under the project license.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues should be reported per
[SECURITY.md](SECURITY.md) — please do not file scanner bypasses or
vulnerabilities in Sighthound itself as public issues.

Developed by the [Corgea](https://github.com/Corgea) team.
