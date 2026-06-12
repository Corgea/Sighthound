# Benchmarks

This directory contains scripts for comparing Sighthound against other static
analysis tools (e.g. Semgrep). Results are documented in [COMPARISON.md](COMPARISON.md).

## Prerequisites

- Python 3.10+
- A built `sighthound` binary at `../target/release/sighthound`
- The benchmark corpus (not included in this repository)

## Setup

Clone the benchmark corpus into the project root:

```bash
git clone <benchmark-corpus-url> fusion-benchmarks
```

The `fusion-benchmarks/` directory is gitignored because it is large and
maintained separately.

## Running benchmarks

```bash
# From the project root, after cargo build --release
python bench/run_bench.py
python bench/compare.py
python bench/score.py
```

Generated JSON artifacts are written to `bench/results/` and are gitignored.
