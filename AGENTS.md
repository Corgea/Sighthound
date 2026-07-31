# CLAUDE

## Commands

`make` targets delegate to the `cargo harness` runner (`harness.rs`). Pass tunable
flags (`--min`, `--max`, `--enforce`) by invoking the runner directly, e.g.
`cargo harness crap --enforce`.

- After edits: `make check` — fix, format, lint, test, suppression report
- Pre-commit: `make pre-commit` — staged Rust files only (auto via git hook)
- Pre-push: `make pre-push` — read-only push gate: clippy + format check → acceptance → arch (auto via git hook; validates the whole pushed tree)
- CI: `make ci` — strict pipeline: clippy → format check → audit → complexity → tests → acceptance → coverage → crap → arch. CRAP is advisory (warns only — pass `--enforce` to hard-fail). Requires `uvx` on PATH.
- Complexity: `make complexity` — lizard@1.22.2 CC gate (CCN≤15, args≤8, length≤100) over src + tests
- CRAP (advisory): `cargo harness crap --max=30` — complexity × coverage gate (joins lizard --csv with `target/llvm-cov/lcov.info`). Add `--enforce` to exit 1 on offenders (default exits 0 with warning).
- Audit: `make audit` — audit dependencies for known vulnerabilities (via cargo-audit)
- Acceptance: `make acceptance` — run cucumber against `tests/features/` (warns and skips with no `.feature` files)
- Coverage: `cargo harness coverage --min=0` — cargo-llvm-cov line coverage with threshold
- Mutation (advisory): `make mutation` — cargo-mutants kill-rate on the crate
- Arch: `make arch` — cargo-modules checks against `arch.toml`
- Agents drift: `make agents-md-drift` — fail if the local CLAUDE.md mirror differs from AGENTS.md (AGENTS.md is the committed source; edit it, not CLAUDE.md)
- Sync: `make sync-agents-md` — rewrite the git-ignored CLAUDE.md mirror from AGENTS.md
- Setup: `make setup-hooks` to install git pre-commit + pre-push hooks and materialize the git-ignored agent files (CLAUDE.md mirror plus the `.claude/` + `.codex/` Stop hook wiring)
- Stop hook: auto-formats/fixes changed files, then runs complexity and CRAP (`make stop-hook`)

## Python / Django test naming

Pytest and scan fixtures both live under these trees — do not put Python/Django pytest elsewhere (e.g. not `tmp_tests/`):

- `tests/test_files/python/`
- `tests/test_files/django/`

1. **Pytest** (executable checks at the tree root): use pytest throughout.
   - Files: `test_*.py`
   - Functions: `test_*`
   - Classes: `Test*`
   - Do not use `*_test.py` — both work with pytest, but this repo standardizes on the prefix form.

2. **Scan fixtures** (vulnerable/safe sample code scanned by Rust tests — not pytest):
   - Live under `fixtures/` only: `tests/test_files/python/fixtures/`, `tests/test_files/django/fixtures/`
   - Name by topic: `sql_injection.py`, `command_injection.py`, `views.py`
   - Avoid `test_*.py` / `*_test.py` and `def test_*` so fixtures are not collected by pytest and do not collide with scanner test-skip patterns.
   - Django app samples use app-like names (`views.py`, `migration_sample.py`).

## Agent skill

CLI flag or output-format changes must also update the agent skill at https://github.com/Corgea/skills (`plugins/sighthound/skills/sighthound/SKILL.md`).
