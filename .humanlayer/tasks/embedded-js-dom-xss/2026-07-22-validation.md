---
task: embedded-js-dom-xss
type: validation
repo: Corgea/Sighthound
branch: main
sha: 17ddd92d8f8ccded3d812943bdd95b1ab839a353
plan: .humanlayer/tasks/embedded-js-dom-xss/2026-07-22-plan.md
exec_plan: none
verdict: PASS
---

# Embedded JavaScript DOM-XSS Validation

## Overview

Validated the current working-tree implementation against the approved three-phase plan. The
implementation reparses executable inline script ranges as JavaScript, runs the canonical frontend
DOM-XSS taint rule with original template provenance, models configured promise fulfillment
sources, filters ineligible fallback findings, and prefers precise taint results at both scanner and
CLI merge points.

All required focused checks, the full repository check, release benchmark scans, corpus comparison,
and performance measurements passed. Fable independently approved the implementation with no
issues. The combined verdict is `PASS`.

## Scope and Inputs

- Plan: `.humanlayer/tasks/embedded-js-dom-xss/2026-07-22-plan.md`
- Task directory: `.humanlayer/tasks/embedded-js-dom-xss`
- ExecPlan: `none`
- Validation date: `2026-07-22`
- Baseline: `17ddd92d8f8ccded3d812943bdd95b1ab839a353` on `main`
- Working tree: dirty with the scoped implementation, fixtures, tests, and untracked task
  artifacts; no staged changes
- Tracked diff: 13 files, 681 insertions, 32 deletions, plus three HTML fixtures and one unit-test
  module

## Validation Verdict

**Local verdict**: `PASS`

**Fable verdict**: `approve`

**Combined verdict**: `PASS`

The current implementation covers all plan-required behavior and proof. No required check is
failing or unrun, no required manual validation remains, and no changed-code defect was found.

## Executed Checks

- `cargo test --test unit_tests embedded_js_dom_xss` — pass — 6 passed, 105 filtered out.
- `cargo test --lib embedded_js_dom_xss` — pass — 4 passed, 29 filtered out.
- `cargo test --test integration_tests embedded_dom_xss` — pass — binary-level default-mode
  precedence regression passed.
- `cargo test --test acceptance` — pass — 5 features, 8 scenarios, 31 steps.
- `cargo check --no-default-features --features html` — pass — HTML-only feature build succeeds.
  It emits two warnings at unchanged `src/language.rs:79` and `src/language.rs:96`;
  `git diff --exit-code HEAD -- src/language.rs` passes.
- `cargo fmt --check` — pass.
- `cargo clippy` — pass.
- `git diff --check` — pass.
- `cargo test` — pass — 211 Rust tests, all acceptance scenarios, and 1 doc test.
- `make check` — pass — Clippy fix, format, tests, and agent-drift checks all returned success; 211
  Rust tests passed. The command made no working-tree changes.
- `cargo build --release` — pass.
- `cargo harness agents-md-drift` — pass with the repository's non-blocking warning that the
  git-ignored `CLAUDE.md` mirror is absent.

## Plan Coverage

### Covered and Verified

- **Feature composition and parser lifetime**: `html` and `django` include JavaScript support.
  `LanguageParser::parse_with_included_ranges` resets included ranges after both successful parsing
  and range errors. The focused parser test verifies original rows across two disjoint ranges and a
  row-zero full parse after success and an invalid-range failure.
- **Executable script eligibility**: absent/empty type, module, accepted JavaScript/ECMAScript MIME
  spellings, case folding, and MIME parameters are covered. Empty bodies, `src`, JSON/data/template,
  plain-text, and unknown types are rejected. Range tests prove ordered, non-overlapping selection.
- **Cost boundary**: the production call site checks `ranges.is_empty()` before accessing the
  embedded parser and passes the entire range vector to one `parse_with_included_ranges` call.
- **Rule loading and partitioning**: default HTML/Django loading selects one semantic
  DOM/frontend XSS taint rule, errors when it is absent or ambiguous, and multi-language loading
  retains one copy. Filesystem/custom loaders are unchanged. Native/cross-file taint receives the
  canonical rule only when JavaScript/TypeScript files are present.
- **Applicability and provenance**: embedded applicability uses a JavaScript-shaped path while the
  finding, source, and sink retain the original HTML path and original tree-sitter rows.
- **Promise boundaries**: only an inline arrow/function expression in the first `.then(...)`
  argument is seeded, the receiver chain must match a configured source, and the source record is
  rooted at the original call. Tests cover function and arrow callbacks, rejection callbacks,
  unrelated promises, parameter-name coincidence, and sanitization.
- **Fallback behavior**: the exact `html-inline-dom-xss-001` tag gates eligibility and precedence.
  Search-only and unified scans remove ineligible blocks. Exact file/line/CWE overlap prefers a
  source-to-sink taint result, while file, line, CWE, other-rule, and unmatched-fallback cases remain.
  The CLI JSON integration test covers the separate simple-plus-taint merge.
- **Regression behavior**: standalone JavaScript acceptance passes. Full repository tests pass. Safe
  fixtures produce no embedded taint or tagged fallback for static, sanitized, unrelated, external,
  empty, data/template/unknown-type, rejection, or unrelated-promise cases.
- **Embedded parse error path**: the ranged parser restores full-document state before returning an
  error. The embedded caller logs the path-specific error and returns an empty embedded vector, so
  native HTML findings already collected for the file are retained.

### Benchmark Provenance

- DjangoAt release scan: exactly one `DOM-based XSS` / `cwe-79` result at absolute
  `signup.html:20`, sourced from `location.hash` at line 15. Finding, source, and sink use the
  original HTML path; tags include `taint_analysis` and `data_flow`.
- PyGoat release scan: exactly one `DOM-based XSS` / `cwe-79` result at absolute
  `mitre_lab_17.html:42`, sourced from `fetch(*).then` at line 36. Finding, source, and sink use the
  original HTML path; tags include `taint_analysis` and `data_flow`.

### Candidate Volume and Performance

Normalized search-only/default comparisons added exactly these keys and no others:

- `realvuln-djangoat/template/users/signup.html:20:cwe-79:DOM-based XSS`
- `realvuln-pygoat/introduction/templates/mitre/mitre_lab_17.html:42:cwe-79:DOM-based XSS`

Both additions are the required source-to-sink true positives. Release timing in the current run:

| Corpus | Search-only | Combined | Difference |
| --- | ---: | ---: | ---: |
| DjangoAt templates | 0.73s | 0.81s | +0.08s |
| PyGoat templates | 0.79s | 0.83s | +0.04s |

### Missing, Mismatched, or Unproven

- None.

## Pre-existing Diagnostics

`cargo clippy --all-targets --all-features -- -D warnings` exits 101 on four diagnostics:

- `clippy::items_after_test_module` in `src/scanner/output.rs:318`
- `clippy::cloned_ref_to_slice_refs` in `harness.rs:1515`
- `clippy::len_zero` in `tests/unit/django_xss_prevention_tests.rs:113`
- `clippy::needless_return` in `tests/unit/django_xss_prevention_tests.rs:128`

These files are unchanged: `git diff --exit-code HEAD -- src/scanner/output.rs harness.rs
tests/unit/django_xss_prevention_tests.rs` passes. Because the failing command enables all features,
the new feature dependency edges do not alter that compilation scope. These are pre-existing,
out-of-scope diagnostics, not changed-code defects. The repository's required default `cargo
clippy` and exact `make check` gate pass.

## Independent Fable Review

- Invocation: bundled Claude wrapper with `--model fable --effort high --permission-mode plan
  --output-format json` and a strict `approve|revise` JSON schema.
- Process result: exit 0, `is_error=false`, valid structured output.
- Verdict: `approve`
- Issues: none.
- Summary: Fable found the implementation aligned with the plan across parser reset, executable
  gating, rule loading/partitioning, callback boundaries, provenance, exact precedence, regression
  tests, benchmark output, corpus volume, and timing evidence. It found no blocking issue.
- Error: none. One compound read-only shell probe was denied by plan-mode permissions; the review
  completed successfully after repository inspection and returned a valid verdict.

## Blocking Findings

- None.

## Manual Validation Remaining

- None. The MIME table, parser-access boundary, benchmark JSON, added corpus keys, and timing results
  were reviewed during this validation.

## Recommendation

The implementation is ready for the Flow commit stage. Commit only the scoped Sighthound source,
rules, fixtures, tests, and task artifacts intended for this task.
