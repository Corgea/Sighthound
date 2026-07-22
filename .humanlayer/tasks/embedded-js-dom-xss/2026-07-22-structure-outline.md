---
task: embedded-js-dom-xss
type: structure-outline
repo: Corgea/Sighthound
branch: main
sha: 17ddd92d8f8ccded3d812943bdd95b1ab839a353
---

# Embedded JavaScript DOM-XSS Scanning

Add a narrow per-file phase that reparses executable inline script bodies as JavaScript over the
original HTML byte buffer, then sends that tree through the existing frontend DOM-XSS taint
engine. Deliver the browser-controlled benchmark first, extend the same path for remote promise
responses, and finish with finding precedence, safe-case coverage, and corpus validation.

## Current State

- HTML and Django files use `tree_sitter_html`; inline JavaScript is exposed to search rules as one
  `script_element`, not as JavaScript statements or expressions.
- `html-inline-dom-xss-001` matches a limited set of backtick-based sink spellings across the full
  script element. It cannot prove source-to-sink flow through local variables, concatenation, or
  callbacks.
- `js-dom-xss-taint-001` already defines the production frontend source, sink, and sanitizer policy,
  but its file applicability is JavaScript-shaped and its location sources omit unqualified
  `location.hash` and `location.search`.
- The single-file taint pass tracks assignments and propagation in two passes. Function parameters
  become sources only when their names match a source token, so a `.then(response => ...)` callback
  does not inherit taint from a configured remote source such as `fetch`.
- Taint findings already retain the reporting path, source and sink evidence, original line numbers,
  and `taint_analysis` / `data_flow` tags.
- No scanner-invoking regression test currently covers the production HTML DOM-XSS rule or inline
  JavaScript taint analysis.

## Desired End State

- HTML and template files with eligible inline scripts receive one additional JavaScript parse over
  only their executable `raw_text` ranges; files without an eligible range receive no second parse.
- Inline scripts with no `type`, a recognized JavaScript/ECMAScript MIME type, or `type="module"` are
  eligible. Empty bodies, external scripts, unknown or non-JavaScript types, and data/template blocks
  are skipped.
- Only the canonical frontend DOM-XSS taint rule runs in the embedded phase. Native HTML rules,
  custom file-rule behavior, and cross-file taint remain unchanged.
- Unqualified URL fragment/query sources and configured remote promise sources propagate through the
  two held-out benchmark shapes into `document.write` and `innerHTML`.
- Each benchmark produces one DOM-XSS finding on the real sink line with the original template path,
  source/sink evidence, and existing taint tags.
- Static sinks, sanitized values, `textContent`, unrelated source/sink code, external scripts, and
  non-JavaScript script types remain finding-free.
- The existing HTML backtick rule remains available as fallback coverage, while an embedded taint
  finding wins when both rules identify the same file, sink line, and CWE.

## What we're not doing

- Building a generic polyglot or tree-sitter injection framework.
- Fetching external scripts or joining their flow state to template files.
- Adding cross-file taint for embedded scripts.
- Covering inline event-handler attributes, CSS, server-side template encoding, or new DOM sinks.
- Adding a rule-schema field, dependency, feature flag, persisted state, or CLI option.
- Replacing `html-inline-dom-xss-001`; it remains the fallback for dynamic sinks without a configured
  taint source.
- General promise scheduling or async data-flow modeling beyond fulfillment callbacks rooted in a
  configured source. A broader embedded-language framework can be revisited when another concrete
  consumer requires it.

### Patterns to follow

#### Keep parsing and scanning as separate per-file phases

Follow the current per-file flow: parse once, retain the original mapped source bytes and path, and
pass the resulting tree to a scanner entry point. The embedded phase adds a second tree without
creating a synthetic buffer or changing the outer Rayon work model.

```rust
let tree = parser.parse(source)?;

file_findings.extend(ScanningLogic::scan_file_with_taint_rules(
    &filepath_str,
    source,
    &tree,
    rules.taint_rules,
    parser.language_support(),
));
```

Reference:
[src/scanner/vulnerability_scanner.rs](https://github.com/Corgea/Sighthound/blob/17ddd92d8f8ccded3d812943bdd95b1ab839a353/src/scanner/vulnerability_scanner.rs#L436-L496)

#### Preserve original coordinates with tree-sitter included ranges

Build ordered, non-overlapping `tree_sitter::Range` values from eligible HTML `raw_text` nodes and
parse those ranges against the original byte slice. The parser helper must restore full-document
parsing before returning on both success and failure so its thread-local instance is safe to reuse.

```rust
pub fn parse_with_included_ranges(
    &mut self,
    source: &[u8],
    ranges: &[tree_sitter::Range],
) -> Result<tree_sitter::Tree> { ... }
```

Reference:
[src/parser.rs](https://github.com/Corgea/Sighthound/blob/17ddd92d8f8ccded3d812943bdd95b1ab839a353/src/parser.rs#L5-L35)

#### Keep security policy in the canonical frontend rule

Select the existing taint rule by semantics (`category == "xss"` plus `dom` and `frontend` tags)
instead of copying its large source, sink, and sanitizer lists into the HTML rule. Add only the two
missing location spellings to that canonical rule.

```ron
sources: Some([
    "window.location.hash",
    "window.location.search",
    "location.hash",
    "location.search",
    "fetch(*).then",
])
```

Reference:
[rules/javascript/frontend_taint_security.ron](https://github.com/Corgea/Sighthound/blob/17ddd92d8f8ccded3d812943bdd95b1ab839a353/rules/javascript/frontend_taint_security.ron#L5-L244)

#### Separate rule applicability from finding provenance

Retain the current public taint entry point as a same-path wrapper, and add an internal form that can
filter rules against a JavaScript-shaped path while reporting the original HTML/template path.

```rust
pub(crate) fn scan_file_with_taint_rules_for_path(
    reporting_path: &str,
    applicability_path: &str,
    source: &[u8],
    tree: &tree_sitter::Tree,
    taint_rules: &[&UnifiedRule],
    language_support: &dyn LanguageSupport,
) -> Vec<Finding> { ... }
```

Reference:
[src/scanner/scanning_logic.rs](https://github.com/Corgea/Sighthound/blob/17ddd92d8f8ccded3d812943bdd95b1ab839a353/src/scanner/scanning_logic.rs#L1171-L1228)

#### Exercise production rules through the scanner API

Load embedded HTML rules, construct `VulnerabilityScanner`, run the unified scan with test fixtures
enabled, and assert the returned finding's type, path, line, source/sink evidence, and tags. Do not
limit regression coverage to RON deserialization or fixture text checks.

Reference:
[tests/acceptance/main.rs](https://github.com/Corgea/Sighthound/blob/17ddd92d8f8ccded3d812943bdd95b1ab839a353/tests/acceptance/main.rs#L140-L149)

### Design Summary

Full discussion doc:
[2026-07-22-design-discussion.md](./2026-07-22-design-discussion.md)

#### Reparse only executable inline script ranges

Traverse the existing HTML tree for `script_element` nodes, inspect each start tag, and include only
the corresponding nonempty `raw_text` body when the block has no `src` and has an executable
JavaScript type. One included-range parse preserves original bytes, rows, and columns across multiple
script blocks without concatenation or line remapping.

#### Cache a dedicated embedded JavaScript parser per worker

Keep the existing primary parser cache intact and add a second thread-local JavaScript parser for the
embedded phase. This avoids parser construction per HTML file and prevents language switching or
included-range state from leaking into the next primary parse.

#### Reuse one canonical DOM-XSS taint rule

Default embedded HTML/Django rule loading adds only the frontend DOM-XSS taint slice. `ScanRuleSet`
keeps that slice separate from native search/taint rules; custom file-rule scans do not gain hidden
rules, and embedded rules do not enter cross-file analysis.

#### Seed fulfillment callback parameters from configured remote sources

For an arrow/function expression used as the fulfillment callback of a `.then(...)` chain, inspect
its JavaScript AST ancestry. When the chain root matches a configured source, record the first
callback parameter in `VariableFlowTracker` with the root source line and pattern; do not infer taint
from parameter names.

#### Prefer precise taint findings locally

Merge native HTML and embedded findings per file. Suppress the HTML search result only when an
embedded taint result has the same reporting path, sink line, and CWE; leave the global CLI
deduplication key and all unrelated same-line findings unchanged.

---

## Phase 1: Detect browser-controlled DOM XSS in eligible inline scripts

Wire a complete HTML-to-JavaScript-to-taint vertical slice and use it to detect the URL-fragment
benchmark. This phase establishes range extraction, parser reuse, rule selection, provenance, and
script eligibility without changing the existing HTML search phase.

### File Changes

- **`src/parser.rs`**: Add `LanguageParser::parse_with_included_ranges`. Set ordered ranges, parse
  the original source bytes, and always clear included ranges before returning. Keep `parse` as the
  unchanged full-document entry point.
- **`src/scanner/parser_helper.rs`**: Add a dedicated thread-local embedded JavaScript parser and a
  closure helper that reuses it independently from `TLS_PARSER`.
- **`src/rules.rs`**: When loading default embedded HTML or Django rules, select and append only the
  canonical taint-mode frontend DOM-XSS rule from the embedded JavaScript rules. Leave
  `load_from_file`, `load_from_path`, and directory/custom-rule behavior unchanged, and avoid a
  second copy when a multi-language embedded load already contains the canonical rule.
- **`src/scanner/scan_context.rs`**: Extend `ScanRuleSet` with a distinct embedded DOM-XSS taint
  slice and its nonempty flag so the per-file phase and cross-file stage cannot confuse rule roles.
- **`src/scanner/scanning_logic.rs`**: Add the internal reporting-path/applicability-path taint entry
  point. Keep the current method as a wrapper that passes the same path twice; the embedded caller
  uses a JavaScript-shaped applicability path and the original template reporting path.
- **`src/scanner/vulnerability_scanner.rs`**: Collect sorted `raw_text` ranges from executable
  inline `script_element` nodes, skipping `src`, empty bodies, unknown/non-JavaScript types, and
  data/template types. For HTML/Django files with both eligible ranges and embedded rules, parse once
  through the embedded parser and invoke single-file taint after native HTML scanning. Keep the
  embedded slice out of native HTML and cross-file taint; when a scan also contains standalone
  JavaScript, the same canonical rule retains its existing native JavaScript role.
- **`rules/javascript/frontend_taint_security.ron`**: Add unqualified `location.hash` and
  `location.search` to `js-dom-xss-taint-001`; do not duplicate the rule in `rules/html/xss.ron`.
- **`tests/test_files/html/embedded_dom_xss_vulnerable.html`**: Add the held-out-shaped URL fragment
  flow through splitting/decoding, local variables, and concatenated `document.write` with stable
  source and sink lines.
- **`tests/test_files/html/embedded_dom_xss_safe.html`**: Add static `document.write` / `innerHTML`,
  `DOMPurify.sanitize`, `textContent`, unrelated source/sink code, an external script, an empty
  script, and JSON/template/unknown-type script blocks.
- **`tests/unit/embedded_js_dom_xss_tests.rs`**: Use production embedded rules and the unified
  scanner API. Assert one URL-flow taint finding at the exact original template path and sink line,
  nonempty source/sink evidence with source before sink, and both taint tags. Assert all safe fixture
  cases produce no DOM-XSS finding, the HTML loader selects only the canonical embedded taint rule,
  a combined HTML/JavaScript embedded load contains that rule once, included-range coordinates match
  the HTML file, and a subsequent full parse proves parser state was reset.
- **`tests/unit/main.rs`**: Register `embedded_js_dom_xss_tests`.

### Validation

- Run `cargo test --test unit_tests embedded_js_dom_xss`.
- Confirm the vulnerable fixture yields exactly one canonical DOM-XSS taint finding on the
  `document.write` line with the `.html` path.
- Confirm every safe script variant remains finding-free and a file with no eligible script takes
  the empty-range branch before the embedded parser is requested.

---

## Phase 2: Propagate configured remote sources through promise callbacks

Extend the existing JavaScript source pass at the callback boundary so the embedded phase can follow
the remote-response benchmark through `.then(...)`, parsing, property assignment, collection access,
and `innerHTML +=`. The change remains source-token-driven and single-file.

### File Changes

- **`src/scanner/scanning_logic.rs`**: Add an AST-based helper for arrow/function expressions that
  are fulfillment handlers in a `.then(...)` chain. Resolve the configured source at the chain root,
  taint only the first callback parameter with the root line/pattern and callback function context,
  and feed that record into the existing assignment/propagation pass. Ignore rejection callbacks,
  unrelated `.then` chains, and parameter-name coincidences.
- **`tests/test_files/html/embedded_dom_xss_vulnerable.html`**: Add the held-out-shaped `fetch` flow
  through chained fulfillment callbacks, `JSON.parse`, a property, an indexed collection element,
  and `innerHTML +=`, with stable source and sink lines.
- **`tests/test_files/html/embedded_dom_xss_safe.html`**: Add an unrelated promise chain and a
  similarly named callback parameter whose chain root is not a configured source.
- **`tests/unit/embedded_js_dom_xss_tests.rs`**: Assert the fetch flow adds exactly one DOM-XSS taint
  finding at the original `innerHTML` line, reports the template path, records source evidence rooted
  at the configured remote source, and leaves the unrelated promise cases clean.

### Validation

- Run `cargo test --test unit_tests embedded_js_dom_xss`.
- Inspect both benchmark-shaped findings: each must have a distinct sink line, a source line before
  its sink, nonempty source/sink evidence, and `taint_analysis` / `data_flow` tags.
- Re-run the existing JavaScript XSS acceptance scenario to confirm standalone frontend taint
  behavior still passes: `cargo test --test acceptance`.

---

## Phase 3: Preserve HTML fallback coverage and validate production behavior

Finalize per-file result precedence so precise embedded taint replaces only an equivalent HTML
search finding. Lock in fallback behavior, run repository gates, inspect the held-out benchmark
outputs and candidate volume, then commit the scoped implementation.

### File Changes

- **`src/scanner/vulnerability_scanner.rs`**: Merge native HTML and embedded findings through a
  small per-file preference helper. Drop a search finding only when an embedded taint finding shares
  its original path, sink line, and CWE; do not alter CLI-global deduplication.
- **`tests/test_files/html/embedded_dom_xss_fallback.html`**: Add one backtick DOM sink with a known
  taint source to exercise overlap and one backtick sink whose dynamic source is outside the
  canonical taint set to exercise search fallback.
- **`tests/unit/embedded_js_dom_xss_tests.rs`**: Assert the overlap produces one taint finding rather
  than duplicate search/taint results, while the unknown-source case retains
  `html-inline-dom-xss-001`. Reassert exact file/line/CWE matching so unrelated same-line findings
  are not suppressed.

### Validation

- Run `cargo test --test unit_tests embedded_js_dom_xss`, then `make check`.
- Scan each held-out benchmark input in the default combined mode and inspect JSON output. Require
  one DOM-XSS finding per benchmark at the real sink, original template provenance, and populated
  source/sink fields.
- Scan the containing benchmark corpus or representative real template repository and compare
  candidate volume with the baseline. Inspect every added candidate; static, sanitized, external,
  and non-JavaScript blocks must not add findings.
- Verify files without eligible scripts avoid the second parse and eligible files perform one
  JavaScript parse across all included ranges, independent of the number of script blocks.
- After all checks pass, create one sentence-case imperative commit containing only this task's
  implementation, fixtures, and tests.

---

## Open Questions

None.
