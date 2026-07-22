---
task: embedded-js-dom-xss
type: design-discussion
repo: Corgea/Sighthound
branch: main
sha: 17ddd92d8f8ccded3d812943bdd95b1ab839a353
---

### Summary of change request

Add production DOM-XSS detection for JavaScript embedded in HTML and template files. The
scanner must follow browser-controlled and remote values into `document.write` and
`innerHTML`, including the two benchmark shapes that current HTML search misses:

1. `location.hash` propagated through splitting/decoding and concatenated into
   `document.write`.
2. A `fetch` response propagated through promise callbacks, parsed data, and a collection
   element into `innerHTML`.

The change must retain the existing scanner pipeline, report the original template path and
source/sink lines, avoid broad sink-only findings, and keep the extra parse cost limited to files
that contain eligible inline scripts.

### Current State

- HTML and template files are scanned as HTML, so inline script bodies are visible only as one
  enclosing `<script>` region rather than as JavaScript statements and expressions.
- The production HTML rule detects a small set of template-literal sink spellings. It does not
  follow a value through assignments, concatenation, promise callbacks, or parsed response data.
- A URL-fragment value that reaches `document.write` through local variables is missed.
- A remote response that reaches `innerHTML` through `.then(...)` callbacks is missed.
- The same source-to-sink shapes are analyzed more precisely when they live in standalone
  JavaScript, where findings include source and sink evidence.

### Desired End State

- Eligible inline JavaScript in supported HTML/template files is parsed as JavaScript and passed
  through the existing single-file taint engine.
- Unqualified `location.hash` and `location.search` are treated like their `window.location`
  forms by the canonical frontend DOM-XSS rule.
- The fulfillment value of a promise chain rooted in a configured remote source, such as
  `fetch`, is tainted inside the corresponding `.then(...)` callback.
- The two benchmark-shaped flows produce one DOM-XSS finding each at the real sink line.
- Each finding keeps the original `.html`/template path and carries existing taint
  `source_info`, `sink_info`, and `taint_analysis`/`data_flow` tags.
- Static `document.write`, static `innerHTML`, sanitized values, `textContent`, external scripts,
  and non-JavaScript `<script type=...>` blocks remain finding-free.
- Files without eligible inline scripts do no second parse. Files with scripts use one additional
  JavaScript parse over only the included source ranges.

### What we're not doing

- Building a generic polyglot or tree-sitter injection framework.
- Fetching or joining external `<script src="...">` files with template files.
- Adding cross-file taint between external JavaScript and inline scripts.
- Covering inline event-handler attributes, CSS, server-side template output encoding, or new DOM
  sinks beyond the existing frontend DOM-XSS rule.
- Adding a rule-schema field, dependency, feature flag, persisted state, or new CLI option.
- Replacing the existing HTML template-literal search rule; it remains a fallback for dynamic
  sink expressions whose source is outside the known taint-source set.

### Current Architecture

- File discovery maps HTML and common template extensions to the HTML scan path. HTML and Django
  both use `tree_sitter_html`, while their language adapters expose `script_element` as the
  pseudo-function `script`.
  [src/scanner/utils.rs](https://github.com/Corgea/Sighthound/blob/17ddd92d8f8ccded3d812943bdd95b1ab839a353/src/scanner/utils.rs#L239-L288)
  [src/language.rs](https://github.com/Corgea/Sighthound/blob/17ddd92d8f8ccded3d812943bdd95b1ab839a353/src/language.rs#L525-L660)
- `scan_single_file_findings` opens and maps a file once, parses it with the thread-local parser,
  then invokes enhanced search and single-file taint against that tree.
  [src/scanner/vulnerability_scanner.rs](https://github.com/Corgea/Sighthound/blob/17ddd92d8f8ccded3d812943bdd95b1ab839a353/src/scanner/vulnerability_scanner.rs#L436-L496)
- The parser cache currently retains one language parser per Rayon worker. An embedded scan must
  not construct a fresh JavaScript parser for every file or leave included-range state on a parser
  reused by the next file.
  [src/scanner/parser_helper.rs](https://github.com/Corgea/Sighthound/blob/17ddd92d8f8ccded3d812943bdd95b1ab839a353/src/scanner/parser_helper.rs#L7-L37)
- HTML search walks `script_element` nodes and matches a rule against the complete element text.
  The existing rule only accepts backtick-based sink spellings.
  [rules/html/xss.ron](https://github.com/Corgea/Sighthound/blob/17ddd92d8f8ccded3d812943bdd95b1ab839a353/rules/html/xss.ron#L3-L47)
  [src/scanner/scanning_logic.rs](https://github.com/Corgea/Sighthound/blob/17ddd92d8f8ccded3d812943bdd95b1ab839a353/src/scanner/scanning_logic.rs#L1815-L1903)
- JavaScript taint is a two-pass analysis. The first pass records assignment sources and
  propagation in `VariableFlowTracker`; the second matches sinks and emits a finding only when a
  used variable is tainted.
  [src/scanner/scanning_logic.rs](https://github.com/Corgea/Sighthound/blob/17ddd92d8f8ccded3d812943bdd95b1ab839a353/src/scanner/scanning_logic.rs#L787-L1228)
- `js-dom-xss-taint-001` is the canonical frontend source/sink/sanitizer policy. It already owns
  `window.location`, form/DOM/postMessage/network/storage sources and the `innerHTML`,
  `document.write`, and related sinks.
  [rules/javascript/frontend_taint_security.ron](https://github.com/Corgea/Sighthound/blob/17ddd92d8f8ccded3d812943bdd95b1ab839a353/rules/javascript/frontend_taint_security.ron#L5-L244)
- Taint finding construction reports the source assignment and sink expression using the path and
  line numbers passed to the single-file scanner.
  [src/scanner/scanning_logic.rs](https://github.com/Corgea/Sighthound/blob/17ddd92d8f8ccded3d812943bdd95b1ab839a353/src/scanner/scanning_logic.rs#L1594-L1649)

### Patterns to follow

#### Keep parsing and scanning as separate per-file phases

The current per-file path parses once and passes the same source bytes, tree, path, and language
adapter into scanning. The embedded phase should follow this shape: derive ranges from the HTML
tree, parse those ranges with the JavaScript adapter, then call the existing taint entry point.

```rust
let tree = parser.parse(source)?;

file_findings.extend(ScanningLogic::scan_file_with_rules_and_taint_context(
    &filepath_str,
    source,
    &tree,
    rules.search_rules,
    rules.taint_rules,
    parser.language_support(),
));
```

```rust
file_findings.extend(ScanningLogic::scan_file_with_taint_rules(
    &filepath_str,
    source,
    &tree,
    rules.taint_rules,
    parser.language_support(),
));
```

#### Keep source, sink, and sanitizer policy in the canonical frontend rule

Do not copy the large source and sanitizer lists into `rules/html/xss.ron`. Select the existing
DOM/frontend taint rule for the embedded phase and add only missing source spellings there.

```ron
sources: Some([
    "window.location.hash",
    "window.location.search",
    "document.URL",
    "fetch(*).then",
    "*.responseText",
]),
sinks: Some([
    "*.innerHTML",
    "*.outerHTML",
    "document.write",
    "document.writeln",
    "*.insertAdjacentHTML",
]),
sanitizers: Some([
    "DOMPurify.sanitize",
    "encodeHTML",
    "escapeHTML",
]),
```

#### Preserve provenance through the existing taint finding

The embedded JavaScript tree must point into the original HTML byte buffer. That lets existing
finding construction remain unchanged and avoids synthetic paths or post-hoc line arithmetic.

```rust
let taint_source = TaintSource {
    file: site.filepath.to_string(),
    line: taint_info.source_line,
    code: taint_info.assignment_code.clone(),
    // ...
};
let taint_sink = TaintSink {
    file: site.filepath.to_string(),
    line: site.line,
    code: site.node_text.to_string(),
    // ...
};
```

#### Exercise production rules through the scanner API

Follow the existing scanner tests: load real rules, create a `VulnerabilityScanner`, scan a focused
fixture directory with test fixtures enabled, and assert findings by type, file, line, and evidence
rather than checking only that RON deserializes.

```rust
let rules = Rules::load_embedded_rules("html", None).expect("embedded HTML rules should load");
let scanner = VulnerabilityScanner::new("html", rules).expect("scanner should build");
let findings = scanner.find_vulnerabilities_parallel_with_options(
    fixture_dir,
    "html",
    false,
    true,
)?;
```

### Design Questions

None. The ticket's provenance, performance, architecture, and safe-case constraints resolve the
choices below.

### Resolved Design Questions

#### How should inline JavaScript be analyzed?

Choose a JavaScript parse over the HTML tree's eligible `script_element` body ranges, followed by
the existing single-file taint pass.

- Expanding `rules/html/xss.ron` with whole-script regular expressions is smaller in lines changed,
  but it proves only source/sink co-occurrence. It cannot preserve variable-level provenance or
  distinguish an unrelated or sanitized source.
- A general language-injection subsystem would solve a broader problem than this ticket and add a
  new abstraction before another consumer exists.
- A narrow embedded-JavaScript phase reuses the current parser adapter, taint tracker, sanitizer
  checks, finding model, and per-file parallelism. This is the minimum seam that meets the stated
  correctness contract.

#### How should original line and byte coordinates be retained?

Use tree-sitter included ranges over the original mapped HTML bytes.

- Collect the `raw_text` range from each eligible `script_element`, sort the ranges by byte offset,
  and pass them to a JavaScript parser through a small `LanguageParser` included-range method.
- Do not concatenate script strings or scan a synthetic `.js` buffer. Those approaches require
  remapping finding, source, sink, snippet, column, and end-position fields.
- The parser method must clear included ranges before returning, including error paths. Cache one
  embedded JavaScript parser per worker beside the existing primary parser so HTML/JS parser
  construction does not alternate for every file.

#### Which script blocks are eligible?

Analyze inline blocks with no `type`, a recognized JavaScript/ECMAScript MIME type, or
`type="module"`. Skip a block with `src`, an empty body, or a non-JavaScript type such as
`application/json`, `application/ld+json`, or `text/template`.

This mirrors browser execution closely enough for the requested scope and prevents data/template
payloads from becoming JavaScript false positives. Unknown explicit types are skipped rather than
guessed.

#### Which rules should the embedded pass use?

Reuse only the canonical taint-mode rule whose semantics are frontend DOM XSS (category `xss` and
`dom`/`frontend` tags). Keep this embedded rule slice separate from native HTML search/taint rules
in `ScanRuleSet`.

- The default embedded HTML/Django rule loader should include that narrow slice from the canonical
  JavaScript rule source. Custom file-rule scans remain controlled by the rules the caller loads.
- Rule applicability for the embedded pass uses a JavaScript-shaped eligibility path, while the
  reporting path remains the original template path. This preserves the canonical rule's `.js` /
  `.jsx` / `.ts` / `.tsx` contract without copying or mutating it.
- Embedded rules do not enter multi-file taint. The new phase is single-file and frontend-only.
- Do not load the broader JavaScript rule pack into HTML; that would expand scope to storage,
  redirect, code-injection, and other unrelated findings.

#### What taint behavior is needed for the benchmark flows?

Make two narrow improvements in the existing JavaScript taint source pass:

1. Add unqualified `location.hash` and `location.search` source spellings to the canonical DOM-XSS
   rule. Existing assignment and member/call propagation then carries the value through `split`,
   `decodeURIComponent`, concatenation, and local variables.
2. When an arrow/function callback is the fulfillment handler of a `.then(...)` chain rooted in a
   configured remote source, taint its first parameter with the root source's line and pattern.
   Detect this from the JavaScript AST ancestry and configured source tokens, not from parameter
   names such as `data`, `result`, or `response`. Existing propagation then carries `result` through
   `JSON.parse`, property assignments, and indexed collection reads.

The callback rule stays inside `scanning_logic.rs` and feeds `VariableFlowTracker`; it does not add
a promise graph, async scheduler, or cross-file state.

#### How should duplicate HTML search and embedded-taint findings be handled?

Keep `html-inline-dom-xss-001` as fallback coverage, but prefer the embedded taint finding when both
identify the same original sink line and CWE in one file. Perform this preference while merging the
two per-file result vectors. Do not weaken the global CLI deduplication key or suppress unrelated
findings that share a line.

#### What verification is required?

Add focused vulnerable and safe fixtures under `tests/test_files/html/` and a scanner-invoking unit
module registered by `tests/unit/main.rs`.

The regression assertions must cover:

- URL fragment -> local variables -> decoded value -> concatenated `document.write`.
- `fetch` -> chained fulfillment parameter -> `JSON.parse`/property/index propagation ->
  `innerHTML +=`.
- Exact original template path and sink line for both findings.
- Nonempty source and sink evidence with the source line preceding the sink line.
- Static sink values, `DOMPurify.sanitize`, safe text sinks, unrelated source/sink code, external
  scripts, and JSON/template script types producing no DOM-XSS finding.
- Existing backtick-based HTML search coverage remaining available when no configured taint source
  is present.

Run the focused unit target first, then `make check`. The final implementation phase must also scan
the two real benchmark fixtures and inspect candidate volume before committing, as required by the
repository's scanner-rule workflow.
