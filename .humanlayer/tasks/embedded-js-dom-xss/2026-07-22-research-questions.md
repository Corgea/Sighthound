---
type: research-questions
---

# Research Questions

1. How does an HTML or template file move end to end from discovery and language detection into parsing, rule selection, scanning, and finding emission, particularly through `src/scanner/utils.rs`, `src/parser.rs`, `src/rules.rs`, and `src/scanner/`?
2. How do the HTML and template language implementations represent inline `<script>` content in tree-sitter, and which node types and text regions are visible to search-mode and taint-mode traversal in `src/language.rs`, `src/scanner/parser_helper.rs`, and `src/scanner/scanning_logic.rs`?
3. How are embedded HTML and JavaScript RON rules loaded, filtered, and converted into `UnifiedRule` behavior, including the contracts for modes, file types, patterns, sources, sinks, conditions, sanitizers, and exclusions in `src/rules.rs`, `src/models.rs`, and `src/scanner/modes.rs`?
4. How do the current frontend and HTML rules model browser-controlled or remote data sources and DOM XSS sinks such as `document.write` and `innerHTML`, and how do `rules/javascript/frontend_security.ron`, `rules/javascript/frontend_taint_security.ron`, `rules/html/xss.ron`, and `src/common.rs` divide or overlap responsibility?
5. How does the scanner currently propagate JavaScript taint through assignments, member access, calls, concatenation, template literals, callbacks, and scope boundaries, and which AST shapes or control-flow cases are handled by `src/scanner/dataflow.rs`, `src/scanner/flow_tracker.rs`, `src/scanner/taint_utils.rs`, and `src/scanner/conditions.rs`?
6. How are search findings and taint findings constructed, deduplicated, and reported with file, rule, source, sink, line, and trace provenance in `src/scanner/vulnerability_scanner.rs`, `src/scanner/output.rs`, `src/scanner/scan_context.rs`, and `src/models.rs`?
7. How do prefiltering, file eligibility, rule gating, traversal limits, and parallel scanning currently bound the cost of scanning HTML/templates and JavaScript in `src/scanner/prefilter.rs`, `src/scanner/core.rs`, `src/scanner/scanning_logic.rs`, and their tests?
8. What vulnerable, safe, false-positive, and false-negative behaviors are already covered for JavaScript DOM XSS and inline scripts across `tests/test_files/javascript/`, `tests/test_files/html/`, `tests/test_files/html_samples/`, `tests/unit/`, `tests/integration/`, `tests/end_to_end/`, and `tests/features/javascript_xss.feature`, and how does each test layer invoke and assert scanner output?
