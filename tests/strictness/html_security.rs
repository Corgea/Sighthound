//! Strictness coverage for the generic HTML security rule pack.
//!
//! Drives the shipped binary through CLI auto-detection — no `--language`, no rules
//! path — which is exactly what routes `run_simple_analysis` to
//! `run_auto_detection_scan` (`src/main.rs`).

use super::helpers::*;
use serde_json::Value;
use std::collections::BTreeSet;

const POSITIVE_FIXTURE: &str = "html_security_positive.html";
const SAFE_FIXTURE: &str = "html_security_safe.html";

/// (rule id — documentation only, `Finding` has no rule-id field; fixture line;
/// `finding_type`; `description`; `snippet`).
///
/// `description` is the discriminator: eight of the twelve share
/// "Cross-Site Scripting (XSS)", two share "Code Injection", and `tags` are identical
/// across -001 / -002 / -019. **Do not simplify these assertions back to
/// `finding_type`** — they would stop distinguishing eight of the twelve rules.
///
/// `snippet` is the verbatim `get_node_text` of the node that matched, which is what
/// pins "tightest node span wins" (assertion 4). Nine are attribute-level; the four
/// tag-level ones are not typos — see the comment on assertion 4.
const EXPECTED: &[(&str, u64, &str, &str, &str)] = &[
    (
        "html-xss-011",
        7,
        "Cross-Site Scripting (XSS)",
        "Meta refresh tags with JavaScript URLs can execute arbitrary code",
        "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">",
    ),
    (
        "html-xss-001",
        11,
        "Cross-Site Scripting (XSS)",
        "JavaScript URLs in href attributes can execute arbitrary code when clicked",
        "href=\"javascript:alert(1)\"",
    ),
    (
        "html-xss-002",
        13,
        "Cross-Site Scripting (XSS)",
        "JavaScript URLs in form action attributes can execute arbitrary code on form submission",
        "action=\"javascript:alert(1)\"",
    ),
    (
        "html-xss-019",
        15,
        "Cross-Site Scripting (XSS)",
        "JavaScript URLs in src attributes can execute arbitrary code",
        "src=\"javascript:alert(1)\"",
    ),
    (
        "html-xss-020",
        17,
        "Cross-Site Scripting (XSS)",
        "Data URLs containing script tags can execute arbitrary JavaScript",
        "href=\"data:text/html,<script>alert(1)</script>\"",
    ),
    (
        "html-xss-004",
        19,
        "Code Injection",
        "Using eval() in inline event handlers can execute arbitrary code, especially with user-controlled input",
        "onclick=\"eval(userInput)\"",
    ),
    (
        "html-xss-014",
        21,
        "Cross-Site Scripting (XSS)",
        "Template expressions in event handlers can inject user-controlled data, leading to XSS",
        "onclick=\"greet('${userName}')\"",
    ),
    (
        "html-xss-008",
        23,
        "Cross-Site Scripting (XSS)",
        "The srcdoc attribute can inject HTML/JavaScript into an iframe, creating XSS vulnerabilities",
        "srcdoc=\"${userContent}\"",
    ),
    (
        "html-xss-010",
        25,
        "Cross-Site Scripting (XSS)",
        "CSS expressions in IE can execute JavaScript code (legacy vulnerability but still relevant)",
        "style=\"width:expression(alert(1))\"",
    ),
    (
        "html-xss-012",
        27,
        "DOM XSS",
        "document.write can inject HTML/JavaScript into the page, potentially leading to XSS",
        "<script>document.write(userInput);</script>",
    ),
    (
        "html-xss-013",
        29,
        "Code Injection",
        "eval() can execute arbitrary JavaScript code, especially dangerous with user input",
        "<script>eval(userInput);</script>",
    ),
    (
        "html-sec-001",
        31,
        "Insecure postMessage",
        "Using wildcard (*) as targetOrigin in postMessage allows any site to receive the message",
        "<script>window.postMessage(payload, \"*\");</script>",
    ),
];

fn scan_staged_html_fixtures() -> Vec<Value> {
    scan_staged_html_fixtures_with(&["--simple-analysis"])
}

/// `extra_args` sits between the scan path and `--output-format json`. Passing `&[]`
/// reproduces the fusion contract exactly: default mode, no language, no simple flag.
fn scan_staged_html_fixtures_with(extra_args: &[&str]) -> Vec<Value> {
    let staging = stage_dir();
    stage_file(
        staging.path(),
        "tests/test_files/html/html_security_positive.html",
        POSITIVE_FIXTURE,
        &[],
    );
    stage_file(staging.path(), "tests/test_files/html/html_security_safe.html", SAFE_FIXTURE, &[]);
    let dir = staging.path().to_str().expect("staging path is not valid UTF-8").to_string();
    let mut args = vec![dir.as_str()];
    args.extend_from_slice(extra_args);
    args.extend_from_slice(&["--output-format", "json"]);
    run_cli_json(&args)
}

fn findings_for_file<'a>(findings: &'a [Value], filename: &str) -> Vec<&'a Value> {
    findings.iter().filter(|f| f["file"].as_str().is_some_and(|p| p.ends_with(filename))).collect()
}

fn line_description_pairs(findings: &[&Value]) -> BTreeSet<(u64, String)> {
    findings
        .iter()
        .map(|f| {
            (
                f["line"].as_u64().unwrap_or(0),
                f["description"].as_str().unwrap_or("<none>").to_string(),
            )
        })
        .collect()
}

#[cfg(feature = "html")]
#[test]
fn html_security_rules_fire_through_cli_auto_detection() {
    let findings = scan_staged_html_fixtures();
    let positives = findings_for_file(&findings, POSITIVE_FIXTURE);
    let observed = line_description_pairs(&positives);

    // 1. All twelve triples present at their marked lines.
    for (id, line, finding_type, description, _) in EXPECTED {
        assert!(
            positives.iter().any(|f| {
                f["line"].as_u64() == Some(*line)
                    && f["finding_type"].as_str() == Some(*finding_type)
                    && f["description"].as_str() == Some(*description)
            }),
            "{id}: expected a finding at line {line} of {POSITIVE_FIXTURE}; observed {observed:?}"
        );
    }

    // 2. Zero findings in the safe fixture.
    let safe = findings_for_file(&findings, SAFE_FIXTURE);
    assert!(
        safe.is_empty(),
        "{SAFE_FIXTURE} must produce no findings, got {:?}",
        line_description_pairs(&safe)
    );

    // 3. Nested markup collapses: exactly one finding per (line, description).
    //    `description`, not `finding_type` — eight of the twelve share a finding_type.
    let mut counts: std::collections::BTreeMap<(u64, String), usize> =
        std::collections::BTreeMap::new();
    for f in &positives {
        let key = (
            f["line"].as_u64().unwrap_or(0),
            f["description"].as_str().unwrap_or("<none>").to_string(),
        );
        *counts.entry(key).or_default() += 1;
    }
    for (key, count) in &counts {
        assert_eq!(*count, 1, "nested markup dedup failed for {key:?}: {count} findings");
    }

    // 4. Tightest node span wins, pinned as per-finding snippet equality rather than as
    //    a negative: `traverse_calls_only` yields a parent before its children, so under
    //    first-seen the enclosing `start_tag` wins and every attribute-level equality
    //    below breaks.
    //
    //    Nine snippets are attribute-level and four are tag-level. That asymmetry is the
    //    tightest span, not an oversight: html-xss-011 (line 7) matches across two
    //    attributes (`http-equiv` and the `javascript:` URL), and lines 27/29/31 match
    //    inside a `<script>` body — in neither case does any single `attribute` node's
    //    text contain the match, so the enclosing node is the smallest one that does.
    //
    //    Keyed on (line, description), matching assertion 3: one line may legitimately
    //    carry two findings from different rules.
    let expected_snippets: std::collections::BTreeMap<(u64, &str), &str> = EXPECTED
        .iter()
        .map(|(_, line, _, description, snippet)| ((*line, *description), *snippet))
        .collect();
    for f in &positives {
        let snippet = f["snippet"].as_str().unwrap_or("");
        assert!(!snippet.is_empty(), "finding carries an empty snippet: {f:?}");
        let key = (f["line"].as_u64().unwrap_or(0), f["description"].as_str().unwrap_or("<none>"));
        let expected = expected_snippets
            .get(&key)
            .unwrap_or_else(|| panic!("finding at unexpected (line, description) {key:?}: {f:?}"));
        assert_eq!(
            &snippet, expected,
            "snippet at line {} is not the tightest matching node span",
            key.0
        );
    }
}

/// Keyed on the fixture basename, not the full path: each call stages into its own
/// `TempDir`, so absolute paths differ between the two invocations by construction.
fn finding_identity_set(findings: &[Value]) -> BTreeSet<(String, u64, String, String)> {
    findings
        .iter()
        .map(|f| {
            let path = f["file"].as_str().unwrap_or("<none>");
            (
                path.rsplit(['/', '\\']).next().unwrap_or("").to_string(),
                f["line"].as_u64().unwrap_or(0),
                f["finding_type"].as_str().unwrap_or("<none>").to_string(),
                f["description"].as_str().unwrap_or("<none>").to_string(),
            )
        })
        .collect()
}

#[cfg(feature = "html")]
#[test]
fn html_security_rules_fire_in_default_mode() {
    // Default mode is the fusion contract: `sighthound --output-format json <path>`,
    // no `--language`, no `--simple-analysis`. Without the zero-taint-rule skip in
    // `src/scanner/modes.rs` this call panics with
    // `sighthound failed with status Some(1): Error: No taint flow rules found. ...`,
    // because `run_cli_json` asserts exit 0 before it parses stdout.
    let default_mode = scan_staged_html_fixtures_with(&[]);
    let simple_mode = scan_staged_html_fixtures();

    assert!(
        !default_mode.is_empty(),
        "default mode must report the HTML findings; an empty set would make the parity \
         assertion below vacuous"
    );
    assert_eq!(
        finding_identity_set(&default_mode),
        finding_identity_set(&simple_mode),
        "default mode must report exactly what --simple-analysis reports: for a language \
         with zero taint rules the taint pass must add nothing and drop nothing"
    );
}
