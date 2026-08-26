//! Tier 2: language-focused strictness checks for scanner robustness.

use super::helpers::*;
use serde_json::Value;
use sighthound::rules::Rules;
use std::collections::BTreeSet;

#[cfg(feature = "php")]
#[test]
fn php_taint_detects_unsafe_and_skips_sanitized_variants() {
    let staging = stage_dir();
    stage_file(
        staging.path(),
        "tests/test_files/strictness_languages/php/unsafe.php",
        "php_case_unsafe.php",
        &[],
    );
    stage_file(
        staging.path(),
        "tests/test_files/strictness_languages/php/safe.php",
        "php_case_safe.php",
        &[],
    );

    let rules =
        Rules::load_from_file("rules/php/taint.ron").expect("failed to load php taint rule");
    let findings = scan_language_unified_with_rules(staging.path(), "php", rules);

    let unsafe_findings = findings_in_file(&findings, "php_case_unsafe.php");
    let safe_findings = findings_in_file(&findings, "php_case_safe.php");

    assert!(
        unsafe_findings.len() >= 2,
        "unsafe.php should trigger taint findings, got {}: {:?}",
        unsafe_findings.len(),
        unsafe_findings
            .iter()
            .map(|f| (f.line, f.finding_type.as_str(), f.snippet.as_str()))
            .collect::<Vec<_>>()
    );
    assert!(
        safe_findings.is_empty(),
        "safe.php should be clean under taint sanitizers, got {}: {:?}",
        safe_findings.len(),
        safe_findings
            .iter()
            .map(|f| (f.line, f.finding_type.as_str(), f.snippet.as_str()))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "go")]
#[test]
fn go_rules_detect_unsafe_patterns_without_secret_findings() {
    let staging = stage_dir();
    stage_file(
        staging.path(),
        "tests/test_files/strictness_languages/go/unsafe.go",
        "go_case_unsafe.go",
        &[],
    );
    stage_file(
        staging.path(),
        "tests/test_files/strictness_languages/go/safe.go",
        "go_case_safe.go",
        &[],
    );

    let rules = Rules::load_from_directory("rules/go/").expect("failed to load go rules");
    let findings = scan_language_simple_with_rules(staging.path(), "go", rules);

    let unsafe_findings = findings_in_file(&findings, "go_case_unsafe.go");
    let safe_findings = findings_in_file(&findings, "go_case_safe.go");

    assert!(
        unsafe_findings.len() >= 2,
        "unsafe.go should trigger command/sql findings, got {}: {:?}",
        unsafe_findings.len(),
        unsafe_findings.iter().map(|f| (f.line, f.finding_type.as_str())).collect::<Vec<_>>()
    );
    assert!(
        safe_findings.is_empty(),
        "safe.go should be clean, got {}: {:?}",
        safe_findings.len(),
        safe_findings
            .iter()
            .map(|f| (f.line, f.finding_type.as_str(), f.snippet.as_str()))
            .collect::<Vec<_>>()
    );
    assert!(
        findings.iter().all(|f| !f.finding_type.to_ascii_lowercase().contains("secret")),
        "go findings should not include hardcoded-secret types: {:?}",
        findings
            .iter()
            .map(|f| (f.file.as_str(), f.line, f.finding_type.as_str()))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "ruby")]
#[test]
fn ruby_rules_detect_unsafe_patterns_without_secret_findings() {
    let staging = stage_dir();
    stage_file(
        staging.path(),
        "tests/test_files/strictness_languages/ruby/unsafe.rb",
        "ruby_case_unsafe.rb",
        &[],
    );
    stage_file(
        staging.path(),
        "tests/test_files/strictness_languages/ruby/safe.rb",
        "ruby_case_safe.rb",
        &[],
    );

    let rules = Rules::load_from_directory("rules/ruby/").expect("failed to load ruby rules");
    let findings = scan_language_simple_with_rules(staging.path(), "ruby", rules);

    let unsafe_findings = findings_in_file(&findings, "ruby_case_unsafe.rb");
    let safe_findings = findings_in_file(&findings, "ruby_case_safe.rb");

    assert!(
        unsafe_findings.len() >= 2,
        "unsafe.rb should trigger command/sql findings, got {}: {:?}",
        unsafe_findings.len(),
        unsafe_findings.iter().map(|f| (f.line, f.finding_type.as_str())).collect::<Vec<_>>()
    );
    assert!(
        safe_findings.is_empty(),
        "safe.rb should be clean, got {}: {:?}",
        safe_findings.len(),
        safe_findings
            .iter()
            .map(|f| (f.line, f.finding_type.as_str(), f.snippet.as_str()))
            .collect::<Vec<_>>()
    );
    assert!(
        findings.iter().all(|f| !f.finding_type.to_ascii_lowercase().contains("secret")),
        "ruby findings should not include hardcoded-secret types: {:?}",
        findings
            .iter()
            .map(|f| (f.file.as_str(), f.line, f.finding_type.as_str()))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "csharp")]
#[test]
fn csharp_explicit_and_filtered_cli_results_match() {
    let staging = stage_dir();
    stage_file(
        staging.path(),
        "tests/test_files/strictness_languages/csharp/parity.cs",
        "parity.cs",
        &[],
    );
    let root = staging.path().to_str().unwrap();

    let explicit = run_cli_json(&[
        root,
        "csharp",
        "rules/csharp",
        "--use-file-rules",
        "--output-format",
        "json",
    ]);
    let filtered = run_cli_json(&[
        root,
        "--language-filter",
        "csharp",
        "--use-file-rules",
        "--rules-dir",
        "rules",
        "--output-format",
        "json",
    ]);

    assert!(!explicit.is_empty(), "explicit csharp scan should produce at least one finding");

    assert_eq!(
        finding_key_set(&explicit),
        finding_key_set(&filtered),
        "explicit and --language-filter csharp findings diverged"
    );
}

#[cfg(feature = "go")]
#[test]
fn include_test_fixtures_flag_enables_scanning_tests_directory() {
    let without_flag = run_cli_json(&[
        "tests",
        "go",
        "rules/go",
        "--use-file-rules",
        "--simple-analysis",
        "--output-format",
        "json",
    ]);
    assert!(
        without_flag.is_empty(),
        "without --include-test-fixtures, tests/ should remain skipped, got {:?}",
        without_flag
    );

    let with_flag = run_cli_json(&[
        "tests",
        "go",
        "rules/go",
        "--use-file-rules",
        "--simple-analysis",
        "--include-test-fixtures",
        "--output-format",
        "json",
    ]);
    assert!(
        !with_flag.is_empty(),
        "with --include-test-fixtures, tests/ fixtures should be scanned"
    );
    assert!(
        with_flag.iter().any(|f| {
            f["file"].as_str().is_some_and(|path| {
                path.replace("\\", "/").contains("strictness_languages/go/unsafe.go")
            })
        }),
        "expected finding from strictness go fixture, got: {:?}",
        with_flag
    );
}

/// A language whose rule pack ships search rules but no `mode = "taint"` rules must not
/// abort the scan. Scanning a SINGLE FILE is load-bearing: a directory scan merges in
/// python/javascript taint rules, the zero-taint-rule guard never fires, and the test
/// passes with or without the fix.
#[cfg(feature = "html")]
#[test]
fn html_only_single_file_scan_succeeds_without_taint_rules() {
    let staging = stage_dir();
    let file = write_staged_file(
        staging.path(),
        "page.html",
        "<html><body><h1>hello</h1><p>plain markup</p></body></html>\n",
    );
    let path = file.to_str().unwrap();

    assert_taint_skip_contract(path);

    // Locked decision Q2: the explicit --taint-analysis path degrades the same way.
    run_json_scan_ok(&[path, "--taint-analysis", "--output-format", "json"]);
}

#[cfg(feature = "objectscript")]
#[test]
fn objectscript_only_single_file_scan_succeeds_without_taint_rules() {
    let staging = stage_dir();
    let file = write_staged_file(
        staging.path(),
        "Sample.cls",
        r#"Class Demo.Sample Extends %RegisteredObject
{

ClassMethod Run(input As %String) As %String
{
  Quit input
}

}
"#,
    );
    assert_taint_skip_contract(file.to_str().unwrap());
}

/// json invocation: exit 0, stdout parses as a JSON array, no notice on stdout.
/// text invocation: exit 0, notice on stderr only, and never the benchmark-grepped string.
#[cfg(any(feature = "html", feature = "objectscript"))]
fn assert_taint_skip_contract(path: &str) {
    const NOTICE: &str = "skipping taint analysis";
    const OLD_ERROR: &str = "No taint flow rules found";

    let json = run_json_scan_ok(&[path, "--output-format", "json"]);
    let json_stdout = String::from_utf8_lossy(&json.stdout);
    assert!(
        !json_stdout.contains(NOTICE),
        "{path}: json stdout must stay pure JSON, got: {json_stdout}"
    );

    let text = run_cli_raw(&[path]);
    let stdout = String::from_utf8_lossy(&text.stdout);
    let stderr = String::from_utf8_lossy(&text.stderr);
    assert_eq!(text.status.code(), Some(0), "{path}: text scan should exit 0, stderr: {stderr}");
    assert!(stderr.contains(NOTICE), "{path}: expected skip notice on stderr, got: {stderr}");
    assert!(!stdout.contains(NOTICE), "{path}: skip notice leaked to stdout: {stdout}");
    assert!(
        !stderr.contains(OLD_ERROR) && !stdout.contains(OLD_ERROR),
        "{path}: legacy '{OLD_ERROR}' text must be gone, stdout: {stdout} stderr: {stderr}"
    );
}

/// Run the CLI and assert exit 0 with a parseable JSON array on stdout. Deliberately says
/// nothing about length: a minimal fixture legitimately yields `[]`.
#[cfg(any(feature = "html", feature = "objectscript"))]
fn run_json_scan_ok(args: &[&str]) -> std::process::Output {
    let output = run_cli_raw(args);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{args:?}: expected exit 0, stderr: {stderr}");
    serde_json::from_slice::<Vec<Value>>(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "{args:?}: stdout is not a JSON array ({e}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    output
}

fn finding_key_set(findings: &[Value]) -> BTreeSet<(String, u64, String, String)> {
    findings
        .iter()
        .map(|f| {
            (
                f["file"].as_str().unwrap_or("").to_string(),
                f["line"].as_u64().unwrap_or(0),
                f["finding_type"].as_str().unwrap_or("").to_string(),
                f["snippet"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect()
}
