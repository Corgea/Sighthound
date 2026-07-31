//! Tier 2: language-focused strictness checks for scanner robustness.

use super::helpers::*;
use serde_json::Value;
use sighthound::rules::Rules;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

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

fn run_cli_json(args: &[&str]) -> Vec<Value> {
    let output = Command::new(sighthound_binary())
        .args(args)
        .output()
        .expect("failed to run sighthound binary");
    assert!(
        output.status.success(),
        "sighthound failed with status {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    match serde_json::from_slice(&output.stdout) {
        Ok(findings) => findings,
        Err(_) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.trim().is_empty() || stdout.trim_start().starts_with("No ") {
                Vec::new()
            } else {
                panic!("failed to parse scanner JSON output: {stdout}");
            }
        }
    }
}

fn sighthound_binary() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_sighthound") {
        return PathBuf::from(path);
    }
    fixture_path("target/debug/sighthound")
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
