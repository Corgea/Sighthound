//! Tier 1: documented false-positive regressions must not reappear.

use super::helpers::*;

#[test]
#[cfg(feature = "javascript")]
fn cleartext_transmission_regression_fixture() {
    let staging = stage_dir();

    // Stage under a neutral name so prefilter heuristics do not skip the file.
    stage_file(
        staging.path(),
        "tests/test_files/false_positives/cleartext_transmission_false_positives.js",
        "cleartext_regression.js",
        &[],
    );

    let findings = scan_javascript_frontend_taint(staging.path());

    // TRUE POSITIVES section: lines 39–62 (HTTP + sensitive DOM sources)
    assert_findings_in_range(&findings, 39, 62, 2, "cleartext regression true-positive section");

    // FALSE POSITIVES section: library constants, params, THREE.js patterns (line 68+)
    assert_no_findings_in_range(&findings, 68, 220, "cleartext regression false-positive section");
}

/// Regression for #35: DB-API 2.0 parameterized queries must not be flagged as SQL injection.
#[test]
#[cfg(feature = "python")]
fn dbapi_parameterized_queries_are_not_sql_injection() {
    let staging = stage_dir();
    stage_file(
        staging.path(),
        "tests/test_files/python/sql_safe_parameterized.py",
        "safe_sql.py",
        &[],
    );
    let rules = load_production_python_rules();
    let findings = scan_python_simple_with_rules(staging.path(), rules);
    let sql_findings: Vec<_> =
        findings.iter().filter(|f| f.finding_type.to_lowercase().contains("sql")).collect();
    assert!(
        sql_findings.is_empty(),
        "parameterized queries should not be flagged, got {} finding(s): {:?}",
        sql_findings.len(),
        sql_findings.iter().map(|f| (f.line, f.snippet.as_str())).collect::<Vec<_>>()
    );
}

/// Verification that all dangerous variants of raw SQL formatting are indeed flagged by simple python rules.
#[test]
#[cfg(feature = "python")]
fn raw_sql_injection_formatting_variants_are_flagged() {
    let staging = stage_dir();
    stage_file(
        staging.path(),
        "tests/test_files/python/sql_formatting.py",
        "sql_formatting.py",
        &[],
    );
    let rules = load_production_python_rules();
    let findings = scan_python_simple_with_rules(staging.path(), rules);
    let sql_findings: Vec<_> =
        findings.iter().filter(|f| f.finding_type.to_lowercase().contains("sql")).collect();

    let flagged_lines: std::collections::BTreeSet<_> =
        sql_findings.iter().map(|f| f.line).collect();
    let expected_lines: std::collections::BTreeSet<usize> =
        vec![2, 6, 10, 14, 18, 22, 26, 30, 35].into_iter().collect();

    assert_eq!(
        flagged_lines,
        expected_lines,
        "Expected SQL injection findings on lines 2, 6, 10, 14, 18, 22, 26, 30, and 35. Got: {:?}",
        sql_findings.iter().map(|f| (f.line, f.snippet.as_str())).collect::<Vec<_>>()
    );
}
