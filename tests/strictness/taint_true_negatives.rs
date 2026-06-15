//! Tier 1: safe cross-file sources must stay silent under taint analysis.

use super::helpers::*;

const ACCURACY_TAINT_RULES: &str = "tests/strictness/fixtures/accuracy_taint.ron";

#[test]
#[cfg(feature = "python")]
fn safe_cross_file_sources_produce_no_taint_findings() {
    let staging = stage_dir();

    stage_file(
        staging.path(),
        "tests/test_files/accuracy_tests/true_negatives/safe_source.py",
        "safe_source.py",
        &[],
    );
    stage_file(
        staging.path(),
        "tests/test_files/accuracy_tests/true_negatives/safe_sink.py",
        "safe_sink.py",
        &[],
    );

    let findings = scan_python_taint(staging.path(), ACCURACY_TAINT_RULES);
    let sink_findings = findings_in_file(&findings, "safe_sink.py");

    assert!(
        sink_findings.is_empty(),
        "safe_sink.py should have zero taint findings (10 labeled safe functions), got {}: {:?}",
        sink_findings.len(),
        sink_findings
            .iter()
            .map(|f| (f.line, f.finding_type.as_str(), f.snippet.as_str()))
            .collect::<Vec<_>>()
    );
}
