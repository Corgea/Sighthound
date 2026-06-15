//! Tier 1: verified cross-file taint chains must be reported.

use super::helpers::*;

const ACCURACY_TAINT_RULES: &str = "tests/strictness/fixtures/accuracy_taint.ron";

#[test]
#[cfg(feature = "python")]
fn cross_file_accuracy_fixtures_report_real_vulnerabilities() {
    let staging = stage_dir();

    for name in ["module_a.py", "module_b.py", "module_c.py"] {
        stage_file(
            staging.path(),
            &format!("tests/test_files/accuracy_tests/cross_file/{name}"),
            name,
            &[],
        );
    }

    let findings = scan_python_taint(staging.path(), ACCURACY_TAINT_RULES);
    let cross = cross_file_findings(&findings);
    let module_c: Vec<_> = cross
        .into_iter()
        .filter(|f| f.file.ends_with("module_c.py"))
        .collect();

    assert!(
        module_c.len() >= 4,
        "cross_file/module_c.py should have multiple cross-file command-injection flows, got {}: {:?}",
        module_c.len(),
        module_c
            .iter()
            .map(|f| (f.line, f.finding_type.as_str()))
            .collect::<Vec<_>>()
    );
}

#[test]
#[cfg(feature = "python")]
fn true_positive_cross_file_sinks_are_detected() {
    let staging = stage_dir();

    stage_file(
        staging.path(),
        "tests/test_files/accuracy_tests/true_positives/source.py",
        "source.py",
        &[],
    );
    stage_file(
        staging.path(),
        "tests/test_files/accuracy_tests/true_positives/sink.py",
        "sink.py",
        &[],
    );

    let findings = scan_python_taint(staging.path(), ACCURACY_TAINT_RULES);
    let sink_findings = findings_in_file(&findings, "sink.py");

    assert!(
        sink_findings.len() >= 4,
        "true_positives/sink.py should report multiple cross-file flows, got {}: {:?}",
        sink_findings.len(),
        sink_findings
            .iter()
            .map(|f| (f.line, f.finding_type.as_str()))
            .collect::<Vec<_>>()
    );
}
