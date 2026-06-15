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
    assert_findings_in_range(
        &findings,
        39,
        62,
        2,
        "cleartext regression true-positive section",
    );

    // FALSE POSITIVES section: library constants, params, THREE.js patterns (line 68+)
    assert_no_findings_in_range(
        &findings,
        68,
        220,
        "cleartext regression false-positive section",
    );
}
