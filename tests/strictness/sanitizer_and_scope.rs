//! Tier 2: sanitizer respect and single-file scope boundaries.

use super::helpers::*;

const SANITIZER_RULES: &str = "tests/strictness/fixtures/sanitizer_taint.ron";
const ACCURACY_TAINT_RULES: &str = "tests/strictness/fixtures/accuracy_taint.ron";

#[test]
#[cfg(feature = "python")]
fn shlex_quote_sanitizer_suppresses_taint_finding() {
    let staging_safe = stage_dir();
    write_staged_file(
        staging_safe.path(),
        "app.py",
        r#"
import os
import shlex
user = input("prompt")
os.system(shlex.quote(user))
"#,
    );
    let staging_unsafe = stage_dir();
    write_staged_file(
        staging_unsafe.path(),
        "app.py",
        r#"
import os
user = input("prompt")
os.system(user)
"#,
    );

    let safe_findings = scan_python_taint(staging_safe.path(), SANITIZER_RULES);
    let unsafe_findings = scan_python_taint(staging_unsafe.path(), SANITIZER_RULES);

    assert!(
        safe_findings.is_empty(),
        "shlex.quote in sink should suppress finding, got {:?}",
        safe_findings
    );
    assert_eq!(
        unsafe_findings.len(),
        1,
        "unsanitized os.system(user) should produce exactly one finding, got {:?}",
        unsafe_findings
    );
}

#[test]
#[cfg(feature = "python")]
fn same_name_different_scope_does_not_create_false_taint() {
    let staging = stage_dir();

    stage_file(
        staging.path(),
        "tests/test_files/accuracy_tests/edge_cases/tricky_source.py",
        "edge_source.py",
        &[],
    );
    stage_file(
        staging.path(),
        "tests/test_files/accuracy_tests/edge_cases/tricky_sink.py",
        "edge_sink.py",
        &[("tricky_source", "edge_source")],
    );

    let findings = scan_python_taint(staging.path(), ACCURACY_TAINT_RULES);

    // EC9: local_user_data has no connection to imported taint sources.
    assert_no_findings_in_range(
        &findings,
        87,
        92,
        "test_false_positive (similar name, no taint connection)",
    );
}

#[test]
#[cfg(feature = "python")]
fn taint_does_not_leak_across_function_boundaries_in_single_file() {
    let staging = stage_dir();

    write_staged_file(
        staging.path(),
        "app.py",
        r#"
import os

def uses_taint():
    data = os.environ.get("USER_INPUT", "")
    eval(data)

def uses_safe_name_only():
    local_user_data = "safe_local_data"
    eval(local_user_data)
"#,
    );

    let findings = scan_python_taint(staging.path(), ACCURACY_TAINT_RULES);

    assert_findings_in_range(
        &findings,
        4,
        7,
        1,
        "os.environ.get -> eval in same function",
    );
    assert_no_findings_in_range(
        &findings,
        9,
        12,
        "literal local_user_data eval must not be flagged",
    );
}
