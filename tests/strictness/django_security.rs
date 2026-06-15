//! Tier 2: Django fixture scanning with production rules.

use super::helpers::*;

#[test]
#[cfg(feature = "python")]
fn django_views_fixture_detects_known_vulnerabilities() {
    let staging = stage_dir();

    stage_file(
        staging.path(),
        "tests/test_files/python/django/django_views.py",
        "views.py",
        &[],
    );

    let findings = scan_python_simple_with_rules(staging.path(), load_production_python_rules());
    let types: std::collections::BTreeSet<_> =
        findings.iter().map(|f| f.finding_type.as_str()).collect();

    assert!(
        types.contains("Code Injection"),
        "eval(user_code) should be detected, findings: {:?}",
        findings
            .iter()
            .map(|f| (f.line, &f.finding_type))
            .collect::<Vec<_>>()
    );
    assert!(
        types.contains("Unsafe Deserialization"),
        "pickle.loads(user data) should be detected"
    );
}

#[test]
#[cfg(feature = "python")]
fn django_escaped_response_is_not_flagged_as_xss() {
    let staging = stage_dir();

    write_staged_file(
        staging.path(),
        "views.py",
        r#"
from django.http import HttpResponse
from django.utils.html import escape

def safe_response(request):
    user_input = request.GET.get("data", "")
    return HttpResponse(escape(user_input))
"#,
    );

    let findings = scan_python_simple_with_rules(staging.path(), load_production_python_rules());
    let xss: Vec<_> = findings
        .iter()
        .filter(|f| f.finding_type.contains("Scripting") || f.finding_type.contains("XSS"))
        .collect();

    assert!(
        xss.is_empty(),
        "escaped HttpResponse should not produce XSS findings, got {:?}",
        xss
    );
}
