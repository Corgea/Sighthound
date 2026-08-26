//! CWE-95 eval-only sinks; CWE-79 HTML sinks without autoescape/HTMX noise.

use super::helpers::*;
use sighthound::models::Finding;
use sighthound::rules::Rules;

fn is_cwe95(finding: &Finding) -> bool {
    finding.cwe_id.as_deref() == Some("cwe-95")
        || finding.tags.as_ref().is_some_and(|tags| tags.iter().any(|t| t == "cwe-95"))
}

fn is_xss(finding: &Finding) -> bool {
    let ty = finding.finding_type.to_lowercase();
    ty.contains("xss") || ty.contains("scripting") || finding.cwe_id.as_deref() == Some("cwe-79")
}

fn cwe95_findings(findings: &[Finding]) -> Vec<Finding> {
    findings.iter().filter(|f| is_cwe95(f)).cloned().collect()
}

#[test]
#[cfg(feature = "javascript")]
fn innerhtml_helpers_are_not_cwe95_but_eval_is() {
    let staging = stage_dir();
    stage_file(
        staging.path(),
        "tests/test_files/javascript/cwe95_xss_sink_precision.js",
        "sink_precision.js",
        &[],
    );

    let findings = scan_language_unified_with_rules(
        staging.path(),
        "javascript",
        load_production_javascript_rules(),
    );
    let cwe95 = cwe95_findings(&findings);

    assert_findings_in_range(&cwe95, 6, 6, 1, "eval(userInput) is CWE-95");
    assert_findings_in_range(&cwe95, 10, 10, 1, "new Function(userInput) is CWE-95");
    assert_findings_in_range(&cwe95, 15, 15, 1, "setTimeout(string concat) is CWE-95");
    assert_findings_in_range(&cwe95, 19, 19, 1, "setInterval(string concat) is CWE-95");
    assert_findings_in_range(&cwe95, 23, 23, 1, "eval(location.hash) is CWE-95");
    assert_findings_in_range(&cwe95, 27, 27, 1, "vm.runInNewContext(userInput) is CWE-95");
    assert_findings_in_range(&cwe95, 103, 103, 1, "Function('return '+userInput) is CWE-95");
    assert_no_findings_in_range(&cwe95, 30, 98, "DOM/HTMX/callback helpers are not CWE-95");

    let xss: Vec<_> = findings.iter().filter(|f| is_xss(f)).cloned().collect();
    assert_findings_in_range(&xss, 32, 32, 1, "innerHTML = location.hash must remain XSS");
    assert_no_findings_in_range(
        &xss,
        36,
        98,
        "escapeHtml/DOMPurify/template/htmx helpers are not XSS",
    );
    assert!(
        xss.iter().all(|f| f.cwe_id.as_deref() != Some("cwe-95")),
        "XSS findings must not be labeled CWE-95: {:?}",
        xss.iter().map(|f| (f.line, f.cwe_id.as_deref(), f.snippet.as_str())).collect::<Vec<_>>()
    );
}

#[test]
#[cfg(feature = "javascript")]
fn existing_js_xss_true_positives_still_fire() {
    let staging = stage_dir();
    stage_file(
        staging.path(),
        "tests/test_files/javascript/xss_simple_test.js",
        "xss_case.js",
        &[],
    );
    stage_file(
        staging.path(),
        "tests/test_files/javascript/dom_xss_test.js",
        "dom_xss_case.js",
        &[],
    );

    let findings = scan_language_unified_with_rules(
        staging.path(),
        "javascript",
        load_production_javascript_rules(),
    );

    let xss: Vec<_> = findings.iter().filter(|f| is_xss(f)).collect();
    assert!(
        xss.iter().any(|f| f.file.ends_with("xss_case.js") && f.snippet.contains("innerHTML")),
        "xss_simple_test.js innerHTML XSS TPs must still fire, got: {:?}",
        findings
            .iter()
            .map(|f| (f.file.as_str(), f.line, f.finding_type.as_str(), f.snippet.as_str()))
            .collect::<Vec<_>>()
    );
    assert!(
        xss.iter().any(|f| f.file.ends_with("dom_xss_case.js")),
        "dom_xss_test.js XSS TPs must still fire, got: {:?}",
        findings
            .iter()
            .filter(|f| f.file.ends_with("dom_xss_case.js"))
            .map(|f| (f.line, f.finding_type.as_str(), f.snippet.as_str()))
            .collect::<Vec<_>>()
    );
    assert!(
        cwe95_findings(&findings).iter().all(|f| {
            f.snippet.contains("eval(")
                || f.snippet.contains("Function(")
                || f.snippet.contains("setTimeout(")
                || f.snippet.contains("setInterval(")
                || f.snippet.contains("vm.runIn")
        }),
        "CWE-95 on XSS fixtures must be eval-family only, got: {:?}",
        cwe95_findings(&findings)
            .iter()
            .map(|f| (f.file.as_str(), f.line, f.snippet.as_str()))
            .collect::<Vec<_>>()
    );
}

#[test]
#[cfg(feature = "django")]
fn django_autoescape_and_htmx_are_not_xss_but_safe_filter_is() {
    let staging = stage_dir();
    stage_file(
        staging.path(),
        "tests/test_files/django/fixtures/template_xss.html",
        "page.html",
        &[],
    );

    let findings = scan_language_simple_with_rules(
        staging.path(),
        "django",
        Rules::load_from_directory("rules/html/").expect("load html rules"),
    );
    let xss: Vec<_> = findings.iter().filter(|f| is_xss(f)).cloned().collect();

    assert!(
        xss.iter().any(|f| f.snippet.contains("request.GET") && f.snippet.contains("|safe")),
        "|safe on request.GET must be XSS, got: {:?}",
        findings
            .iter()
            .map(|f| (f.line, f.finding_type.as_str(), f.snippet.as_str()))
            .collect::<Vec<_>>()
    );
    assert!(
        xss.iter()
            .any(|f| f.snippet.contains("request.COOKIES") && f.snippet.contains("mark_safe")),
        "spaced | mark_safe on request.COOKIES must be XSS, got: {:?}",
        xss.iter().map(|f| (f.line, f.snippet.as_str())).collect::<Vec<_>>()
    );
    assert!(
        xss.iter().any(|f| f.snippet.contains("value=") && f.snippet.contains("|safe")),
        "|safe on request.GET in an attribute must be XSS, got: {:?}",
        xss.iter().map(|f| (f.line, f.snippet.as_str())).collect::<Vec<_>>()
    );
    assert_no_findings_in_range(&xss, 4, 10, "autoescape, json_script, hx-swap are not XSS");
    assert!(
        findings.iter().all(|f| !is_cwe95(f)),
        "django templates must not produce CWE-95, got: {:?}",
        findings
            .iter()
            .map(|f| (f.line, f.cwe_id.as_deref(), f.snippet.as_str()))
            .collect::<Vec<_>>()
    );
}

#[test]
#[cfg(feature = "html")]
fn html_language_still_flags_django_safe_filter() {
    // CLI auto-detect maps `.html` → `html`, not `django`. Search rules must
    // still see `|safe` on text nodes and attribute values.
    let staging = stage_dir();
    stage_file(
        staging.path(),
        "tests/test_files/django/fixtures/template_xss.html",
        "page.html",
        &[],
    );

    let findings = scan_language_simple_with_rules(
        staging.path(),
        "html",
        Rules::load_from_directory("rules/html/").expect("load html rules"),
    );
    let xss: Vec<_> = findings.iter().filter(|f| is_xss(f)).cloned().collect();

    assert!(
        xss.iter().any(|f| f.snippet.contains("request.GET") && f.snippet.contains("|safe")),
        "|safe on request.GET must be XSS when scanned as html, got: {:?}",
        findings
            .iter()
            .map(|f| (f.line, f.finding_type.as_str(), f.snippet.as_str()))
            .collect::<Vec<_>>()
    );
    assert!(
        xss.iter().any(|f| f.snippet.contains("value=") && f.snippet.contains("|safe")),
        "|safe in an attribute must be XSS when scanned as html, got: {:?}",
        xss.iter().map(|f| (f.line, f.snippet.as_str())).collect::<Vec<_>>()
    );
    assert_no_findings_in_range(&xss, 4, 10, "autoescape, json_script, hx-swap are not XSS");
}

#[test]
#[cfg(feature = "javascript")]
fn request_body_to_ejs_render_is_cwe94_not_cwe95() {
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "render.js",
        "function render(req) {\n    const template = req.body.template;\n    ejs.render(template);\n}\n",
    );
    let findings = scan_language_unified_with_rules(
        staging.path(),
        "javascript",
        Rules::load_from_directory("rules/backend_javascript/").expect("load backend js rules"),
    );
    assert!(
        findings
            .iter()
            .any(|f| f.cwe_id.as_deref() == Some("cwe-94") && f.snippet.contains("ejs.render")),
        "ejs.render(req.body) must be CWE-94 SSTI, got: {:?}",
        findings
            .iter()
            .map(|f| (f.line, f.cwe_id.as_deref(), f.snippet.as_str()))
            .collect::<Vec<_>>()
    );
    assert!(
        findings.iter().all(|f| f.cwe_id.as_deref() != Some("cwe-95")),
        "SSTI must not be labeled CWE-95, got: {:?}",
        findings
            .iter()
            .map(|f| (f.line, f.cwe_id.as_deref(), f.snippet.as_str()))
            .collect::<Vec<_>>()
    );
}
