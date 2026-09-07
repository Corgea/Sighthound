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

const SQL_UNSAFE_FIXTURE: &str = "tests/test_files/strictness_languages/sql/unsafe.sql";

// SQL is matched textually against the whole file, so `safe.sql` has to dodge every
// pattern in the eleven-rule pack at once. What it is avoiding: a first statement that
// does not start with `SELECT `/`EXEC(`/`EXECUTE(`/`CONCAT(`, since patterns containing
// `*` are globs anchored at byte 0 — that, not the explicit column list, is what keeps
// `sql-wildcard-001`'s `SELECT *` quiet, so the `INSERT` has to stay first; no `||`
// (`sql-injection-002`); no `--`, `/*` or `#` (`sql-comment-001`); no `DROP`/`TRUNCATE`
// (`sql-dangerous-001/002`); no `UNION SELECT` (`sql-union-001`); no `SLEEP(`/
// `WAITFOR DELAY`/`BENCHMARK(`/`pg_sleep(` (`sql-timing-001`); no `EXECUTE IMMEDIATE`/
// `sp_executesql` (`sql-unsafe-001`); no `OR 1=1` family (`sql-auth-001`); and a
// newline between the two statements, so no
// `;SELECT` (`sql-batch-001`). Counts below were measured, not guessed.
#[cfg(feature = "sql")]
#[test]
fn sql_rules_detect_unsafe_patterns_and_leave_safe_clean() {
    let staging = stage_dir();
    stage_file(staging.path(), SQL_UNSAFE_FIXTURE, "sql_case_unsafe.sql", &[]);
    stage_file(
        staging.path(),
        "tests/test_files/strictness_languages/sql/safe.sql",
        "sql_case_safe.sql",
        &[],
    );

    let rules = Rules::load_from_directory("rules/sql/").expect("failed to load sql rules");
    let findings = scan_language_simple_with_rules(staging.path(), "sql", rules);

    let unsafe_findings = findings_in_file(&findings, "sql_case_unsafe.sql");
    let safe_findings = findings_in_file(&findings, "sql_case_safe.sql");
    let described = |fs: &[&sighthound::models::Finding]| {
        fs.iter()
            .map(|f| (f.line, f.finding_type.clone(), f.severity.clone(), f.confidence.clone()))
            .collect::<Vec<_>>()
    };

    assert_eq!(
        unsafe_findings.len(),
        2,
        "unsafe.sql should trigger exactly the sp_executesql and || findings, got {:?}",
        described(&unsafe_findings)
    );
    assert!(
        unsafe_findings.iter().any(|f| f.finding_type == "SQL Injection" && f.severity == "High"),
        "expected the sp_executesql SQL Injection finding, got {:?}",
        described(&unsafe_findings)
    );
    // The `||` finding is the only coverage the sql-injection-002 downgrade gets:
    // before it, this same line was reported Critical by sql-injection-001.
    assert!(
        unsafe_findings.iter().any(|f| {
            f.finding_type == "SQL Injection" && f.severity == "Low" && f.confidence == "Low"
        }),
        "expected the sql-injection-002 Low/Low || finding, got {:?}",
        described(&unsafe_findings)
    );
    assert!(
        safe_findings.is_empty(),
        "safe.sql should be clean under every bundled SQL rule, got {:?}",
        described(&safe_findings)
    );
}

#[cfg(feature = "sql")]
#[test]
fn sql_explicit_mode_scans_ddl_and_dml_but_only_sql_reports() {
    let staging = stage_dir();
    for dest in ["case.sql", "case.ddl", "case.dml"] {
        stage_file(staging.path(), SQL_UNSAFE_FIXTURE, dest, &[]);
    }
    let root = staging.path().to_str().unwrap();

    // Runs the explicit-mode invocation the README documents — positional language plus
    // rules directory, file rules, one pass — which is what makes `should_include_file`'s
    // `"sql" => matches!(ext, "sql" | "ddl" | "dml")` arm discover all three files.
    // `--simple-analysis` keeps this test to the one pass it is about; the default
    // combined mode is covered by `sql_default_combined_mode_succeeds_without_taint_rules`.
    let findings = run_cli_json(&[
        root,
        "sql",
        "rules/sql",
        "--use-file-rules",
        "--simple-analysis",
        "--output-format",
        "json",
    ]);

    let in_file = |name: &str| {
        findings.iter().filter(|f| f["file"].as_str().is_some_and(|p| p.ends_with(name))).count()
    };
    assert!(in_file("case.sql") > 0, "case.sql should produce findings, got {:?}", findings);
    // `.ddl` and `.dml` are discovered and scanned, but every bundled rule is scoped to
    // `.sql` via `file_types.extensions`, so `rule_applies_to_file` rejects them. This
    // asserts the real measured behavior so a future reader does not "fix" the gate arm.
    assert_eq!(in_file("case.ddl"), 0, "every bundled SQL rule is scoped to .sql");
    assert_eq!(in_file("case.dml"), 0, "every bundled SQL rule is scoped to .sql");
}

// All eleven SQL rules are `mode: "search"`, so the taint pass of a combined scan finds
// zero taint rules. This is fusion's exact invocation (`sighthound --output-format json
// <file>`, embedded rules, no language, default combined mode), which used to die with
// "No taint flow rules found". Combined output must equal simple-only output: the taint
// pass contributes nothing, and — because `run_selected_analysis` *appends* it — must not
// re-run the search pass either, or every finding would appear twice.
#[cfg(feature = "sql")]
#[test]
fn sql_default_combined_mode_succeeds_without_taint_rules() {
    let staging = stage_dir();
    let case = stage_file(staging.path(), SQL_UNSAFE_FIXTURE, "case.sql", &[]);
    let case = case.to_str().unwrap();

    let combined = run_cli_json(&[case, "--output-format", "json"]);
    let simple_only = run_cli_json(&[case, "--simple-analysis", "--output-format", "json"]);

    assert!(
        !combined.is_empty(),
        "default combined mode should report the search findings, got {:?}",
        combined
    );
    assert_eq!(
        combined.len(),
        simple_only.len(),
        "combined mode must not duplicate the search pass: {} vs {} findings",
        combined.len(),
        simple_only.len()
    );
    assert_eq!(
        finding_key_set(&combined),
        finding_key_set(&simple_only),
        "combined and --simple-analysis findings diverged on a search-only rule pack"
    );
}

#[cfg(feature = "sql")]
#[test]
fn sql_explicit_taint_analysis_returns_empty_findings_without_taint_rules() {
    let staging = stage_dir();
    let case = stage_file(staging.path(), SQL_UNSAFE_FIXTURE, "case.sql", &[]);

    let findings =
        run_cli_json(&[case.to_str().unwrap(), "--taint-analysis", "--output-format", "json"]);
    assert!(
        findings.is_empty(),
        "a search-only SQL pack must produce no taint findings, got {findings:?}"
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

#[cfg(feature = "ruby")]
#[test]
fn ruby_rules_taint_and_search_validation() {
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
    let findings = scan_language_unified_with_rules(staging.path(), "ruby", rules);

    let unsafe_findings = findings_in_file(&findings, "ruby_case_unsafe.rb");
    let safe_findings = findings_in_file(&findings, "ruby_case_safe.rb");

    // Print findings for debugging purposes
    println!(
        "UNSAFE FINDINGS: {:?}",
        unsafe_findings.iter().map(|f| (f.line, &f.finding_type, &f.tags)).collect::<Vec<_>>()
    );
    println!(
        "SAFE FINDINGS: {:?}",
        safe_findings.iter().map(|f| (f.line, &f.finding_type, &f.tags)).collect::<Vec<_>>()
    );

    // All safe patterns (array literals, multiple arguments, escaped) must be CLEAN!
    assert!(
        safe_findings.is_empty(),
        "safe.rb should be clean from all findings, got {}: {:?}",
        safe_findings.len(),
        safe_findings
            .iter()
            .map(|f| (f.line, f.finding_type.as_str(), f.snippet.as_str()))
            .collect::<Vec<_>>()
    );

    // Unsafe patterns must trigger findings
    let unsafe_lines: BTreeSet<usize> = unsafe_findings.iter().map(|f| f.line).collect();

    // Assert key unsafe lines trigger findings
    assert!(unsafe_lines.contains(&4), "line 4 must trigger finding");
    assert!(unsafe_lines.contains(&5), "line 5 must trigger finding");
    assert!(unsafe_lines.contains(&6), "line 6 must trigger finding");
    assert!(unsafe_lines.contains(&7), "line 7 must trigger finding");
    assert!(unsafe_lines.contains(&8), "line 8 must trigger finding");
    assert!(unsafe_lines.contains(&9), "line 9 must trigger finding");
    assert!(unsafe_lines.contains(&12), "line 12 must trigger finding");
    assert!(unsafe_lines.contains(&25), "line 25 must trigger finding");
    assert!(unsafe_lines.contains(&26), "line 26 must trigger finding");
    assert!(unsafe_lines.contains(&29), "line 29 must trigger finding");
    assert!(unsafe_lines.contains(&30), "line 30 must trigger finding");
    assert!(unsafe_lines.contains(&31), "line 31 must trigger finding");
    assert!(unsafe_lines.contains(&32), "line 32 must trigger finding (clustered -lc)");
    assert!(unsafe_lines.contains(&33), "line 33 must trigger finding (clustered -ec)");
    assert!(unsafe_lines.contains(&35), "line 35 must trigger finding (SQL injection)");

    assert!(
        unsafe_findings.len() >= 10,
        "unsafe.rb should trigger at least 10 findings, got {}: {:?}",
        unsafe_findings.len(),
        unsafe_findings
            .iter()
            .map(|f| (f.line, f.finding_type.as_str(), f.snippet.as_str()))
            .collect::<Vec<_>>()
    );
}
