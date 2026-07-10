//! Cucumber/Gherkin acceptance gate (`cargo harness acceptance`).
//!
//! Drives the scanner through its public library API — the same entry
//! points `tests/strictness/helpers.rs` uses (`Rules::load_from_*` +
//! `VulnerabilityScanner`) — never the CLI binary. Scenarios live under
//! `tests/features/`; each `.feature` file is plain Gherkin, no code.

use std::fs;
use std::path::PathBuf;

use cucumber::{World as _, given, then, when};
use sighthound::VulnerabilityScanner;
use sighthound::models::Finding;
use sighthound::rules::Rules;
use tempfile::TempDir;

/// Cucumber `World`: one staging directory per scenario, plus the outcome
/// of the most recent scan. Scenarios run in isolated staging dirs so
/// findings can be attributed to files by name without cross-scenario
/// interference.
#[derive(cucumber::World)]
#[world(init = Self::new)]
struct ScanWorld {
    staging: TempDir,
    findings: Vec<Finding>,
    scan_error: Option<String>,
}

impl ScanWorld {
    fn new() -> Self {
        Self {
            staging: TempDir::new().expect("failed to create staging directory"),
            findings: Vec::new(),
            scan_error: None,
        }
    }
}

// `TempDir` has no `Debug` impl; cucumber's default step runner requires
// `World: Debug`, so implement it by hand over the fields that matter.
impl std::fmt::Debug for ScanWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanWorld")
            .field("staging", &self.staging.path())
            .field("findings", &self.findings.len())
            .field("scan_error", &self.scan_error)
            .finish()
    }
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn write_into_staging(world: &ScanWorld, name: &str, content: &str) {
    let dest = world.staging.path().join(name);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::write(&dest, content).unwrap_or_else(|e| panic!("failed to write staged file {name}: {e}"));
}

/// Run a scan and record `Ok`/`Err` on the world — steps assert on either.
fn record_scan(world: &mut ScanWorld, result: anyhow::Result<Vec<Finding>>) {
    match result {
        Ok(findings) => {
            world.findings = findings;
            world.scan_error = None;
        }
        Err(e) => {
            world.findings.clear();
            world.scan_error = Some(e.to_string());
        }
    }
}

fn taint_tagged(findings: Vec<Finding>) -> Vec<Finding> {
    findings
        .into_iter()
        .filter(|f| f.tags.as_ref().is_some_and(|tags| tags.iter().any(|t| t == "taint_analysis")))
        .collect()
}

// ── Given ───────────────────────────────────────────────────────────

#[given(expr = "a staged copy of the fixture {string} as {string}")]
fn stage_fixture_copy(world: &mut ScanWorld, fixture: String, dest_name: String) {
    let source = manifest_dir().join(&fixture);
    let content = fs::read_to_string(&source)
        .unwrap_or_else(|e| panic!("failed to read fixture {fixture}: {e}"));
    write_into_staging(world, &dest_name, &content);
}

#[given(expr = "a staged file {string} with unsupported-extension content that looks vulnerable")]
fn stage_unsupported_extension_file(world: &mut ScanWorld, name: String) {
    // Deliberately reuses recognizable sink patterns (os.system, cursor.execute,
    // subprocess shell=True) so a false "supported" match would be caught —
    // this proves the file is skipped by extension, not merely by content.
    let content = "os.system(user_input)\n\
                   cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n\
                   subprocess.call(cmd, shell=True)\n";
    write_into_staging(world, &name, content);
}

#[given(expr = "a staged benign Python module {string}")]
fn stage_benign_python_module(world: &mut ScanWorld, name: String) {
    let content = r#"
def add(a, b):
    return a + b


def greet(name):
    return f"Hello, {name}!"


class Calculator:
    def multiply(self, a, b):
        return a * b

    def divide(self, a, b):
        if b == 0:
            raise ValueError("cannot divide by zero")
        return a / b
"#;
    write_into_staging(world, &name, content);
}

// ── When ────────────────────────────────────────────────────────────

#[when(expr = "I scan the staging directory as {string} with the production rules")]
fn scan_with_production_rules(world: &mut ScanWorld, language: String) {
    let rules = Rules::load_from_directory(&format!("rules/{language}/"))
        .unwrap_or_else(|e| panic!("failed to load production {language} rules: {e}"));
    let scanner = VulnerabilityScanner::new(&language, rules).expect("failed to create scanner");
    let path = world.staging.path().to_str().unwrap().to_string();
    let result = scanner.find_vulnerabilities_unified(&path, &language, false);
    record_scan(world, result);
}

#[when(expr = "I scan the staging directory as {string} with the frontend taint rules")]
fn scan_with_frontend_taint_rules(world: &mut ScanWorld, language: String) {
    let rules = Rules::load_from_directory(&format!("rules/{language}/"))
        .unwrap_or_else(|e| panic!("failed to load production {language} rules: {e}"));
    let scanner = VulnerabilityScanner::new(&language, rules).expect("failed to create scanner");
    let path = world.staging.path().to_str().unwrap().to_string();
    let result = scanner
        .find_vulnerabilities_unified_with_filters(&path, &language, false, Some("frontend"), None)
        .map(taint_tagged);
    record_scan(world, result);
}

#[when(expr = "I scan the staging directory as {string} with the {string} taint rule file")]
fn scan_with_taint_rule_file(world: &mut ScanWorld, language: String, rule_file: String) {
    let rules = Rules::load_from_file(&rule_file)
        .unwrap_or_else(|e| panic!("failed to load taint rule file {rule_file}: {e}"));
    let scanner = VulnerabilityScanner::new(&language, rules).expect("failed to create scanner");
    let path = world.staging.path().to_str().unwrap().to_string();
    let result = scanner.find_vulnerabilities_unified(&path, &language, false);
    record_scan(world, result);
}

#[when(expr = "I scan the staging directory as {string} using every rule in its rules directory")]
fn scan_using_every_rule_in_directory(world: &mut ScanWorld, language: String) {
    let rules = Rules::load_from_directory(&format!("rules/{language}/"))
        .unwrap_or_else(|e| panic!("failed to load {language} rules: {e}"));
    let scanner = VulnerabilityScanner::new(&language, rules).expect("failed to create scanner");
    let path = world.staging.path().to_str().unwrap().to_string();
    let result = scanner.find_vulnerabilities_single_threaded(&path, &language);
    record_scan(world, result);
}

// ── Then ────────────────────────────────────────────────────────────

#[then(expr = "the scan should succeed without error")]
fn assert_scan_succeeded(world: &mut ScanWorld) {
    assert!(
        world.scan_error.is_none(),
        "expected scan to succeed, got error: {:?}",
        world.scan_error
    );
}

#[then(expr = "the findings should include a {string} finding in {string}")]
fn assert_finding_type_in_file(world: &mut ScanWorld, finding_type: String, filename: String) {
    let found = world
        .findings
        .iter()
        .any(|f| f.finding_type == finding_type && f.file.ends_with(&filename));
    assert!(
        found,
        "expected a {finding_type:?} finding in {filename:?}, got: {:?}",
        world
            .findings
            .iter()
            .map(|f| (f.line, f.finding_type.as_str(), f.file.as_str()))
            .collect::<Vec<_>>()
    );
}

#[then(expr = "the findings should include a finding whose type contains {string} in {string}")]
fn assert_finding_type_contains_in_file(
    world: &mut ScanWorld,
    substring: String,
    filename: String,
) {
    let found = world
        .findings
        .iter()
        .any(|f| f.finding_type.contains(&substring) && f.file.ends_with(&filename));
    assert!(
        found,
        "expected a finding whose type contains {substring:?} in {filename:?}, got: {:?}",
        world
            .findings
            .iter()
            .map(|f| (f.line, f.finding_type.as_str(), f.file.as_str()))
            .collect::<Vec<_>>()
    );
}

#[then(expr = "the findings should include a taint finding in {string}")]
fn assert_taint_finding_in_file(world: &mut ScanWorld, filename: String) {
    let found = world.findings.iter().any(|f| {
        f.file.ends_with(&filename)
            && f.tags.as_ref().is_some_and(|tags| tags.iter().any(|t| t == "taint_analysis"))
    });
    assert!(
        found,
        "expected a taint-tagged finding in {filename:?}, got: {:?}",
        world
            .findings
            .iter()
            .map(|f| (f.line, f.finding_type.as_str(), f.file.as_str()))
            .collect::<Vec<_>>()
    );
}

#[then(expr = "no findings should be reported")]
fn assert_no_findings(world: &mut ScanWorld) {
    assert!(
        world.findings.is_empty(),
        "expected zero findings, got {}: {:?}",
        world.findings.len(),
        world
            .findings
            .iter()
            .map(|f| (f.line, f.finding_type.as_str(), f.file.as_str()))
            .collect::<Vec<_>>()
    );
}

#[then(expr = "no findings should reference {string}")]
fn assert_no_findings_reference(world: &mut ScanWorld, filename: String) {
    let offenders: Vec<_> = world.findings.iter().filter(|f| f.file.ends_with(&filename)).collect();
    assert!(
        offenders.is_empty(),
        "expected no findings referencing {filename:?}, got: {:?}",
        offenders.iter().map(|f| (f.line, f.finding_type.as_str())).collect::<Vec<_>>()
    );
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    ScanWorld::run("tests/features").await;
}
