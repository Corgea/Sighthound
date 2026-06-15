use sighthound::models::Finding;
use sighthound::rules::Rules;
use sighthound::VulnerabilityScanner;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

pub fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn fixture_path(relative: &str) -> PathBuf {
    manifest_dir().join(relative)
}

pub fn load_rules(relative: &str) -> Rules {
    Rules::load_from_file(fixture_path(relative).to_str().unwrap())
        .unwrap_or_else(|e| panic!("failed to load rules {}: {e}", relative))
}

pub fn load_production_python_rules() -> Rules {
    Rules::load_from_directory("rules/python/").expect("failed to load production python rules")
}

#[cfg(feature = "javascript")]
pub fn load_production_javascript_rules() -> Rules {
    Rules::load_from_directory("rules/javascript/")
        .expect("failed to load production javascript rules")
}

pub fn stage_dir() -> TempDir {
    TempDir::new().expect("failed to create temp directory")
}

/// Copy a fixture file into a staging directory, optionally rewriting content.
pub fn stage_file(
    staging: &Path,
    source_relative: &str,
    dest_name: &str,
    replacements: &[(&str, &str)],
) -> PathBuf {
    let source = fixture_path(source_relative);
    let mut content = fs::read_to_string(&source)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", source.display()));
    for (from, to) in replacements {
        content = content.replace(from, to);
    }
    let dest = staging.join(dest_name);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::write(&dest, content).expect("failed to write staged file");
    dest
}

pub fn write_staged_file(staging: &Path, name: &str, content: &str) -> PathBuf {
    let dest = staging.join(name);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::write(&dest, content).expect("failed to write staged file");
    dest
}

pub fn scan_python_taint_with_rules(staging: &Path, rules: Rules) -> Vec<Finding> {
    let scanner = VulnerabilityScanner::new("python", rules).expect("failed to create scanner");
    let findings = scanner
        .find_vulnerabilities_unified(staging.to_str().unwrap(), "python", false)
        .expect("scan failed");
    taint_findings(&findings)
}

pub fn scan_python_taint(staging: &Path, rules_relative: &str) -> Vec<Finding> {
    scan_python_taint_with_rules(staging, load_rules(rules_relative))
}

pub fn scan_python_simple_with_rules(staging: &Path, rules: Rules) -> Vec<Finding> {
    let scanner = VulnerabilityScanner::new("python", rules).expect("failed to create scanner");
    scanner
        .find_vulnerabilities_single_threaded(staging.to_str().unwrap(), "python")
        .expect("scan failed")
}

pub fn scan_language_simple_with_rules(
    staging: &Path,
    language: &str,
    rules: Rules,
) -> Vec<Finding> {
    let scanner = VulnerabilityScanner::new(language, rules).expect("failed to create scanner");
    scanner
        .find_vulnerabilities_single_threaded(staging.to_str().unwrap(), language)
        .expect("scan failed")
}

pub fn scan_language_unified_with_rules(
    staging: &Path,
    language: &str,
    rules: Rules,
) -> Vec<Finding> {
    let scanner = VulnerabilityScanner::new(language, rules).expect("failed to create scanner");
    scanner
        .find_vulnerabilities_unified(staging.to_str().unwrap(), language, false)
        .expect("scan failed")
}

#[cfg(feature = "javascript")]
pub fn scan_javascript_frontend_taint_with_rules(staging: &Path, rules: Rules) -> Vec<Finding> {
    let scanner = VulnerabilityScanner::new("javascript", rules).expect("failed to create scanner");
    let findings = scanner
        .find_vulnerabilities_unified_with_filters(
            staging.to_str().unwrap(),
            "javascript",
            false,
            Some("frontend"),
            None,
        )
        .expect("scan failed");
    taint_findings(&findings)
}

#[cfg(feature = "javascript")]
pub fn scan_javascript_frontend_taint(staging: &Path) -> Vec<Finding> {
    scan_javascript_frontend_taint_with_rules(staging, load_production_javascript_rules())
}

#[cfg(feature = "java")]
pub fn scan_java_simple_with_rules(staging: &Path, rules: Rules) -> Vec<Finding> {
    let scanner = VulnerabilityScanner::new("java", rules).expect("failed to create scanner");
    scanner
        .find_vulnerabilities_single_threaded(staging.to_str().unwrap(), "java")
        .expect("scan failed")
}

pub fn taint_findings(findings: &[Finding]) -> Vec<Finding> {
    findings
        .iter()
        .filter(|f| {
            f.tags
                .as_ref()
                .is_some_and(|tags| tags.iter().any(|t| t == "taint_analysis"))
        })
        .cloned()
        .collect()
}

pub fn cross_file_findings(findings: &[Finding]) -> Vec<&Finding> {
    findings
        .iter()
        .filter(|f| {
            f.tags
                .as_ref()
                .is_some_and(|tags| tags.iter().any(|t| t == "cross_file"))
        })
        .collect()
}

pub fn findings_in_file<'a>(findings: &'a [Finding], filename: &str) -> Vec<&'a Finding> {
    findings
        .iter()
        .filter(|f| f.file.ends_with(filename))
        .collect()
}

pub fn findings_in_line_range(
    findings: &[Finding],
    min_line: usize,
    max_line: usize,
) -> Vec<&Finding> {
    findings
        .iter()
        .filter(|f| f.line >= min_line && f.line <= max_line)
        .collect()
}

pub fn assert_no_findings_in_range(
    findings: &[Finding],
    min_line: usize,
    max_line: usize,
    context: &str,
) {
    let hits = findings_in_line_range(findings, min_line, max_line);
    assert!(
        hits.is_empty(),
        "{context}: expected no findings between lines {min_line}-{max_line}, got {}: {:?}",
        hits.len(),
        hits.iter()
            .map(|f| (f.line, &f.finding_type, &f.file))
            .collect::<Vec<_>>()
    );
}

pub fn assert_findings_in_range(
    findings: &[Finding],
    min_line: usize,
    max_line: usize,
    min_count: usize,
    context: &str,
) {
    let hits = findings_in_line_range(findings, min_line, max_line);
    assert!(
        hits.len() >= min_count,
        "{context}: expected at least {min_count} findings between lines {min_line}-{max_line}, got {}: {:?}",
        hits.len(),
        hits.iter()
            .map(|f| (f.line, &f.finding_type))
            .collect::<Vec<_>>()
    );
}

pub fn assert_no_cross_file_findings(findings: &[Finding], context: &str) {
    let hits = cross_file_findings(findings);
    assert!(
        hits.is_empty(),
        "{context}: expected no cross-file taint findings, got {}: {:?}",
        hits.len(),
        hits.iter()
            .map(|f| (f.file.as_str(), f.line, f.finding_type.as_str()))
            .collect::<Vec<_>>()
    );
}

pub fn assert_has_cross_file_finding_near(
    findings: &[Finding],
    filename: &str,
    line: usize,
    tolerance: usize,
    context: &str,
) {
    let hits: Vec<_> = cross_file_findings(findings)
        .into_iter()
        .filter(|f| f.file.ends_with(filename))
        .filter(|f| f.line.abs_diff(line) <= tolerance)
        .collect();
    assert!(
        !hits.is_empty(),
        "{context}: expected cross-file finding in {filename} near line {line} (±{tolerance}), got: {:?}",
        cross_file_findings(findings)
            .iter()
            .map(|f| (f.file.as_str(), f.line))
            .collect::<Vec<_>>()
    );
}
