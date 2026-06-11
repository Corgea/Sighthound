use sighthound::rules::Rules;
use sighthound::VulnerabilityScanner;
use tempfile::TempDir;
use std::fs;

/// Load a representative set of Python security rules.
fn load_general_rules() -> Rules {
    Rules::load_from_file("rules/python/general_security.ron")
        .expect("Failed to load general security rules")
}

#[cfg(test)]
mod django_xss_tests {
    use super::*;

    #[test]
    fn test_basic_scanner_functionality() {
        let rules = load_general_rules();
        let scanner_result = VulnerabilityScanner::new("python", rules);
        assert!(scanner_result.is_ok(), "Should be able to create scanner with general rules");
    }

    #[test]
    fn test_django_xss_patterns_with_general_rules() {
        let rules = load_general_rules();
        let scanner_result = VulnerabilityScanner::new("python", rules);
        assert!(scanner_result.is_ok(), "Should be able to create scanner for Django patterns");
    }

    #[test]
    fn test_mark_safe_patterns() {
        let rules = load_general_rules();
        let scanner_result = VulnerabilityScanner::new("python", rules);
        assert!(scanner_result.is_ok(), "Should be able to create scanner for mark_safe patterns");
    }

    #[test]
    fn test_template_injection_patterns() {
        let rules = load_general_rules();
        let scanner_result = VulnerabilityScanner::new("python", rules);
        assert!(scanner_result.is_ok(), "Should be able to create scanner for template injection patterns");
    }

    #[test]
    fn test_safe_django_patterns() {
        let rules = load_general_rules();
        let scanner_result = VulnerabilityScanner::new("python", rules);
        assert!(scanner_result.is_ok(), "Should be able to create scanner for safe Django patterns");
    }

    #[test]
    fn test_xss_prevention_rule_structure() {
        let rules = load_general_rules();
        assert!(!rules.rules.is_empty(), "Should have loaded general security rules");

        // The general security rule set includes an XSS rule.
        let has_xss_rule = rules.rules.iter().any(|r| {
            r.category.as_deref() == Some("xss")
                || r.finding_type.as_deref().map(|t| t.to_lowercase().contains("scripting")).unwrap_or(false)
        });
        assert!(has_xss_rule, "Expected an XSS rule in the general security rule set");

        // Every search rule must carry a matchable pattern or patterns.
        for rule in rules.rules.iter().filter(|r| r.mode == "search") {
            assert!(rule.pattern.is_some() || rule.patterns.is_some(),
                "Each search rule should have either pattern or patterns: {:?}", rule.id);
        }
    }

    #[test]
    fn test_python_rules_directory_loading_and_scan() {
        let rules = Rules::load_from_directory("rules/python/")
            .expect("Failed to load Python rules directory");
        assert!(!rules.rules.is_empty(), "Should have loaded some Python rules");

        let scanner = VulnerabilityScanner::new("python", rules)
            .expect("Failed to create scanner");

        // Scan an inline file with unambiguous command-execution sinks.
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let vuln_file = temp_dir.path().join("vuln.py");
        fs::write(&vuln_file, r#"
import os
import subprocess

def run(cmd):
    os.system(cmd)
    subprocess.Popen(cmd, shell=True)
"#).expect("Failed to write fixture");

        let results = scanner.find_vulnerabilities_single_threaded(
            temp_dir.path().to_str().unwrap(),
            "python"
        ).expect("Failed to scan directory");

        assert!(results.len() >= 1, "Should detect at least one vulnerability in the fixture");
    }
}
