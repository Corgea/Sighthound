use sighthound::rules::{rule_matches_pattern_unified, validate_unified_rule_patterns, Rules};
use std::io::Write;
use tempfile::NamedTempFile;

// note: rules now live in a single unified `rules: [...]` list. Pattern matching uses
// `rule_matches_pattern_unified` and validation uses `validate_unified_rule_patterns`
// (which validates regex patterns only). RON Option fields require explicit `Some(...)`.
#[cfg(test)]
mod integration_tests {
    use super::*;

    fn create_test_python_file(content: &str) -> NamedTempFile {
        let mut temp_file = NamedTempFile::with_suffix(".py").expect("Failed to create temp file");
        write!(temp_file, "{}", content).expect("Failed to write to temp file");
        temp_file
    }

    fn create_test_rules_file(content: &str) -> NamedTempFile {
        let mut temp_file = NamedTempFile::with_suffix(".ron").expect("Failed to create temp file");
        write!(temp_file, "{}", content).expect("Failed to write to temp file");
        temp_file
    }

    #[test]
    fn test_single_pattern_rule_scanning() {
        // Create test Python file with clipboard access
        let python_content = r#"
import pyperclip

def copy_data():
    pyperclip.copy("sensitive data")
    return True

def paste_data():
    data = pyperclip.paste()
    return data
"#;
        let _python_file = create_test_python_file(python_content);

        // Create rules with single patterns
        let rules_content = r#"(
            rules: [
                (
                    pattern: Some("pyperclip.copy"),
                    finding_type: Some("clipboard_access"),
                    severity: Some("medium"),
                    conditions: None,
                    file_types: Some((
                        extensions: Some([".py"]),
                        include_patterns: None,
                        exclude_patterns: None,
                    )),
                ),
                (
                    pattern: Some("pyperclip.paste"),
                    finding_type: Some("clipboard_access"),
                    severity: Some("medium"),
                    conditions: None,
                    file_types: Some((
                        extensions: Some([".py"]),
                        include_patterns: None,
                        exclude_patterns: None,
                    )),
                ),
            ]
        )"#;
        let rules_file = create_test_rules_file(rules_content);

        // Load and validate rules
        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");

        assert_eq!(rules.rules.len(), 2);

        // Validate each rule
        for rule in &rules.rules {
            assert!(validate_unified_rule_patterns(rule).is_ok());
        }

        // Test pattern matching
        assert!(rule_matches_pattern_unified(&rules.rules[0], "pyperclip.copy"));
        assert!(!rule_matches_pattern_unified(&rules.rules[0], "pyperclip.paste"));
        assert!(rule_matches_pattern_unified(&rules.rules[1], "pyperclip.paste"));
        assert!(!rule_matches_pattern_unified(&rules.rules[1], "pyperclip.copy"));
    }

    #[test]
    fn test_multiple_patterns_rule_scanning() {
        // Create test Python file with various clipboard operations
        let python_content = r#"
import pyperclip
import pandas as pd
import tkinter as tk

def test_clipboard_operations():
    # Various clipboard access patterns
    pyperclip.copy("data")
    data = pyperclip.paste()

    df = pd.DataFrame({"col": [1, 2, 3]})
    df.to_clipboard()

    root = tk.Tk()
    root.clipboard_append("text")

    # Non-matching function
    print("safe operation")
"#;
        let _python_file = create_test_python_file(python_content);

        // Create rules with multiple patterns
        let rules_content = r#"(
            rules: [
                (
                    patterns: Some([
                        "pyperclip.copy",
                        "pyperclip.paste",
                        "*.to_clipboard",
                        "*.clipboard_append",
                    ]),
                    finding_type: Some("clipboard_access"),
                    severity: Some("medium"),
                    confidence: Some("high"),
                    conditions: None,
                    file_types: Some((
                        extensions: Some([".py"]),
                        include_patterns: None,
                        exclude_patterns: None,
                    )),
                ),
            ]
        )"#;
        let rules_file = create_test_rules_file(rules_content);

        // Load and validate rules
        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");

        assert_eq!(rules.rules.len(), 1);

        let rule = &rules.rules[0];
        assert!(validate_unified_rule_patterns(rule).is_ok());

        // Test that all patterns match
        assert!(rule_matches_pattern_unified(rule, "pyperclip.copy"));
        assert!(rule_matches_pattern_unified(rule, "pyperclip.paste"));
        assert!(rule_matches_pattern_unified(rule, "df.to_clipboard"));
        assert!(rule_matches_pattern_unified(rule, "root.clipboard_append"));

        // Test non-matching patterns
        assert!(!rule_matches_pattern_unified(rule, "print"));
        assert!(!rule_matches_pattern_unified(rule, "clipboard.get"));
    }

    #[test]
    fn test_wildcard_patterns_in_multiple_patterns() {
        // Create test Python file with various suspicious patterns
        let python_content = r#"
import keyboard
import subprocess

def malicious_functions():
    keyboard.hook(callback)
    keyboard.on_press(handler)

    subprocess.call("malware.exe")
    subprocess.run("virus.exe.hidden")

    # Safe functions
    mouse.click()
    file.txt.read()
"#;
        let _python_file = create_test_python_file(python_content);

        // Create rules with wildcard patterns
        let rules_content = r#"(
            rules: [
                (
                    patterns: Some([
                        "keyboard.*",
                        "*.exe*",
                    ]),
                    finding_type: Some("suspicious_activity"),
                    severity: Some("high"),
                    conditions: None,
                    file_types: Some((
                        extensions: Some([".py"]),
                        include_patterns: None,
                        exclude_patterns: None,
                    )),
                ),
            ]
        )"#;
        let rules_file = create_test_rules_file(rules_content);

        // Load and validate rules
        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");

        let rule = &rules.rules[0];

        // Test wildcard matching
        assert!(rule_matches_pattern_unified(rule, "keyboard.hook"));
        assert!(rule_matches_pattern_unified(rule, "keyboard.on_press"));
        assert!(rule_matches_pattern_unified(rule, "malware.exe"));
        assert!(rule_matches_pattern_unified(rule, "virus.exe.hidden"));

        // Test non-matching patterns
        assert!(!rule_matches_pattern_unified(rule, "mouse.click"));
        assert!(!rule_matches_pattern_unified(rule, "file.txt"));
    }

    #[test]
    fn test_rule_validation_integration() {
        // note: validation now only checks that `regex:`-prefixed patterns compile, so the
        // "invalid" case below is a malformed regex rather than the old both-pattern case.
        let test_cases = vec![
            // Valid single pattern
            (
                r#"(
                rules: [
                    (
                        pattern: Some("test_function"),
                        finding_type: Some("test"),
                        conditions: None,
                        file_types: None,
                    ),
                ]
            )"#,
                true,
            ),
            // Valid multiple patterns
            (
                r#"(
                rules: [
                    (
                        patterns: Some(["test1", "test2"]),
                        finding_type: Some("test"),
                        conditions: None,
                        file_types: None,
                    ),
                ]
            )"#,
                true,
            ),
            // Invalid: malformed regex pattern (should parse but fail validation)
            (
                r#"(
                rules: [
                    (
                        pattern: Some("regex:[unclosed"),
                        finding_type: Some("test"),
                        conditions: None,
                        file_types: None,
                    ),
                ]
            )"#,
                false,
            ),
        ];

        for (rules_content, should_be_valid) in test_cases {
            let rules_file = create_test_rules_file(rules_content);
            let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
                .expect("Failed to load rules");

            for rule in &rules.rules {
                let validation_result = validate_unified_rule_patterns(rule);
                if should_be_valid {
                    assert!(validation_result.is_ok(), "Rule should be valid: {:?}", rule);
                } else {
                    assert!(validation_result.is_err(), "Rule should be invalid: {:?}", rule);
                }
            }
        }
    }

    #[test]
    fn test_file_type_filtering() {
        // Create rules that should only apply to Python files
        let rules_content = r#"(
            rules: [
                (
                    pattern: Some("dangerous_function"),
                    finding_type: Some("test"),
                    conditions: None,
                    file_types: Some((
                        extensions: Some([".py"]),
                        include_patterns: None,
                        exclude_patterns: None,
                    )),
                ),
                (
                    patterns: Some(["pattern1", "pattern2"]),
                    finding_type: Some("test"),
                    conditions: None,
                    file_types: Some((
                        extensions: Some([".py", ".pyw"]),
                        include_patterns: Some(["*test*"]),
                        exclude_patterns: Some(["*safe*"]),
                    )),
                ),
            ]
        )"#;
        let rules_file = create_test_rules_file(rules_content);

        // Load rules and verify file type filters
        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");

        assert_eq!(rules.rules.len(), 2);

        // Check first rule file types
        let file_types1 = rules.rules[0].file_types.as_ref().unwrap();
        assert_eq!(file_types1.extensions, Some(vec![".py".to_string()]));
        assert_eq!(file_types1.include_patterns, None);
        assert_eq!(file_types1.exclude_patterns, None);

        // Check second rule file types
        let file_types2 = rules.rules[1].file_types.as_ref().unwrap();
        assert_eq!(file_types2.extensions, Some(vec![".py".to_string(), ".pyw".to_string()]));
        assert_eq!(file_types2.include_patterns, Some(vec!["*test*".to_string()]));
        assert_eq!(file_types2.exclude_patterns, Some(vec!["*safe*".to_string()]));
    }

    #[test]
    fn test_conditions_with_patterns() {
        // Create rules with conditions that use both single and multiple patterns
        let rules_content = r#"(
            rules: [
                (
                    pattern: Some("subprocess.Popen"),
                    finding_type: Some("command_injection"),
                    conditions: Some([
                        (
                            field: "has_argument",
                            operator: "contains",
                            value: "shell=True",
                            pattern: Some("shell=True"),
                        ),
                        (
                            field: "has_argument",
                            operator: "matches",
                            value: "executables",
                            patterns: Some(["*.exe*", "*.bat*", "*.cmd*"]),
                        ),
                    ]),
                    file_types: None,
                ),
            ]
        )"#;
        let rules_file = create_test_rules_file(rules_content);

        // Load and validate rules
        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");

        let rule = &rules.rules[0];

        // Validate rule structure
        assert!(validate_unified_rule_patterns(rule).is_ok());
        assert_eq!(rule.pattern, Some("subprocess.Popen".to_string()));

        let conditions = rule.conditions.as_ref().unwrap();
        assert_eq!(conditions.len(), 2);

        // First condition with single pattern
        assert_eq!(conditions[0].pattern, Some("shell=True".to_string()));
        assert_eq!(conditions[0].patterns, None);

        // Second condition with multiple patterns
        assert_eq!(conditions[1].pattern, None);
        assert_eq!(
            conditions[1].patterns,
            Some(vec!["*.exe*".to_string(), "*.bat*".to_string(), "*.cmd*".to_string(),])
        );
    }

    #[test]
    fn test_real_world_malware_patterns() {
        // Test with realistic malware detection patterns
        let rules_content = r#"(
            rules: [
                (
                    patterns: Some([
                        "*.tk*",
                        "*.ml*",
                        "*.ga*",
                        "*.cf*",
                    ]),
                    finding_type: Some("suspicious_domain"),
                    severity: Some("medium"),
                    conditions: None,
                    file_types: Some((
                        extensions: Some([".py"]),
                        include_patterns: None,
                        exclude_patterns: None,
                    )),
                ),
                (
                    patterns: Some([
                        "bit.ly",
                        "tinyurl",
                        "t.co",
                    ]),
                    finding_type: Some("url_shortener"),
                    severity: Some("low"),
                    conditions: None,
                    file_types: Some((
                        extensions: Some([".py"]),
                        include_patterns: None,
                        exclude_patterns: None,
                    )),
                ),
            ]
        )"#;
        let rules_file = create_test_rules_file(rules_content);

        // Load rules
        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");

        assert_eq!(rules.rules.len(), 2);

        // Test suspicious domain patterns
        let domain_rule = &rules.rules[0];
        assert!(rule_matches_pattern_unified(domain_rule, "malicious.tk"));
        assert!(rule_matches_pattern_unified(domain_rule, "bad.ml.site"));
        assert!(rule_matches_pattern_unified(domain_rule, "evil.ga"));
        assert!(rule_matches_pattern_unified(domain_rule, "virus.cf.com"));
        assert!(!rule_matches_pattern_unified(domain_rule, "google.com"));

        // Test URL shortener patterns
        let url_rule = &rules.rules[1];
        assert!(rule_matches_pattern_unified(url_rule, "bit.ly"));
        assert!(rule_matches_pattern_unified(url_rule, "tinyurl"));
        assert!(rule_matches_pattern_unified(url_rule, "t.co"));
        assert!(!rule_matches_pattern_unified(url_rule, "github.com"));
    }

    #[test]
    fn test_csv_quotes_file_paths_with_commas() {
        let bin_path = if let Ok(path) = std::env::var("CARGO_BIN_EXE_sighthound") {
            std::path::PathBuf::from(path)
        } else {
            std::path::PathBuf::from("target/debug/sighthound")
        };

        if !bin_path.exists() {
            return;
        }

        let mut python_file = tempfile::Builder::new()
            .prefix("vulnerable,")
            .suffix(".py")
            .tempfile()
            .expect("Failed to create temp file");
        writeln!(python_file, "import os\nos.system(input())")
            .expect("Failed to write to temp file");

        let output = std::process::Command::new(&bin_path)
            .args([
                python_file.path().to_str().unwrap(),
                "python",
                "--simple-analysis",
                "--output-format",
                "csv",
            ])
            .output()
            .expect("failed to run sighthound");

        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).expect("CSV output should be UTF-8");
        let expected_prefix = format!("\"{}\",", python_file.path().display());
        assert!(
            stdout.lines().skip(1).any(|line| line.starts_with(&expected_prefix)),
            "CSV path containing a comma was not quoted:\n{stdout}"
        );
    }

    #[test]
    fn test_cli_exit_code_gating() {
        let bin_path = if let Ok(path) = std::env::var("CARGO_BIN_EXE_sighthound") {
            std::path::PathBuf::from(path)
        } else {
            std::path::PathBuf::from("target/debug/sighthound")
        };

        if !bin_path.exists() {
            return;
        }

        // os.system(cmd) is a known High finding in the embedded python rules.
        // We will test that High triggers "--fail-on-severity high" but NOT "--fail-on-severity critical".
        let python_content_high = r#"
import os
def run(cmd):
    os.system(cmd)
"#;
        let temp_file_high = create_test_python_file(python_content_high);
        let file_path_high = temp_file_high.path().to_str().unwrap();

        // pickle.loads(data) is a known Critical finding in the embedded python rules.
        // We will test that Critical triggers "--fail-on-severity critical".
        let python_content_critical = r#"
import pickle
def run(data):
    pickle.loads(data)
"#;
        let temp_file_critical = create_test_python_file(python_content_critical);
        let file_path_critical = temp_file_critical.path().to_str().unwrap();

        // no gate flag — should always succeed
        let status = std::process::Command::new(&bin_path)
            .args([file_path_high, "python", "--simple-analysis"])
            .status()
            .expect("failed to run sighthound");
        assert!(status.success());

        // --error-on-findings should flip exit code when there are findings
        let status = std::process::Command::new(&bin_path)
            .args([file_path_high, "python", "--simple-analysis", "--error-on-findings"])
            .status()
            .expect("failed to run sighthound");
        assert_eq!(status.code(), Some(1));

        // critical threshold — os.system is High, so critical threshold should NOT trigger on it
        let status = std::process::Command::new(&bin_path)
            .args([file_path_high, "python", "--simple-analysis", "--fail-on-severity", "critical"])
            .status()
            .expect("failed to run sighthound");
        assert!(status.success());

        // critical threshold — pickle.loads is Critical, so critical threshold should trigger on it
        let status = std::process::Command::new(&bin_path)
            .args([
                file_path_critical,
                "python",
                "--simple-analysis",
                "--fail-on-severity",
                "critical",
            ])
            .status()
            .expect("failed to run sighthound");
        assert_eq!(status.code(), Some(1));

        // high threshold — os.system is High, so high threshold should trigger on it
        let status = std::process::Command::new(&bin_path)
            .args([file_path_high, "python", "--simple-analysis", "--fail-on-severity", "high"])
            .status()
            .expect("failed to run sighthound");
        assert_eq!(status.code(), Some(1));

        // low threshold — still triggered since high >= low
        let status = std::process::Command::new(&bin_path)
            .args([file_path_high, "python", "--simple-analysis", "--fail-on-severity", "low"])
            .status()
            .expect("failed to run sighthound");
        assert_eq!(status.code(), Some(1));

        // bad severity value — validation should reject it
        let output = std::process::Command::new(&bin_path)
            .args([
                file_path_high,
                "python",
                "--simple-analysis",
                "--fail-on-severity",
                "invalid_level",
            ])
            .output()
            .expect("failed to run sighthound");
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("Invalid severity level: 'invalid_level'"), "got: {stderr}");
    }
}
