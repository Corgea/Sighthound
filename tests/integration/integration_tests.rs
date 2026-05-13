use sighthound::rules::{rule_matches_pattern_unified, validate_unified_rule_patterns, Rules};
use std::io::Write;
use tempfile::NamedTempFile;

// Integration tests covering the full Rules-file -> deserialize -> match cycle
// against the unified schema. Each fixture is the flat
// `( rules: [ ( ... ) ] )` shape that `src/models.rs::UnifiedRule` accepts.

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

        let rules_content = r#"(
            rules: [
                (
                    pattern: Some("pyperclip.copy"),
                    finding_type: Some("clipboard_access"),
                    severity: Some("medium"),
                    category: Some("malware"),
                    file_types: Some((
                        extensions: Some([".py"]),
                    )),
                ),
                (
                    pattern: Some("pyperclip.paste"),
                    finding_type: Some("clipboard_access"),
                    severity: Some("medium"),
                    category: Some("malware"),
                    file_types: Some((
                        extensions: Some([".py"]),
                    )),
                ),
            ],
        )"#;
        let rules_file = create_test_rules_file(rules_content);

        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");

        let malware_rules = rules.get_rules_by_category("malware");
        assert_eq!(malware_rules.len(), 2);

        for rule in &malware_rules {
            assert!(validate_unified_rule_patterns(rule).is_ok());
        }

        assert!(rule_matches_pattern_unified(malware_rules[0], "pyperclip.copy"));
        assert!(!rule_matches_pattern_unified(malware_rules[0], "pyperclip.paste"));
        assert!(rule_matches_pattern_unified(malware_rules[1], "pyperclip.paste"));
        assert!(!rule_matches_pattern_unified(malware_rules[1], "pyperclip.copy"));
    }

    #[test]
    fn test_multiple_patterns_rule_scanning() {
        let python_content = r#"
import pyperclip
import pandas as pd
import tkinter as tk

def test_clipboard_operations():
    pyperclip.copy("data")
    data = pyperclip.paste()

    df = pd.DataFrame({"col": [1, 2, 3]})
    df.to_clipboard()

    root = tk.Tk()
    root.clipboard_append("text")

    print("safe operation")
"#;
        let _python_file = create_test_python_file(python_content);

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
                    category: Some("malware"),
                    file_types: Some((
                        extensions: Some([".py"]),
                    )),
                ),
            ],
        )"#;
        let rules_file = create_test_rules_file(rules_content);

        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");

        let malware_rules = rules.get_rules_by_category("malware");
        assert_eq!(malware_rules.len(), 1);

        let rule = malware_rules[0];
        assert!(validate_unified_rule_patterns(rule).is_ok());

        assert!(rule_matches_pattern_unified(rule, "pyperclip.copy"));
        assert!(rule_matches_pattern_unified(rule, "pyperclip.paste"));
        assert!(rule_matches_pattern_unified(rule, "df.to_clipboard"));
        assert!(rule_matches_pattern_unified(rule, "root.clipboard_append"));

        assert!(!rule_matches_pattern_unified(rule, "print"));
        assert!(!rule_matches_pattern_unified(rule, "clipboard.get"));
    }

    #[test]
    fn test_wildcard_patterns_in_multiple_patterns() {
        let python_content = r#"
import keyboard
import subprocess

def malicious_functions():
    keyboard.hook(callback)
    keyboard.on_press(handler)

    subprocess.call("malware.exe")
    subprocess.run("virus.exe.hidden")

    mouse.click()
    file.txt.read()
"#;
        let _python_file = create_test_python_file(python_content);

        let rules_content = r#"(
            rules: [
                (
                    patterns: Some([
                        "keyboard.*",
                        "*.exe*",
                    ]),
                    finding_type: Some("suspicious_activity"),
                    severity: Some("high"),
                    category: Some("malware"),
                    file_types: Some((
                        extensions: Some([".py"]),
                    )),
                ),
            ],
        )"#;
        let rules_file = create_test_rules_file(rules_content);

        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");

        let malware_rules = rules.get_rules_by_category("malware");
        let rule = malware_rules[0];

        assert!(rule_matches_pattern_unified(rule, "keyboard.hook"));
        assert!(rule_matches_pattern_unified(rule, "keyboard.on_press"));
        assert!(rule_matches_pattern_unified(rule, "malware.exe"));
        assert!(rule_matches_pattern_unified(rule, "virus.exe.hidden"));

        assert!(!rule_matches_pattern_unified(rule, "mouse.click"));
        assert!(!rule_matches_pattern_unified(rule, "file.txt"));
    }

    #[test]
    fn test_rule_validation_integration() {
        // Current `validate_unified_rule_patterns` only flags malformed
        // `regex:` patterns; the structural shapes below are all valid.
        let valid_cases = [
            r#"(
                rules: [
                    (
                        pattern: Some("test_function"),
                        finding_type: Some("test"),
                    ),
                ],
            )"#,
            r#"(
                rules: [
                    (
                        patterns: Some(["test1", "test2"]),
                        finding_type: Some("test"),
                    ),
                ],
            )"#,
            r#"(
                rules: [
                    (
                        pattern: Some("test"),
                        patterns: Some(["test1", "test2"]),
                        finding_type: Some("test"),
                    ),
                ],
            )"#,
        ];

        for rules_content in valid_cases {
            let rules_file = create_test_rules_file(rules_content);
            let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
                .expect("Failed to load rules");

            for rule in &rules.rules {
                assert!(
                    validate_unified_rule_patterns(rule).is_ok(),
                    "Rule should pass validation: {:?}",
                    rule
                );
            }
        }

        // A malformed `regex:` pattern is the one shape that should fail
        // validation today.
        let invalid_regex = r#"(
            rules: [
                (
                    pattern: Some("regex:[unclosed"),
                    finding_type: Some("test"),
                ),
            ],
        )"#;
        let rules_file = create_test_rules_file(invalid_regex);
        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");
        assert!(
            validate_unified_rule_patterns(&rules.rules[0]).is_err(),
            "Malformed regex should fail validation"
        );
    }

    #[test]
    fn test_file_type_filtering() {
        let rules_content = r#"(
            rules: [
                (
                    pattern: Some("dangerous_function"),
                    finding_type: Some("test"),
                    file_types: Some((
                        extensions: Some([".py"]),
                    )),
                ),
                (
                    patterns: Some(["pattern1", "pattern2"]),
                    finding_type: Some("test"),
                    file_types: Some((
                        extensions: Some([".py", ".pyw"]),
                        include_patterns: Some(["*test*"]),
                        exclude_patterns: Some(["*safe*"]),
                    )),
                ),
            ],
        )"#;
        let rules_file = create_test_rules_file(rules_content);

        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");

        assert_eq!(rules.count_rules(), 2);

        let file_types1 = rules.rules[0].file_types.as_ref().unwrap();
        assert_eq!(file_types1.extensions, Some(vec![".py".to_string()]));
        assert_eq!(file_types1.include_patterns, None);
        assert_eq!(file_types1.exclude_patterns, None);

        let file_types2 = rules.rules[1].file_types.as_ref().unwrap();
        assert_eq!(
            file_types2.extensions,
            Some(vec![".py".to_string(), ".pyw".to_string()])
        );
        assert_eq!(file_types2.include_patterns, Some(vec!["*test*".to_string()]));
        assert_eq!(file_types2.exclude_patterns, Some(vec!["*safe*".to_string()]));
    }

    #[test]
    fn test_conditions_with_patterns() {
        let rules_content = r#"(
            rules: [
                (
                    pattern: Some("subprocess.Popen"),
                    finding_type: Some("command_injection"),
                    category: Some("command_injection"),
                    conditions: Some([
                        (
                            field: "argument",
                            operator: "contains",
                            value: "shell=True",
                            condition_type: Some("has_argument"),
                            pattern: Some("shell=True"),
                        ),
                        (
                            field: "argument",
                            operator: "matches_any",
                            value: "",
                            condition_type: Some("has_argument"),
                            patterns: Some(["*.exe*", "*.bat*", "*.cmd*"]),
                        ),
                    ]),
                ),
            ],
        )"#;
        let rules_file = create_test_rules_file(rules_content);

        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");

        let rule = &rules.rules[0];
        assert!(validate_unified_rule_patterns(rule).is_ok());
        assert_eq!(rule.pattern, Some("subprocess.Popen".to_string()));

        let conditions = rule.conditions.as_ref().unwrap();
        assert_eq!(conditions.len(), 2);

        assert_eq!(conditions[0].pattern, Some("shell=True".to_string()));
        assert_eq!(conditions[0].patterns, None);

        assert_eq!(conditions[1].pattern, None);
        assert_eq!(
            conditions[1].patterns,
            Some(vec![
                "*.exe*".to_string(),
                "*.bat*".to_string(),
                "*.cmd*".to_string(),
            ])
        );
    }

    #[test]
    fn test_real_world_malware_patterns() {
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
                    category: Some("malware"),
                    file_types: Some((
                        extensions: Some([".py"]),
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
                    category: Some("malware"),
                    file_types: Some((
                        extensions: Some([".py"]),
                    )),
                ),
            ],
        )"#;
        let rules_file = create_test_rules_file(rules_content);

        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");

        let malware_rules = rules.get_rules_by_category("malware");
        assert_eq!(malware_rules.len(), 2);

        let domain_rule = malware_rules[0];
        assert!(rule_matches_pattern_unified(domain_rule, "malicious.tk"));
        assert!(rule_matches_pattern_unified(domain_rule, "bad.ml.site"));
        assert!(rule_matches_pattern_unified(domain_rule, "evil.ga"));
        assert!(rule_matches_pattern_unified(domain_rule, "virus.cf.com"));
        assert!(!rule_matches_pattern_unified(domain_rule, "google.com"));

        let url_rule = malware_rules[1];
        assert!(rule_matches_pattern_unified(url_rule, "bit.ly"));
        assert!(rule_matches_pattern_unified(url_rule, "tinyurl"));
        assert!(rule_matches_pattern_unified(url_rule, "t.co"));
        assert!(!rule_matches_pattern_unified(url_rule, "github.com"));
    }
}
