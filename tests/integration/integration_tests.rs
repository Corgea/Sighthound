use sighthound::rules::{Rules, rule_matches_pattern_unified, validate_unified_rule_patterns};
use tempfile::NamedTempFile;
use std::io::Write;

#[cfg(test)]
mod integration_tests {
    use super::*;

    fn create_test_rules_file(content: &str) -> NamedTempFile {
        let mut temp_file = NamedTempFile::with_suffix(".ron").expect("Failed to create temp file");
        write!(temp_file, "{}", content).expect("Failed to write to temp file");
        temp_file
    }

    #[test]
    fn test_single_pattern_rule_loading() {
        let rules_content = r#"(
            rules: [
                (
                    mode: "search",
                    pattern: Some("pyperclip.copy"),
                    finding_type: Some("clipboard_access"),
                    severity: Some("medium"),
                    file_types: Some((
                        extensions: Some([".py"]),
                    )),
                ),
                (
                    mode: "search",
                    pattern: Some("pyperclip.paste"),
                    finding_type: Some("clipboard_access"),
                    severity: Some("medium"),
                    file_types: Some((
                        extensions: Some([".py"]),
                    )),
                ),
            ],
        )"#;
        let rules_file = create_test_rules_file(rules_content);

        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");

        assert_eq!(rules.rules.len(), 2);

        for rule in &rules.rules {
            assert!(validate_unified_rule_patterns(rule).is_ok());
        }

        assert!(rule_matches_pattern_unified(&rules.rules[0], "pyperclip.copy"));
        assert!(!rule_matches_pattern_unified(&rules.rules[0], "pyperclip.paste"));
        assert!(rule_matches_pattern_unified(&rules.rules[1], "pyperclip.paste"));
        assert!(!rule_matches_pattern_unified(&rules.rules[1], "pyperclip.copy"));
    }

    #[test]
    fn test_multiple_patterns_rule_loading() {
        let rules_content = r#"(
            rules: [
                (
                    mode: "search",
                    patterns: Some([
                        "pyperclip.copy",
                        "pyperclip.paste",
                        "*.to_clipboard",
                        "*.clipboard_append",
                    ]),
                    finding_type: Some("clipboard_access"),
                    severity: Some("medium"),
                    confidence: Some("high"),
                    file_types: Some((
                        extensions: Some([".py"]),
                    )),
                ),
            ],
        )"#;
        let rules_file = create_test_rules_file(rules_content);

        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");

        assert_eq!(rules.rules.len(), 1);

        let rule = &rules.rules[0];
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
        let rules_content = r#"(
            rules: [
                (
                    mode: "search",
                    patterns: Some([
                        "keyboard.*",
                        "*.exe*",
                    ]),
                    finding_type: Some("suspicious_activity"),
                    severity: Some("high"),
                    file_types: Some((
                        extensions: Some([".py"]),
                    )),
                ),
            ],
        )"#;
        let rules_file = create_test_rules_file(rules_content);

        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");

        let rule = &rules.rules[0];

        assert!(rule_matches_pattern_unified(rule, "keyboard.hook"));
        assert!(rule_matches_pattern_unified(rule, "keyboard.on_press"));
        assert!(rule_matches_pattern_unified(rule, "malware.exe"));
        assert!(rule_matches_pattern_unified(rule, "virus.exe.hidden"));

        assert!(!rule_matches_pattern_unified(rule, "mouse.click"));
        assert!(!rule_matches_pattern_unified(rule, "file.txt"));
    }

    #[test]
    fn test_rule_validation_integration() {
        // Valid patterns (literal + regex) validate; an invalid regex must fail.
        let test_cases = vec![
            (r#"(rules: [(mode: "search", pattern: Some("test_function"), finding_type: Some("test"))])"#, true),
            (r#"(rules: [(mode: "search", patterns: Some(["test1", "test2"]), finding_type: Some("test"))])"#, true),
            (r#"(rules: [(mode: "search", pattern: Some("regex:^valid[0-9]+$"), finding_type: Some("test"))])"#, true),
            (r#"(rules: [(mode: "search", pattern: Some("regex:[unterminated"), finding_type: Some("test"))])"#, false),
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
        let rules_content = r#"(
            rules: [
                (
                    mode: "search",
                    pattern: Some("dangerous_function"),
                    finding_type: Some("test"),
                    file_types: Some((
                        extensions: Some([".py"]),
                    )),
                ),
                (
                    mode: "search",
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

        assert_eq!(rules.rules.len(), 2);

        let file_types1 = rules.rules[0].file_types.as_ref().unwrap();
        assert_eq!(file_types1.extensions, Some(vec![".py".to_string()]));
        assert_eq!(file_types1.include_patterns, None);
        assert_eq!(file_types1.exclude_patterns, None);

        let file_types2 = rules.rules[1].file_types.as_ref().unwrap();
        assert_eq!(file_types2.extensions, Some(vec![".py".to_string(), ".pyw".to_string()]));
        assert_eq!(file_types2.include_patterns, Some(vec!["*test*".to_string()]));
        assert_eq!(file_types2.exclude_patterns, Some(vec!["*safe*".to_string()]));
    }

    #[test]
    fn test_conditions_with_patterns() {
        let rules_content = r#"(
            rules: [
                (
                    mode: "search",
                    pattern: Some("subprocess.Popen"),
                    finding_type: Some("command_injection"),
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
                            operator: "matches",
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
        assert_eq!(conditions[1].patterns, Some(vec![
            "*.exe*".to_string(),
            "*.bat*".to_string(),
            "*.cmd*".to_string(),
        ]));
    }

    #[test]
    fn test_real_world_patterns() {
        let rules_content = r#"(
            rules: [
                (
                    mode: "search",
                    patterns: Some([
                        "*.tk*",
                        "*.ml*",
                        "*.ga*",
                        "*.cf*",
                    ]),
                    finding_type: Some("suspicious_domain"),
                    severity: Some("medium"),
                    file_types: Some((
                        extensions: Some([".py"]),
                    )),
                ),
                (
                    mode: "search",
                    patterns: Some([
                        "bit.ly",
                        "tinyurl",
                        "t.co",
                    ]),
                    finding_type: Some("url_shortener"),
                    severity: Some("low"),
                    file_types: Some((
                        extensions: Some([".py"]),
                    )),
                ),
            ],
        )"#;
        let rules_file = create_test_rules_file(rules_content);

        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");

        assert_eq!(rules.rules.len(), 2);

        let domain_rule = &rules.rules[0];
        assert!(rule_matches_pattern_unified(domain_rule, "malicious.tk"));
        assert!(rule_matches_pattern_unified(domain_rule, "bad.ml.site"));
        assert!(rule_matches_pattern_unified(domain_rule, "evil.ga"));
        assert!(rule_matches_pattern_unified(domain_rule, "virus.cf.com"));
        assert!(!rule_matches_pattern_unified(domain_rule, "google.com"));

        let url_rule = &rules.rules[1];
        assert!(rule_matches_pattern_unified(url_rule, "bit.ly"));
        assert!(rule_matches_pattern_unified(url_rule, "tinyurl"));
        assert!(rule_matches_pattern_unified(url_rule, "t.co"));
        assert!(!rule_matches_pattern_unified(url_rule, "github.com"));
    }
}
