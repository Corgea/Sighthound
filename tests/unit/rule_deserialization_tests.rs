use sighthound::rules::Rules;
use std::io::Write;
use tempfile::NamedTempFile;

// These tests verify the RON deserialization shapes the unified `Rules`
// schema accepts: single `pattern` vs `patterns` list, optional condition
// fields, mixed pattern shapes across multiple rules in one file, etc. The
// per-rule tuple mirrors `src/models.rs::UnifiedRule`. RON requires
// `Some(...)` wrappers for `Option<T>` fields, so every optional value is
// written explicitly here.

#[cfg(test)]
mod deserialization_tests {
    use super::*;

    #[test]
    fn test_single_pattern_rule() {
        let ron_content = r#"(
            rules: [
                (
                    pattern: Some("pyperclip.paste"),
                    finding_type: Some("clipboard_access"),
                    category: Some("malware"),
                    file_types: Some((
                        extensions: Some([".py"]),
                    )),
                ),
            ],
        )"#;

        let rules: Rules = ron::from_str(ron_content).expect("Failed to parse single-pattern RON");
        assert_eq!(rules.rules.len(), 1);

        let rule = &rules.rules[0];
        assert_eq!(rule.pattern, Some("pyperclip.paste".to_string()));
        assert_eq!(rule.patterns, None);
        assert_eq!(rule.finding_type, Some("clipboard_access".to_string()));

        let file_types = rule.file_types.as_ref().unwrap();
        assert_eq!(file_types.extensions, Some(vec![".py".to_string()]));
    }

    #[test]
    fn test_multiple_patterns_rule() {
        let ron_content = r#"(
            rules: [
                (
                    patterns: Some([
                        "pyperclip.paste",
                        "pyperclip.copy",
                        "*.to_clipboard",
                    ]),
                    finding_type: Some("clipboard_access"),
                    category: Some("malware"),
                    file_types: Some((
                        extensions: Some([".py"]),
                    )),
                ),
            ],
        )"#;

        let rules: Rules = ron::from_str(ron_content).expect("Failed to parse multi-pattern RON");
        assert_eq!(rules.rules.len(), 1);

        let rule = &rules.rules[0];
        assert_eq!(rule.pattern, None);
        assert_eq!(
            rule.patterns,
            Some(vec![
                "pyperclip.paste".to_string(),
                "pyperclip.copy".to_string(),
                "*.to_clipboard".to_string(),
            ])
        );
        assert_eq!(rule.finding_type, Some("clipboard_access".to_string()));
    }

    #[test]
    fn test_mixed_pattern_shapes_across_rules() {
        // Verifies that a single rules file can mix single-`pattern` and
        // multi-`patterns` rules side by side and deserialize cleanly.
        let ron_content = r#"(
            rules: [
                (
                    pattern: Some("single_pattern_a"),
                    finding_type: Some("test"),
                ),
                (
                    pattern: Some("single_pattern_b"),
                    finding_type: Some("test"),
                ),
                (
                    patterns: Some([
                        "multi_pattern_1",
                        "multi_pattern_2",
                    ]),
                    finding_type: Some("test"),
                ),
            ],
        )"#;

        let rules: Rules = ron::from_str(ron_content).expect("Failed to parse mixed shapes RON");
        assert_eq!(rules.rules.len(), 3);

        assert_eq!(rules.rules[0].pattern, Some("single_pattern_a".to_string()));
        assert_eq!(rules.rules[0].patterns, None);

        assert_eq!(rules.rules[1].pattern, Some("single_pattern_b".to_string()));
        assert_eq!(rules.rules[1].patterns, None);

        assert_eq!(rules.rules[2].pattern, None);
        assert_eq!(
            rules.rules[2].patterns,
            Some(vec![
                "multi_pattern_1".to_string(),
                "multi_pattern_2".to_string(),
            ])
        );
    }

    #[test]
    fn test_rule_with_conditions() {
        let ron_content = r#"(
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
                            patterns: Some(["*.exe*", "*.bat*"]),
                        ),
                    ]),
                    file_types: Some((
                        extensions: Some([".py"]),
                        include_patterns: Some(["*test*"]),
                        exclude_patterns: Some(["*safe*"]),
                    )),
                ),
            ],
        )"#;

        let rules: Rules = ron::from_str(ron_content).expect("Failed to parse rule with conditions");
        assert_eq!(rules.rules.len(), 1);

        let rule = &rules.rules[0];
        assert_eq!(rule.pattern, Some("subprocess.Popen".to_string()));

        let conditions = rule.conditions.as_ref().unwrap();
        assert_eq!(conditions.len(), 2);

        assert_eq!(conditions[0].pattern, Some("shell=True".to_string()));
        assert_eq!(conditions[0].patterns, None);

        assert_eq!(conditions[1].pattern, None);
        assert_eq!(
            conditions[1].patterns,
            Some(vec!["*.exe*".to_string(), "*.bat*".to_string()])
        );

        let file_types = rule.file_types.as_ref().unwrap();
        assert_eq!(file_types.extensions, Some(vec![".py".to_string()]));
        assert_eq!(file_types.include_patterns, Some(vec!["*test*".to_string()]));
        assert_eq!(file_types.exclude_patterns, Some(vec!["*safe*".to_string()]));
    }

    #[test]
    fn test_file_loading_and_parsing() {
        let ron_content = r#"(
            rules: [
                (
                    patterns: Some([
                        "keyboard.hook",
                        "keyboard.on_press",
                        "pynput.*",
                    ]),
                    finding_type: Some("keylogger"),
                    severity: Some("high"),
                    confidence: Some("medium"),
                    category: Some("malware"),
                    file_types: Some((
                        extensions: Some([".py", ".pyw"]),
                        exclude_patterns: Some(["*test*", "*demo*"]),
                    )),
                ),
                (
                    pattern: Some("cursor.execute"),
                    finding_type: Some("sql_injection"),
                    category: Some("injection"),
                    conditions: Some([
                        (
                            field: "argument",
                            operator: "matches",
                            value: "",
                            condition_type: Some("has_argument"),
                            pattern: Some("*SELECT*"),
                        ),
                    ]),
                    file_types: Some((
                        extensions: Some([".py"]),
                    )),
                ),
            ],
        )"#;

        let mut temp_file = NamedTempFile::with_suffix(".ron").expect("Failed to create temp file");
        write!(temp_file, "{}", ron_content).expect("Failed to write to temp file");

        let rules = Rules::load_from_file(temp_file.path().to_str().unwrap())
            .expect("Failed to load rules from file");
        assert_eq!(rules.count_rules(), 2);

        let malware: Vec<_> = rules.get_rules_by_category("malware");
        assert_eq!(malware.len(), 1);
        let keylogger_rule = malware[0];
        assert_eq!(
            keylogger_rule.patterns,
            Some(vec![
                "keyboard.hook".to_string(),
                "keyboard.on_press".to_string(),
                "pynput.*".to_string(),
            ])
        );
        assert_eq!(keylogger_rule.severity, Some("high".to_string()));
        assert_eq!(keylogger_rule.confidence, Some("medium".to_string()));

        let injection: Vec<_> = rules.get_rules_by_category("injection");
        assert_eq!(injection.len(), 1);
        let sql_rule = injection[0];
        assert_eq!(sql_rule.pattern, Some("cursor.execute".to_string()));
        assert_eq!(sql_rule.finding_type, Some("sql_injection".to_string()));
    }

    #[test]
    fn test_both_pattern_and_patterns_is_structurally_valid() {
        // Having both `pattern` and `patterns` on the same rule is structurally
        // valid RON; semantic validation happens elsewhere.
        let ron_content = r#"(
            rules: [
                (
                    pattern: Some("test"),
                    patterns: Some(["test1", "test2"]),
                    finding_type: Some("test"),
                ),
            ],
        )"#;

        let rules: Result<Rules, _> = ron::from_str(ron_content);
        assert!(rules.is_ok(), "RON parsing should succeed even with both pattern and patterns set");
    }

    #[test]
    fn test_fully_explicit_optional_fields() {
        // The fully-explicit form — every optional field wrapped in `Some(...)`
        // or `None` — must round-trip cleanly.
        let ron_content = r#"(
            rules: [
                (
                    pattern: Some("old_style_pattern"),
                    patterns: None,
                    finding_type: Some("test"),
                    conditions: Some([
                        (
                            field: "argument",
                            operator: "matches",
                            value: "",
                            condition_type: Some("has_argument"),
                            pattern: Some("*old_style_condition*"),
                            patterns: None,
                        ),
                    ]),
                    file_types: Some((
                        extensions: Some([".py"]),
                        include_patterns: Some(["*old*"]),
                        exclude_patterns: Some(["*new*"]),
                    )),
                ),
            ],
        )"#;

        let rules: Rules =
            ron::from_str(ron_content).expect("Failed to parse fully-explicit RON");
        assert_eq!(rules.rules.len(), 1);

        let rule = &rules.rules[0];
        assert_eq!(rule.pattern, Some("old_style_pattern".to_string()));

        let conditions = rule.conditions.as_ref().unwrap();
        assert_eq!(conditions[0].pattern, Some("*old_style_condition*".to_string()));

        let file_types = rule.file_types.as_ref().unwrap();
        assert_eq!(file_types.extensions, Some(vec![".py".to_string()]));
        assert_eq!(file_types.include_patterns, Some(vec!["*old*".to_string()]));
        assert_eq!(file_types.exclude_patterns, Some(vec!["*new*".to_string()]));
    }

    #[test]
    fn test_none_values() {
        let ron_content = r#"(
            rules: [
                (
                    pattern: None,
                    patterns: Some(["test"]),
                    finding_type: None,
                ),
            ],
        )"#;

        let rules: Rules = ron::from_str(ron_content).expect("Failed to parse RON with None values");
        assert_eq!(rules.rules.len(), 1);

        let rule = &rules.rules[0];
        assert_eq!(rule.pattern, None);
        assert_eq!(rule.patterns, Some(vec!["test".to_string()]));
        assert_eq!(rule.finding_type, None);
        assert!(rule.conditions.is_none());
        assert!(rule.file_types.is_none());
    }

    #[test]
    fn test_empty_arrays() {
        let ron_content = r#"(
            rules: [
                (
                    patterns: Some([]),
                    finding_type: Some("test"),
                    conditions: Some([]),
                    file_types: Some((
                        extensions: Some([]),
                        include_patterns: Some([]),
                        exclude_patterns: Some([]),
                    )),
                ),
            ],
        )"#;

        let rules: Rules = ron::from_str(ron_content).expect("Failed to parse RON with empty arrays");
        assert_eq!(rules.rules.len(), 1);

        let rule = &rules.rules[0];
        assert!(rule.patterns.is_some());
        assert_eq!(rule.patterns.as_ref().unwrap().len(), 0);
        assert!(rule.conditions.is_some());
        assert_eq!(rule.conditions.as_ref().unwrap().len(), 0);

        let file_types = rule.file_types.as_ref().unwrap();
        assert_eq!(file_types.extensions.as_ref().unwrap().len(), 0);
        assert_eq!(file_types.include_patterns.as_ref().unwrap().len(), 0);
        assert_eq!(file_types.exclude_patterns.as_ref().unwrap().len(), 0);
    }
}
