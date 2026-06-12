use sighthound::rules::Rules;
use std::io::Write;
use tempfile::NamedTempFile;

#[cfg(test)]
mod deserialization_tests {
    use super::*;

    #[test]
    fn test_single_pattern() {
        let ron_content = r#"(
            rules: [
                (
                    mode: "search",
                    pattern: Some("pyperclip.paste"),
                    finding_type: Some("clipboard_access"),
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
    fn test_multiple_patterns() {
        let ron_content = r#"(
            rules: [
                (
                    mode: "search",
                    patterns: Some([
                        "pyperclip.paste",
                        "pyperclip.copy",
                        "*.to_clipboard",
                    ]),
                    finding_type: Some("clipboard_access"),
                    file_types: Some((
                        extensions: Some([".py"]),
                    )),
                ),
            ],
        )"#;

        let rules: Rules =
            ron::from_str(ron_content).expect("Failed to parse multiple-patterns RON");

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
    fn test_mode_defaults_to_search() {
        // `mode` carries a serde default, so it may be omitted.
        let ron_content = r#"(
            rules: [
                (
                    pattern: Some("os.system"),
                    finding_type: Some("command_injection"),
                ),
            ],
        )"#;

        let rules: Rules =
            ron::from_str(ron_content).expect("Failed to parse RON without explicit mode");
        assert_eq!(rules.rules.len(), 1);
        assert_eq!(rules.rules[0].mode, "search");
        assert_eq!(rules.rules[0].pattern, Some("os.system".to_string()));
    }

    #[test]
    fn test_mixed_single_and_multiple() {
        let ron_content = r#"(
            rules: [
                (
                    mode: "search",
                    pattern: Some("single_pattern"),
                    finding_type: Some("test"),
                ),
                (
                    mode: "search",
                    patterns: Some([
                        "multi_pattern_1",
                        "multi_pattern_2",
                    ]),
                    finding_type: Some("test"),
                ),
            ],
        )"#;

        let rules: Rules = ron::from_str(ron_content).expect("Failed to parse mixed RON");

        assert_eq!(rules.rules.len(), 2);

        assert_eq!(rules.rules[0].pattern, Some("single_pattern".to_string()));
        assert_eq!(rules.rules[0].patterns, None);

        assert_eq!(rules.rules[1].pattern, None);
        assert_eq!(
            rules.rules[1].patterns,
            Some(vec![
                "multi_pattern_1".to_string(),
                "multi_pattern_2".to_string(),
            ])
        );
    }

    #[test]
    fn test_conditions() {
        let ron_content = r#"(
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

        let rules: Rules = ron::from_str(ron_content).expect("Failed to parse conditions RON");

        assert_eq!(rules.rules.len(), 1);

        let rule = &rules.rules[0];
        assert_eq!(rule.pattern, Some("subprocess.Popen".to_string()));

        let conditions = rule.conditions.as_ref().unwrap();
        assert_eq!(conditions.len(), 2);

        assert_eq!(conditions[0].pattern, Some("shell=True".to_string()));
        assert_eq!(conditions[0].patterns, None);
        assert_eq!(
            conditions[0].condition_type,
            Some("has_argument".to_string())
        );

        assert_eq!(conditions[1].pattern, None);
        assert_eq!(
            conditions[1].patterns,
            Some(vec!["*.exe*".to_string(), "*.bat*".to_string(),])
        );

        let file_types = rule.file_types.as_ref().unwrap();
        assert_eq!(file_types.extensions, Some(vec![".py".to_string()]));
        assert_eq!(
            file_types.include_patterns,
            Some(vec!["*test*".to_string()])
        );
        assert_eq!(
            file_types.exclude_patterns,
            Some(vec!["*safe*".to_string()])
        );
    }

    #[test]
    fn test_file_loading_and_parsing() {
        let ron_content = r#"(
            rules: [
                (
                    mode: "search",
                    patterns: Some([
                        "keyboard.hook",
                        "keyboard.on_press",
                        "pynput.*",
                    ]),
                    finding_type: Some("keylogger"),
                    severity: Some("high"),
                    confidence: Some("medium"),
                    file_types: Some((
                        extensions: Some([".py", ".pyw"]),
                        exclude_patterns: Some(["*test*", "*demo*"]),
                    )),
                ),
                (
                    mode: "search",
                    pattern: Some("cursor.execute"),
                    finding_type: Some("sql_injection"),
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

        assert_eq!(rules.rules.len(), 2);

        let keylogger_rule = &rules.rules[0];
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

        let sql_rule = &rules.rules[1];
        assert_eq!(sql_rule.pattern, Some("cursor.execute".to_string()));
        assert_eq!(sql_rule.finding_type, Some("sql_injection".to_string()));
    }

    #[test]
    fn test_empty_rules_parses() {
        let ron_content = r#"(
            rules: [],
        )"#;

        let rules: Rules = ron::from_str(ron_content).expect("Failed to parse empty rules RON");
        assert_eq!(rules.rules.len(), 0);
    }

    #[test]
    fn test_none_and_empty_values() {
        let ron_content = r#"(
            rules: [
                (
                    mode: "search",
                    patterns: Some(["test"]),
                ),
            ],
        )"#;

        let rules: Rules =
            ron::from_str(ron_content).expect("Failed to parse RON with omitted optionals");

        assert_eq!(rules.rules.len(), 1);

        let rule = &rules.rules[0];
        assert_eq!(rule.pattern, None);
        assert_eq!(rule.patterns, Some(vec!["test".to_string()]));
        assert_eq!(rule.finding_type, None);
        assert!(rule.conditions.is_none());
        assert!(rule.file_types.is_none());
    }
}
