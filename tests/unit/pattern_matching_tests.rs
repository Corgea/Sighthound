use sighthound::rules::{
    match_any_pattern, match_pattern, rule_matches_pattern_unified, validate_unified_rule_patterns,
    Rules,
};
use sighthound::UnifiedRule;

// Exercises the pattern-matching primitives in `src/rules.rs`:
// `match_pattern`, `match_any_pattern`, `rule_matches_pattern_unified`, and
// `validate_unified_rule_patterns`. Rules used in these tests are built via
// RON deserialization so adding new optional fields to `UnifiedRule` doesn't
// break this file.

fn rule_from_ron(rule_body: &str) -> UnifiedRule {
    let ron = format!("(rules: [({})])", rule_body);
    let rules: Rules = ron::from_str(&ron).expect("Failed to parse rule fixture");
    rules.rules.into_iter().next().expect("Fixture should yield one rule")
}

#[cfg(test)]
mod pattern_matching_tests {
    use super::*;

    #[test]
    fn test_exact_pattern_matching() {
        // `match_pattern` short-circuits on exact equality first, then falls
        // back to substring matching for plain (non-glob, non-regex) patterns.
        // So `"printf".contains("print")` matches; mismatched substrings don't.
        assert!(match_pattern("print", "print"));
        assert!(match_pattern("os.system", "os.system"));
        assert!(match_pattern("print", "printf"));
        assert!(!match_pattern("os.system", "os.path"));
    }

    #[test]
    fn test_wildcard_pattern_matching() {
        assert!(match_pattern("*.exe", "malware.exe"));
        assert!(match_pattern("*.exe", "file.exe"));
        assert!(!match_pattern("*.exe", "file.txt"));

        assert!(match_pattern("*password*", "get_password_hash"));
        assert!(match_pattern("*password*", "password"));
        assert!(match_pattern("*password*", "my_password_file"));
        assert!(!match_pattern("*password*", "get_user_name"));

        assert!(match_pattern("*test*.py", "my_test_file.py"));
        assert!(match_pattern("*test*.py", "test.py"));
        assert!(!match_pattern("*test*.py", "file.txt"));
    }

    #[test]
    fn test_regex_pattern_matching() {
        assert!(match_pattern("regex:^[a-z]+$", "hello"));
        assert!(!match_pattern("regex:^[a-z]+$", "Hello"));
        assert!(match_pattern("regex:\\d+", "test123"));
        assert!(!match_pattern("regex:\\d+", "test"));

        assert!(match_pattern("regex:eval", "eval"));
        assert!(!match_pattern("regex:^eval$", "evaluate"));
    }

    #[test]
    fn test_edge_cases() {
        // Substring fallback means an empty pattern matches any text
        // (`text.contains("")` is always true), and any non-empty pattern fails
        // against an empty text.
        assert!(match_pattern("", ""));
        assert!(!match_pattern("test", ""));
        assert!(match_pattern("", "test"));

        assert!(match_pattern("test.func", "test.func"));
        assert!(match_pattern("test[0]", "test[0]"));
        assert!(match_pattern("test()", "test()"));

        assert!(!match_pattern("Print", "print"));
        assert!(match_pattern("print", "print"));
    }

    #[test]
    fn test_match_any_pattern() {
        let patterns = vec![
            "print".to_string(),
            "os.system".to_string(),
            "*.exe".to_string(),
        ];

        assert!(match_any_pattern(&patterns, "print"));
        assert!(match_any_pattern(&patterns, "os.system"));
        assert!(match_any_pattern(&patterns, "malware.exe"));

        assert!(!match_any_pattern(&patterns, "os.path"));
        assert!(!match_any_pattern(&patterns, "file.txt"));

        let empty_patterns: Vec<String> = vec![];
        assert!(!match_any_pattern(&empty_patterns, "anything"));
    }

    #[test]
    fn test_single_pattern_rule() {
        let rule = rule_from_ron(
            r#"
                pattern: Some("pyperclip.paste"),
                finding_type: Some("clipboard_access"),
            "#,
        );

        assert!(rule_matches_pattern_unified(&rule, "pyperclip.paste"));
        assert!(!rule_matches_pattern_unified(&rule, "pyperclip.copy"));
        assert!(!rule_matches_pattern_unified(&rule, "clipboard.get"));
    }

    #[test]
    fn test_multiple_patterns_rule() {
        let rule = rule_from_ron(
            r#"
                patterns: Some([
                    "pyperclip.paste",
                    "pyperclip.copy",
                    "*.to_clipboard",
                    "win32clipboard",
                ]),
                finding_type: Some("clipboard_access"),
            "#,
        );

        assert!(rule_matches_pattern_unified(&rule, "pyperclip.paste"));
        assert!(rule_matches_pattern_unified(&rule, "pyperclip.copy"));
        assert!(rule_matches_pattern_unified(&rule, "df.to_clipboard"));
        assert!(rule_matches_pattern_unified(&rule, "win32clipboard"));

        assert!(!rule_matches_pattern_unified(&rule, "clipboard.get"));
        assert!(!rule_matches_pattern_unified(&rule, "print"));
    }

    #[test]
    fn test_wildcard_patterns_in_multiple_patterns() {
        let rule = rule_from_ron(
            r#"
                patterns: Some([
                    "*.tk*",
                    "*.exe*",
                    "keyboard.*",
                ]),
                finding_type: Some("suspicious"),
            "#,
        );

        assert!(rule_matches_pattern_unified(&rule, "malicious.tk"));
        assert!(rule_matches_pattern_unified(&rule, "bad.tk.com"));
        assert!(rule_matches_pattern_unified(&rule, "virus.exe"));
        assert!(rule_matches_pattern_unified(&rule, "malware.exe.file"));
        assert!(rule_matches_pattern_unified(&rule, "keyboard.hook"));
        assert!(rule_matches_pattern_unified(&rule, "keyboard.listener"));

        assert!(!rule_matches_pattern_unified(&rule, "google.com"));
        assert!(!rule_matches_pattern_unified(&rule, "file.txt"));
        assert!(!rule_matches_pattern_unified(&rule, "mouse.click"));
    }

    #[test]
    fn test_rule_validation_regex_only() {
        // Under the unified schema, `validate_unified_rule_patterns` only
        // flags malformed `regex:` patterns — structural shapes like
        // "both pattern and patterns set" or "no patterns at all" are
        // considered valid (semantic checks live in the scanner).
        let single = rule_from_ron(r#"pattern: Some("test")"#);
        assert!(validate_unified_rule_patterns(&single).is_ok());

        let multiple = rule_from_ron(r#"patterns: Some(["test1", "test2"])"#);
        assert!(validate_unified_rule_patterns(&multiple).is_ok());

        let both = rule_from_ron(r#"pattern: Some("test"), patterns: Some(["test1"])"#);
        assert!(validate_unified_rule_patterns(&both).is_ok());

        let neither = rule_from_ron(r#"finding_type: Some("placeholder")"#);
        assert!(validate_unified_rule_patterns(&neither).is_ok());

        // The one shape that *should* fail today: a malformed regex.
        let bad_regex = rule_from_ron(r#"pattern: Some("regex:[unclosed")"#);
        assert!(validate_unified_rule_patterns(&bad_regex).is_err());

        let bad_regex_in_patterns =
            rule_from_ron(r#"patterns: Some(["fine", "regex:(?P<broken"])"#);
        assert!(validate_unified_rule_patterns(&bad_regex_in_patterns).is_err());
    }

    #[test]
    fn test_complex_real_world_patterns() {
        let sql_injection_patterns = vec![
            "execute".to_string(),
            "*.execute*".to_string(),
            "cursor.execute".to_string(),
            "db.execute".to_string(),
        ];

        assert!(match_any_pattern(&sql_injection_patterns, "execute"));
        assert!(match_any_pattern(&sql_injection_patterns, "cursor.execute"));
        assert!(match_any_pattern(&sql_injection_patterns, "db.execute"));
        assert!(match_any_pattern(&sql_injection_patterns, "conn.execute_query"));

        // The non-wildcard `"execute"` pattern falls back to substring matching,
        // so `"executed"` (which contains "execute") matches. `"executor"` —
        // which shares only the prefix `execut` — still misses every pattern.
        assert!(match_any_pattern(&sql_injection_patterns, "executed"));
        assert!(!match_any_pattern(&sql_injection_patterns, "executor"));
        assert!(!match_any_pattern(&sql_injection_patterns, "print_hello"));

        let command_injection_patterns = vec![
            "os.system".to_string(),
            "subprocess.*".to_string(),
            "*.Popen".to_string(),
            "shell=True".to_string(),
        ];

        assert!(match_any_pattern(&command_injection_patterns, "os.system"));
        assert!(match_any_pattern(&command_injection_patterns, "subprocess.call"));
        assert!(match_any_pattern(&command_injection_patterns, "subprocess.Popen"));
        assert!(match_any_pattern(&command_injection_patterns, "shell=True"));

        let crypto_patterns = vec![
            "*MD5*".to_string(),
            "*SHA1*".to_string(),
            "*.md5*".to_string(),
            "hashlib.md5".to_string(),
        ];

        assert!(match_any_pattern(&crypto_patterns, "hashlib.MD5"));
        assert!(match_any_pattern(&crypto_patterns, "crypto.SHA1"));
        assert!(match_any_pattern(&crypto_patterns, "file.md5"));
        assert!(match_any_pattern(&crypto_patterns, "hashlib.md5"));
    }
}

#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_pattern_matching_performance() {
        let patterns = vec![
            "print".to_string(),
            "*.exe".to_string(),
            "regex:^[a-z]+$".to_string(),
            "os.system".to_string(),
            "subprocess.*".to_string(),
        ];

        let test_strings = vec![
            "print",
            "malware.exe",
            "hello",
            "os.system",
            "subprocess.call",
            "safe_function",
            "file.txt",
            "HELLO",
            "os.path",
            "process.run",
        ];

        let start = Instant::now();

        for _ in 0..1000 {
            for test_str in &test_strings {
                for pattern in &patterns {
                    match_pattern(pattern, test_str);
                }
            }
        }

        let duration = start.elapsed();
        println!("Pattern matching 50,000 times took: {:?}", duration);
        assert!(
            duration.as_secs() < 30,
            "Pattern matching too slow: {:?}",
            duration
        );
    }

    #[test]
    fn test_multiple_patterns_performance() {
        let rule = rule_from_ron(
            r#"
                patterns: Some([
                    "print",
                    "*.exe",
                    "os.system",
                    "subprocess.*",
                    "*password*",
                    "regex:^[a-z]+$",
                    "eval",
                    "exec",
                    "*.dll",
                    "malloc",
                ]),
            "#,
        );

        let test_strings = vec![
            "print",
            "malware.exe",
            "os.system",
            "subprocess.call",
            "get_password",
            "hello",
            "eval",
            "exec",
            "library.dll",
            "malloc",
        ];

        let start = Instant::now();

        for _ in 0..1000 {
            for test_str in &test_strings {
                rule_matches_pattern_unified(&rule, test_str);
            }
        }

        let duration = start.elapsed();
        println!("Multiple pattern rule matching 10,000 times took: {:?}", duration);
        assert!(
            duration.as_secs() < 30,
            "Multiple pattern matching too slow: {:?}",
            duration
        );
    }
}
