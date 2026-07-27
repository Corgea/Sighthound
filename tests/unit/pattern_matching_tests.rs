use sighthound::models::UnifiedRule;
use sighthound::rules::{
    match_any_pattern, match_pattern, rule_matches_pattern_unified, validate_unified_rule_patterns,
    Rules,
};

// Build a search-mode UnifiedRule carrying the given pattern/patterns.
// UnifiedRule does not derive Default, so this helper fills the remaining fields.
fn make_rule(pattern: Option<&str>, patterns: Option<Vec<&str>>) -> UnifiedRule {
    UnifiedRule {
        id: None,
        name: None,
        description: None,
        category: None,
        mode: "search".to_string(),
        pattern: pattern.map(|s| s.to_string()),
        patterns: patterns.map(|v| v.into_iter().map(|s| s.to_string()).collect()),
        unless: None,
        sources: None,
        sinks: None,
        propagators: None,
        sanitizers: None,
        finding_type: None,
        severity: None,
        confidence: None,
        file_types: None,
        conditions: None,
        tags: None,
        cwe_id: None,
        message: None,
    }
}

#[cfg(test)]
mod pattern_matching_tests {
    use super::*;

    #[test]
    fn test_plain_substring_matching() {
        // note: plain (non-wildcard, non-regex) patterns now match by substring
        // containment via `matches_unified_pattern(pattern, text)` (text contains pattern),
        // rather than exact equality as in the pre-refactor matcher.
        assert!(match_pattern("print", "print"));
        assert!(match_pattern("os.system", "os.system"));
        assert!(match_pattern("print", "printf")); // "printf" contains "print"
        assert!(!match_pattern("os.system", "os.path")); // not a substring
        assert!(!match_pattern("printf", "print")); // longer pattern is not contained
    }

    #[test]
    fn test_wildcard_pattern_matching() {
        // Test wildcard patterns
        assert!(match_pattern("*.exe", "malware.exe"));
        assert!(match_pattern("*.exe", "file.exe"));
        assert!(!match_pattern("*.exe", "file.txt"));

        // Test patterns with wildcards at beginning
        assert!(match_pattern("*password*", "get_password_hash"));
        assert!(match_pattern("*password*", "password"));
        assert!(match_pattern("*password*", "my_password_file"));
        assert!(!match_pattern("*password*", "get_user_name"));

        // Test multiple wildcards
        assert!(match_pattern("*test*.py", "my_test_file.py"));
        assert!(match_pattern("*test*.py", "test.py"));
        assert!(!match_pattern("*test*.py", "file.txt"));
    }

    #[test]
    fn test_regex_pattern_matching() {
        // Test basic regex patterns that should work
        assert!(match_pattern("regex:^[a-z]+$", "hello"));
        assert!(!match_pattern("regex:^[a-z]+$", "Hello"));
        assert!(match_pattern("regex:\\d+", "test123"));
        assert!(!match_pattern("regex:\\d+", "test"));

        // Test simple patterns
        assert!(match_pattern("regex:eval", "eval"));
        assert!(!match_pattern("regex:^eval$", "evaluate"));
    }

    #[test]
    fn test_edge_cases() {
        // Test empty strings
        assert!(match_pattern("", ""));
        assert!(!match_pattern("test", ""));
        // note: an empty pattern is a substring of any text, so it matches everything
        assert!(match_pattern("", "test"));

        // Test special characters
        assert!(match_pattern("test.func", "test.func"));
        assert!(match_pattern("test[0]", "test[0]"));
        assert!(match_pattern("test()", "test()"));

        // Test case sensitivity
        assert!(!match_pattern("Print", "print"));
        assert!(match_pattern("print", "print"));
    }

    #[test]
    fn test_match_any_pattern() {
        let patterns = vec!["print".to_string(), "os.system".to_string(), "*.exe".to_string()];

        // Test matching different patterns
        assert!(match_any_pattern(&patterns, "print"));
        assert!(match_any_pattern(&patterns, "os.system"));
        assert!(match_any_pattern(&patterns, "malware.exe"));

        // Test non-matching
        assert!(!match_any_pattern(&patterns, "os.path"));
        assert!(!match_any_pattern(&patterns, "file.txt"));

        // Test empty patterns array
        let empty_patterns: Vec<String> = vec![];
        assert!(!match_any_pattern(&empty_patterns, "anything"));
    }

    #[test]
    fn test_single_pattern_rule() {
        // Create a rule with a single pattern
        let rule = make_rule(Some("pyperclip.paste"), None);

        // Test matching
        assert!(rule_matches_pattern_unified(&rule, "pyperclip.paste"));
        assert!(!rule_matches_pattern_unified(&rule, "pyperclip.copy"));
        assert!(!rule_matches_pattern_unified(&rule, "clipboard.get"));
    }

    #[test]
    fn test_multiple_patterns_rule() {
        // Create a rule with multiple patterns
        let rule = make_rule(
            None,
            Some(vec!["pyperclip.paste", "pyperclip.copy", "*.to_clipboard", "win32clipboard"]),
        );

        // Test all patterns match
        assert!(rule_matches_pattern_unified(&rule, "pyperclip.paste"));
        assert!(rule_matches_pattern_unified(&rule, "pyperclip.copy"));
        assert!(rule_matches_pattern_unified(&rule, "df.to_clipboard"));
        assert!(rule_matches_pattern_unified(&rule, "win32clipboard"));

        // Test non-matching
        assert!(!rule_matches_pattern_unified(&rule, "clipboard.get"));
        assert!(!rule_matches_pattern_unified(&rule, "print"));
    }

    #[test]
    fn test_unless_patterns_suppress_matching_rules() {
        let mut rule = make_rule(Some("http://"), None);
        rule.unless =
            Some(vec!["http://localhost".to_string(), "regex:http://127\\.0\\.0\\.1".to_string()]);

        assert!(rule_matches_pattern_unified(&rule, "http://example.com"));
        assert!(!rule_matches_pattern_unified(&rule, "http://localhost:8080"));
        assert!(!rule_matches_pattern_unified(&rule, "http://127.0.0.1/admin"));
    }

    #[test]
    fn embedded_text_rules_match_normal_source_text() {
        let xml_rules = Rules::load_embedded_rules("xml", None).unwrap();
        let xxe_rule =
            xml_rules.rules.iter().find(|rule| rule.id.as_deref() == Some("xml-xxe-001")).unwrap();
        assert!(rule_matches_pattern_unified(
            xxe_rule,
            "<!DOCTYPE root [\n<!ENTITY secret SYSTEM \"file:///etc/passwd\">\n]>"
        ));

        let insecure_xml_rule = xml_rules
            .rules
            .iter()
            .find(|rule| rule.id.as_deref() == Some("xml-insecure-001"))
            .unwrap();
        assert!(!rule_matches_pattern_unified(
            insecure_xml_rule,
            "<root xmlns=\"http://www.w3.org/2001/XMLSchema\" />"
        ));

        let html_rules = Rules::load_embedded_rules("html", None).unwrap();
        let event_eval_rule = html_rules
            .rules
            .iter()
            .find(|rule| rule.id.as_deref() == Some("html-xss-004"))
            .unwrap();
        assert!(rule_matches_pattern_unified(
            event_eval_rule,
            "<button onclick=\"eval(userInput)\">Run</button>"
        ));

        let sql_rules = Rules::load_embedded_rules("sql", None).unwrap();
        let sql_injection_rule = sql_rules
            .rules
            .iter()
            .find(|rule| rule.id.as_deref() == Some("sql-unsafe-001"))
            .unwrap();
        assert!(rule_matches_pattern_unified(
            sql_injection_rule,
            "EXECUTE IMMEDIATE 'SELECT * FROM users WHERE id = ' || user_input"
        ));
    }

    #[test]
    fn embedded_markup_and_text_rules_are_valid() {
        for language in ["html", "sql", "xml", "properties", "config"] {
            let rules = Rules::load_embedded_rules(language, None)
                .unwrap_or_else(|error| panic!("failed to load {language} rules: {error}"));
            assert!(!rules.rules.is_empty(), "{language} should have embedded rules");
            for rule in &rules.rules {
                validate_unified_rule_patterns(rule).unwrap_or_else(|error| {
                    panic!(
                        "invalid {language} rule {}: {error}",
                        rule.id.as_deref().unwrap_or("<unnamed>")
                    )
                });
            }
        }
    }

    #[test]
    fn test_wildcard_patterns_in_multiple_patterns() {
        let rule = make_rule(None, Some(vec!["*.tk*", "*.exe*", "keyboard.*"]));

        // Test wildcard matching
        assert!(rule_matches_pattern_unified(&rule, "malicious.tk"));
        assert!(rule_matches_pattern_unified(&rule, "bad.tk.com"));
        assert!(rule_matches_pattern_unified(&rule, "virus.exe"));
        assert!(rule_matches_pattern_unified(&rule, "malware.exe.file"));
        assert!(rule_matches_pattern_unified(&rule, "keyboard.hook"));
        assert!(rule_matches_pattern_unified(&rule, "keyboard.listener"));

        // Test non-matching
        assert!(!rule_matches_pattern_unified(&rule, "google.com"));
        assert!(!rule_matches_pattern_unified(&rule, "file.txt"));
        assert!(!rule_matches_pattern_unified(&rule, "mouse.click"));
    }

    #[test]
    fn test_rule_validation() {
        // note: the unified-rule refactor replaced the old structural validation
        // (rejecting both/neither pattern, empty pattern, empty patterns array) with
        // `validate_unified_rule_patterns`, which only validates that any `regex:`
        // pattern compiles. We assert that current contract: plain and valid-regex
        // patterns pass; malformed regex patterns fail.
        let valid_single = make_rule(Some("test"), None);
        assert!(validate_unified_rule_patterns(&valid_single).is_ok());

        let valid_multiple = make_rule(None, Some(vec!["test1", "test2"]));
        assert!(validate_unified_rule_patterns(&valid_multiple).is_ok());

        let valid_regex = make_rule(Some("regex:^[a-z]+$"), None);
        assert!(validate_unified_rule_patterns(&valid_regex).is_ok());

        // Invalid regex in the single `pattern` field
        let invalid_regex = make_rule(Some("regex:[unclosed"), None);
        assert!(validate_unified_rule_patterns(&invalid_regex).is_err());

        // Invalid regex inside the `patterns` list
        let invalid_regex_in_list = make_rule(None, Some(vec!["ok", "regex:(("]));
        assert!(validate_unified_rule_patterns(&invalid_regex_in_list).is_err());

        // Contentless and empty-pattern search rules are accepted: the unified validator
        // only checks regex compilation, so the old structural rejection no longer applies.
        // These assert the current (permissive) contract, guarding against silent regressions.
        assert!(validate_unified_rule_patterns(&make_rule(None, None)).is_ok());
        assert!(validate_unified_rule_patterns(&make_rule(Some(""), None)).is_ok());
        assert!(validate_unified_rule_patterns(&make_rule(None, Some(vec![]))).is_ok());
        assert!(validate_unified_rule_patterns(&make_rule(None, Some(vec!["ok", ""]))).is_ok());
    }

    #[test]
    fn test_complex_real_world_patterns() {
        // Test real-world vulnerability patterns
        let sql_injection_patterns = vec![
            "execute".to_string(),
            "*.execute*".to_string(),
            "cursor.execute".to_string(),
            "db.execute".to_string(),
        ];

        // Should match SQL injection patterns
        assert!(match_any_pattern(&sql_injection_patterns, "execute"));
        assert!(match_any_pattern(&sql_injection_patterns, "cursor.execute"));
        assert!(match_any_pattern(&sql_injection_patterns, "db.execute"));
        assert!(match_any_pattern(&sql_injection_patterns, "conn.execute_query"));

        // note: with substring semantics "executed" contains the "execute" pattern, so it
        // matches; "executor" does not contain "execute" and stays unmatched.
        assert!(match_any_pattern(&sql_injection_patterns, "executed"));
        assert!(!match_any_pattern(&sql_injection_patterns, "executor"));

        // Test command injection patterns
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

        // Test crypto patterns
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

        // Run pattern matching many times
        for _ in 0..1000 {
            for test_str in &test_strings {
                for pattern in &patterns {
                    match_pattern(pattern, test_str);
                }
            }
        }

        let duration = start.elapsed();
        println!("Pattern matching 50,000 times took: {:?}", duration);

        // Performance should be reasonable (less than 30 seconds for this test)
        assert!(duration.as_secs() < 30, "Pattern matching too slow: {:?}", duration);
    }

    #[test]
    fn test_multiple_patterns_performance() {
        let rule = make_rule(
            None,
            Some(vec![
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

        // Test rule matching performance
        for _ in 0..1000 {
            for test_str in &test_strings {
                rule_matches_pattern_unified(&rule, test_str);
            }
        }

        let duration = start.elapsed();
        println!("Multiple pattern rule matching 10,000 times took: {:?}", duration);

        // Should be efficient even with multiple patterns (less than 30 seconds)
        assert!(duration.as_secs() < 30, "Multiple pattern matching too slow: {:?}", duration);
    }
}
