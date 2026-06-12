use sighthound::models::UnifiedRule;
use sighthound::rules::{
    match_any_pattern, match_pattern, rule_matches_pattern_unified, validate_unified_rule_patterns,
};

/// Build a minimal search-mode rule for pattern-matching tests.
fn search_rule(pattern: Option<&str>, patterns: Option<Vec<&str>>) -> UnifiedRule {
    UnifiedRule {
        id: None,
        name: None,
        description: None,
        category: None,
        mode: "search".to_string(),
        pattern: pattern.map(|p| p.to_string()),
        patterns: patterns.map(|ps| ps.into_iter().map(|p| p.to_string()).collect()),
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
    fn test_substring_pattern_matching() {
        // A non-wildcard, non-regex pattern matches as a substring of the text.
        assert!(match_pattern("print", "print"));
        assert!(match_pattern("os.system", "os.system"));
        assert!(match_pattern("print", "printf")); // "printf" contains "print"
        assert!(match_pattern("system", "os.system")); // "os.system" contains "system"
        assert!(!match_pattern("os.system", "os.path"));
        assert!(!match_pattern("xyz", "os.system"));
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
        assert!(match_pattern("", ""));
        assert!(!match_pattern("test", ""));
        // An empty pattern is a substring of any text.
        assert!(match_pattern("", "test"));

        assert!(match_pattern("test.func", "test.func"));
        assert!(match_pattern("test[0]", "test[0]"));
        assert!(match_pattern("test()", "test()"));

        // Matching is case-sensitive.
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
        let rule = search_rule(Some("pyperclip.paste"), None);

        assert!(rule_matches_pattern_unified(&rule, "pyperclip.paste"));
        assert!(!rule_matches_pattern_unified(&rule, "pyperclip.copy"));
        assert!(!rule_matches_pattern_unified(&rule, "clipboard.get"));
    }

    #[test]
    fn test_multiple_patterns_rule() {
        let rule = search_rule(
            None,
            Some(vec![
                "pyperclip.paste",
                "pyperclip.copy",
                "*.to_clipboard",
                "win32clipboard",
            ]),
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
        let rule = search_rule(None, Some(vec!["*.tk*", "*.exe*", "keyboard.*"]));

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
    fn test_rule_pattern_validation() {
        // Valid: literal patterns always validate.
        let valid_single = search_rule(Some("test"), None);
        assert!(validate_unified_rule_patterns(&valid_single).is_ok());

        let valid_multiple = search_rule(None, Some(vec!["test1", "test2"]));
        assert!(validate_unified_rule_patterns(&valid_multiple).is_ok());

        // Valid regex.
        let valid_regex = search_rule(Some("regex:^[a-z]+$"), None);
        assert!(validate_unified_rule_patterns(&valid_regex).is_ok());

        // Invalid regex in `pattern` must error.
        let invalid_regex = search_rule(Some("regex:[unterminated"), None);
        assert!(validate_unified_rule_patterns(&invalid_regex).is_err());

        // Invalid regex inside `patterns` must error.
        let invalid_regex_multi = search_rule(None, Some(vec!["ok", "regex:(unbalanced"]));
        assert!(validate_unified_rule_patterns(&invalid_regex_multi).is_err());
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
        assert!(match_any_pattern(
            &sql_injection_patterns,
            "conn.execute_query"
        ));

        // Strings that contain none of the patterns as a substring don't match.
        assert!(!match_any_pattern(&sql_injection_patterns, "fetchone"));
        assert!(!match_any_pattern(&sql_injection_patterns, "commit"));

        let command_injection_patterns = vec![
            "os.system".to_string(),
            "subprocess.*".to_string(),
            "*.Popen".to_string(),
            "shell=True".to_string(),
        ];

        assert!(match_any_pattern(&command_injection_patterns, "os.system"));
        assert!(match_any_pattern(
            &command_injection_patterns,
            "subprocess.call"
        ));
        assert!(match_any_pattern(
            &command_injection_patterns,
            "subprocess.Popen"
        ));
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
        let rule = search_rule(
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
        for _ in 0..1000 {
            for test_str in &test_strings {
                rule_matches_pattern_unified(&rule, test_str);
            }
        }
        let duration = start.elapsed();
        println!(
            "Multiple pattern rule matching 10,000 times took: {:?}",
            duration
        );
        assert!(
            duration.as_secs() < 30,
            "Multiple pattern matching too slow: {:?}",
            duration
        );
    }
}
