use sighthound::rules::ExclusionPatterns;

#[cfg(test)]
mod exclusion_patterns_tests {
    use super::*;

    fn patterns() -> ExclusionPatterns {
        ExclusionPatterns {
            frontend_exclusions: Some(vec!["*.stories.tsx".to_string()]),
            backend_exclusions: Some(vec!["*_test.go".to_string()]),
            common_exclusions: Some(vec!["*.min.js".to_string()]),
        }
    }

    #[test]
    fn frontend_includes_common_and_frontend_only() {
        let result = patterns().get_patterns("frontend");
        assert_eq!(result, vec!["*.min.js".to_string(), "*.stories.tsx".to_string()]);
    }

    #[test]
    fn backend_includes_common_and_backend_only() {
        let result = patterns().get_patterns("backend");
        assert_eq!(result, vec!["*.min.js".to_string(), "*_test.go".to_string()]);
    }

    #[test]
    fn common_returns_only_common_exclusions() {
        let result = patterns().get_patterns("common");
        assert_eq!(result, vec!["*.min.js".to_string()]);
    }

    #[test]
    fn unknown_pattern_type_returns_empty() {
        let result = patterns().get_patterns("something-else");
        assert!(result.is_empty());
    }

    #[test]
    fn missing_common_exclusions_does_not_panic() {
        let p = ExclusionPatterns {
            frontend_exclusions: Some(vec!["*.snap".to_string()]),
            backend_exclusions: None,
            common_exclusions: None,
        };
        assert_eq!(p.get_patterns("frontend"), vec!["*.snap".to_string()]);
        assert_eq!(p.get_patterns("backend"), Vec::<String>::new());
        assert_eq!(p.get_patterns("common"), Vec::<String>::new());
    }

    #[test]
    fn apply_centralized_exclusions_does_not_hardcode_js_extensions() {
        let mut rules = sighthound::rules::Rules {
            rules: vec![sighthound::UnifiedRule {
                id: Some("test-rule".to_string()),
                name: Some("Generic Rule".to_string()),
                description: None,
                category: None,
                mode: "search".to_string(),
                pattern: Some("eval(".to_string()),
                patterns: None,
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
            }],
        };

        rules.apply_centralized_exclusions(&patterns(), "backend");
        let file_types = rules.rules[0].file_types.as_ref();
        assert!(file_types.unwrap().extensions.is_none());
        assert_eq!(
            file_types.unwrap().exclude_patterns.as_ref().unwrap(),
            &vec!["*.min.js".to_string(), "*_test.go".to_string()]
        );

        // Exercise applicability: non-JS files match, but excluded files are skipped
        assert!(sighthound::scanner::utils::rule_applies_to_file(file_types, "src/main.py"));
        assert!(sighthound::scanner::utils::rule_applies_to_file(file_types, "src/service.go"));
        assert!(!sighthound::scanner::utils::rule_applies_to_file(file_types, "src/app.min.js"));
        assert!(!sighthound::scanner::utils::rule_applies_to_file(
            file_types,
            "src/handler_test.go"
        ));
    }
}
