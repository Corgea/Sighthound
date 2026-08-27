use sighthound::models::UnifiedRule;
use sighthound::rules::Rules;
use std::fs;
use tempfile::TempDir;

// Build a minimal search-mode UnifiedRule (UnifiedRule does not derive Default).
fn make_rule(pattern: &str, finding_type: &str) -> UnifiedRule {
    UnifiedRule {
        id: None,
        name: None,
        description: None,
        category: None,
        mode: "search".to_string(),
        pattern: Some(pattern.to_string()),
        patterns: None,
        unless: None,
        sources: None,
        sinks: None,
        propagators: None,
        sanitizers: None,
        finding_type: Some(finding_type.to_string()),
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
mod directory_loading_tests {
    use super::*;

    #[test]
    fn test_load_from_single_file() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let file_path = temp_dir.path().join("test_rules.ron");

        let ron_content = r#"(
            rules: [
                (
                    pattern: Some("test_pattern"),
                    finding_type: Some("test_type"),
                    conditions: None,
                    file_types: Some((
                        extensions: Some([".py"]),
                        include_patterns: None,
                        exclude_patterns: None,
                    )),
                ),
            ]
        )"#;

        fs::write(&file_path, ron_content).expect("Failed to write test file");

        let rules = Rules::load_from_path(file_path.to_str().unwrap())
            .expect("Failed to load rules from single file");

        assert_eq!(rules.count_rules(), 1);
        assert_eq!(rules.rules[0].pattern, Some("test_pattern".to_string()));
        assert_eq!(rules.rules[0].finding_type, Some("test_type".to_string()));
    }

    #[test]
    fn test_load_from_directory() {
        // note: rules from every .ron file in the directory are merged into one unified
        // `rules` list (categories were removed), so we assert on the merged total and
        // verify each expected rule is present.
        let temp_dir = TempDir::new().expect("Failed to create temp directory");

        // Create first rules file
        let file1_path = temp_dir.path().join("rules1.ron");
        let ron_content1 = r#"(
            rules: [
                (
                    pattern: Some("pattern1"),
                    finding_type: Some("type1"),
                    conditions: None,
                    file_types: None,
                ),
                (
                    pattern: Some("sql_inject"),
                    finding_type: Some("sql_injection"),
                    conditions: None,
                    file_types: None,
                ),
            ]
        )"#;
        fs::write(&file1_path, ron_content1).expect("Failed to write test file 1");

        // Create second rules file
        let file2_path = temp_dir.path().join("rules2.ron");
        let ron_content2 = r#"(
            rules: [
                (
                    patterns: Some(["pattern2", "pattern3"]),
                    finding_type: Some("type2"),
                    conditions: None,
                    file_types: None,
                ),
                (
                    pattern: Some("weak_crypto"),
                    finding_type: Some("crypto_issue"),
                    conditions: None,
                    file_types: None,
                ),
            ]
        )"#;
        fs::write(&file2_path, ron_content2).expect("Failed to write test file 2");

        // Create a non-rules file (should be ignored)
        let text_file_path = temp_dir.path().join("readme.txt");
        fs::write(&text_file_path, "This should be ignored").expect("Failed to write text file");

        let rules = Rules::load_from_path(temp_dir.path().to_str().unwrap())
            .expect("Failed to load rules from directory");

        // All four rules across both files should be merged
        assert_eq!(rules.count_rules(), 4);

        let has_pattern = |p: &str| rules.rules.iter().any(|r| r.pattern.as_deref() == Some(p));
        assert!(has_pattern("pattern1"), "merged rules should contain pattern1");
        assert!(has_pattern("sql_inject"), "merged rules should contain sql_inject");
        assert!(has_pattern("weak_crypto"), "merged rules should contain weak_crypto");

        assert!(
            rules.rules.iter().any(|r| r.patterns.as_deref()
                == Some(&["pattern2".to_string(), "pattern3".to_string()][..])),
            "merged rules should contain the pattern2/pattern3 rule"
        );
    }

    #[test]
    fn test_load_from_empty_directory() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");

        let result = Rules::load_from_path(temp_dir.path().to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No valid .ron rules files found"));
    }

    #[test]
    fn test_load_from_nonexistent_path() {
        let result = Rules::load_from_path("/nonexistent/path");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("neither a file nor a directory"));
    }

    #[test]
    fn test_load_unsupported_file_format() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let file_path = temp_dir.path().join("test_rules.json");

        let json_content = r#"{
            "rules": [
                {
                    "pattern": "test_pattern",
                    "finding_type": "test_type"
                }
            ]
        }"#;

        fs::write(&file_path, json_content).expect("Failed to write JSON file");

        let result = Rules::load_from_path(file_path.to_str().unwrap());
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unsupported file format. Only .ron files are supported")
        );
    }

    #[test]
    fn test_merge_rules() {
        let rules1 = Rules { rules: vec![make_rule("a", "type_a")] };

        let rules2 = Rules { rules: vec![make_rule("b", "type_b"), make_rule("c", "type_c")] };

        let merged = Rules::merge_rules(vec![rules1, rules2]).expect("Failed to merge rules");

        assert_eq!(merged.count_rules(), 3);
        let has_pattern = |p: &str| merged.rules.iter().any(|r| r.pattern.as_deref() == Some(p));
        assert!(has_pattern("a"));
        assert!(has_pattern("b"));
        assert!(has_pattern("c"));
    }
}
