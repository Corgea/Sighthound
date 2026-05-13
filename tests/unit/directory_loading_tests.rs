use sighthound::rules::Rules;
use std::fs;
use tempfile::TempDir;

// Exercises `Rules::load_from_path` (file vs directory dispatch),
// `Rules::load_from_directory` (concat .ron files), and `Rules::merge_rules`.
// Under the unified schema all rules merge into the flat `rules` list — there
// are no per-category buckets, so the test asserts on `count_rules()` and on
// `get_rules_by_category(...)` filters.

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
                    category: Some("malware"),
                    file_types: Some((
                        extensions: Some([".py"]),
                    )),
                ),
            ],
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
        let temp_dir = TempDir::new().expect("Failed to create temp directory");

        // First file: one malware rule and one injection rule
        let file1_path = temp_dir.path().join("rules1.ron");
        let ron_content1 = r#"(
            rules: [
                (
                    pattern: Some("pattern1"),
                    finding_type: Some("type1"),
                    category: Some("malware"),
                ),
                (
                    pattern: Some("sql_inject"),
                    finding_type: Some("sql_injection"),
                    category: Some("injection"),
                ),
            ],
        )"#;
        fs::write(&file1_path, ron_content1).expect("Failed to write test file 1");

        // Second file: another malware rule and a crypto rule
        let file2_path = temp_dir.path().join("rules2.ron");
        let ron_content2 = r#"(
            rules: [
                (
                    patterns: Some(["pattern2", "pattern3"]),
                    finding_type: Some("type2"),
                    category: Some("malware"),
                ),
                (
                    pattern: Some("weak_crypto"),
                    finding_type: Some("crypto_issue"),
                    category: Some("crypto"),
                ),
            ],
        )"#;
        fs::write(&file2_path, ron_content2).expect("Failed to write test file 2");

        // A non-.ron file should be ignored by load_from_directory
        let text_file_path = temp_dir.path().join("readme.txt");
        fs::write(&text_file_path, "This should be ignored")
            .expect("Failed to write text file");

        let rules = Rules::load_from_path(temp_dir.path().to_str().unwrap())
            .expect("Failed to load rules from directory");

        assert_eq!(rules.count_rules(), 4, "should merge all 4 rules from both files");

        let malware = rules.get_rules_by_category("malware");
        assert_eq!(malware.len(), 2);

        let injection = rules.get_rules_by_category("injection");
        assert_eq!(injection.len(), 1);
        assert_eq!(injection[0].pattern, Some("sql_inject".to_string()));

        let crypto = rules.get_rules_by_category("crypto");
        assert_eq!(crypto.len(), 1);
        assert_eq!(crypto[0].pattern, Some("weak_crypto".to_string()));
    }

    #[test]
    fn test_load_from_empty_directory() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");

        let result = Rules::load_from_path(temp_dir.path().to_str().unwrap());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No valid .ron rules files found"));
    }

    #[test]
    fn test_load_from_nonexistent_path() {
        let result = Rules::load_from_path("/nonexistent/path");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("neither a file nor a directory"));
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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unsupported file format. Only .ron files are supported"));
    }

    #[test]
    fn test_merge_rules() {
        // Build two Rules instances directly via RON deserialization so we don't
        // depend on private constructors for `UnifiedRule`.
        let rules1: Rules = ron::from_str(
            r#"(
                rules: [
                    (
                        pattern: Some("a"),
                        finding_type: Some("t1"),
                        category: Some("malware"),
                    ),
                    (
                        pattern: Some("b"),
                        finding_type: Some("t2"),
                        category: Some("injection"),
                    ),
                ],
            )"#,
        )
        .expect("Failed to parse rules1");

        let rules2: Rules = ron::from_str(
            r#"(
                rules: [
                    (
                        pattern: Some("c"),
                        finding_type: Some("t3"),
                        category: Some("malware"),
                    ),
                    (
                        pattern: Some("d"),
                        finding_type: Some("t4"),
                        category: Some("crypto"),
                    ),
                ],
            )"#,
        )
        .expect("Failed to parse rules2");

        let merged = Rules::merge_rules(vec![rules1, rules2]).expect("Failed to merge rules");

        assert_eq!(merged.count_rules(), 4);
        assert_eq!(merged.get_rules_by_category("malware").len(), 2);
        assert_eq!(merged.get_rules_by_category("injection").len(), 1);
        assert_eq!(merged.get_rules_by_category("crypto").len(), 1);
        assert_eq!(merged.get_rules_by_category("path_traversal").len(), 0);
    }
}
