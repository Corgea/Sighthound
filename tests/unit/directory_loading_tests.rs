use sighthound::rules::Rules;
use std::fs;
use tempfile::TempDir;

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
                    mode: "search",
                    pattern: Some("test_pattern"),
                    finding_type: Some("test_type"),
                    file_types: Some((
                        extensions: Some([".py"]),
                    )),
                ),
            ],
        )"#;

        fs::write(&file_path, ron_content).expect("Failed to write test file");

        let rules = Rules::load_from_path(file_path.to_str().unwrap())
            .expect("Failed to load rules from single file");

        assert_eq!(rules.rules.len(), 1);
        assert_eq!(rules.rules[0].pattern, Some("test_pattern".to_string()));
        assert_eq!(rules.rules[0].finding_type, Some("test_type".to_string()));
    }

    #[test]
    fn test_load_from_directory() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");

        let file1_path = temp_dir.path().join("rules1.ron");
        let ron_content1 = r#"(
            rules: [
                (
                    mode: "search",
                    pattern: Some("pattern1"),
                    finding_type: Some("type1"),
                ),
                (
                    mode: "search",
                    pattern: Some("sql_inject"),
                    finding_type: Some("sql_injection"),
                ),
            ],
        )"#;
        fs::write(&file1_path, ron_content1).expect("Failed to write test file 1");

        let file2_path = temp_dir.path().join("rules2.ron");
        let ron_content2 = r#"(
            rules: [
                (
                    mode: "search",
                    patterns: Some(["pattern2", "pattern3"]),
                    finding_type: Some("type2"),
                ),
                (
                    mode: "search",
                    pattern: Some("weak_crypto"),
                    finding_type: Some("crypto_issue"),
                ),
            ],
        )"#;
        fs::write(&file2_path, ron_content2).expect("Failed to write test file 2");

        // A non-rules file should be ignored.
        let text_file_path = temp_dir.path().join("readme.txt");
        fs::write(&text_file_path, "This should be ignored").expect("Failed to write text file");

        let rules = Rules::load_from_path(temp_dir.path().to_str().unwrap())
            .expect("Failed to load rules from directory");

        // All rules from both files are merged into a single flat list.
        assert_eq!(rules.rules.len(), 4);

        let patterns: Vec<&str> = rules
            .rules
            .iter()
            .filter_map(|r| r.pattern.as_deref())
            .collect();
        assert!(patterns.contains(&"sql_inject"));
        assert!(patterns.contains(&"weak_crypto"));

        let finding_types: Vec<&str> = rules
            .rules
            .iter()
            .filter_map(|r| r.finding_type.as_deref())
            .collect();
        assert!(finding_types.contains(&"sql_injection"));
        assert!(finding_types.contains(&"crypto_issue"));
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

        let json_content = r#"{ "rules": [] }"#;
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
        let ron1 = r#"(rules: [(mode: "search", pattern: Some("a"))])"#;
        let ron2 = r#"(rules: [(mode: "search", pattern: Some("b")), (mode: "search", pattern: Some("c"))])"#;

        let rules1: Rules = ron::from_str(ron1).expect("parse rules1");
        let rules2: Rules = ron::from_str(ron2).expect("parse rules2");

        let merged = Rules::merge_rules(vec![rules1, rules2]).expect("Failed to merge rules");

        assert_eq!(merged.rules.len(), 3);
    }
}
