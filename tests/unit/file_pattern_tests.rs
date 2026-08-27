use sighthound::VulnerabilityScanner;
use sighthound::rules::Rules;
use std::fs;
use std::io::Write;
use tempfile::{NamedTempFile, TempDir};

#[cfg(test)]
mod file_pattern_tests {
    use super::*;

    // note: the categorized `malware_detection: Some([...])` rule layout was replaced by
    // a single unified `rules: [...]` list. The per-rule `file_types` include/exclude
    // path filtering is unchanged, so the behavioral assertions below are preserved.
    fn create_test_rules_with_patterns() -> NamedTempFile {
        let mut temp_file = NamedTempFile::with_suffix(".ron").expect("Failed to create temp file");

        let ron_content = r#"(
            rules: [
                // Rule that only applies to files with "test" in the path
                (
                    pattern: Some("test_function"),
                    finding_type: Some("test_only"),
                    conditions: None,
                    file_types: Some((
                        extensions: Some([".py"]),
                        include_patterns: Some(["*test*"]),
                        exclude_patterns: None,
                    )),
                ),
                // Rule that excludes files with "safe_" prefix in the path
                (
                    pattern: Some("dangerous_function"),
                    finding_type: Some("danger_not_safe"),
                    conditions: None,
                    file_types: Some((
                        extensions: Some([".py"]),
                        include_patterns: None,
                        exclude_patterns: Some(["*safe_*"]),
                    )),
                ),
                // Rule with both include and exclude patterns
                (
                    pattern: Some("config_function"),
                    finding_type: Some("config_issue"),
                    conditions: None,
                    file_types: Some((
                        extensions: Some([".py"]),
                        include_patterns: Some(["*config*", "*settings*"]),
                        exclude_patterns: Some(["*test*", "*backup*"]),
                    )),
                ),
                // Rule that applies to all .py files (no patterns)
                (
                    pattern: Some("universal_function"),
                    finding_type: Some("universal"),
                    conditions: None,
                    file_types: Some((
                        extensions: Some([".py"]),
                        include_patterns: None,
                        exclude_patterns: None,
                    )),
                ),
            ]
        )"#;

        write!(temp_file, "{}", ron_content).expect("Failed to write to temp file");
        temp_file
    }

    #[test]
    fn test_include_patterns_functionality() {
        let rules_file = create_test_rules_with_patterns();
        let temp_dir = TempDir::new().expect("Failed to create temp directory");

        // Create test files
        let test_file = temp_dir.path().join("my_test_file.py");
        fs::write(&test_file, "test_function()\nuniversal_function()")
            .expect("Failed to write test file");

        let normal_file = temp_dir.path().join("normal_file.py");
        fs::write(&normal_file, "test_function()\nuniversal_function()")
            .expect("Failed to write normal file");

        // Load rules and create scanner
        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");
        let scanner = VulnerabilityScanner::new("python", rules).expect("Failed to create scanner");

        // Scan test file (should match include pattern "*test*")
        let test_findings = scanner
            .find_vulnerabilities_single_threaded(temp_dir.path().to_str().unwrap(), "python")
            .expect("Failed to scan test file");

        // Verify findings
        let test_only_findings: Vec<_> =
            test_findings.iter().filter(|f| f.finding_type == "test_only").collect();
        let universal_findings: Vec<_> =
            test_findings.iter().filter(|f| f.finding_type == "universal").collect();

        // The test file should match the include pattern "*test*" for test_only rule
        assert!(
            !test_only_findings.is_empty(),
            "test_function should be found in test file with include pattern"
        );
        // The universal rule should also apply
        assert!(!universal_findings.is_empty(), "universal_function should be found in test file");
    }

    #[test]
    fn test_exclude_patterns_functionality() {
        let rules_file = create_test_rules_with_patterns();
        let temp_dir = TempDir::new().expect("Failed to create temp directory");

        // Create files
        let safe_file = temp_dir.path().join("safe_file.py");
        fs::write(&safe_file, "dangerous_function()\nuniversal_function()")
            .expect("Failed to write safe file");

        let unsafe_file = temp_dir.path().join("dangerous_file.py");
        fs::write(&unsafe_file, "dangerous_function()\nuniversal_function()")
            .expect("Failed to write unsafe file");

        // Load rules and create scanner
        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");
        let scanner = VulnerabilityScanner::new("python", rules).expect("Failed to create scanner");

        // Scan both files
        let findings = scanner
            .find_vulnerabilities_single_threaded(temp_dir.path().to_str().unwrap(), "python")
            .expect("Failed to scan files");

        // Check findings by file
        let safe_findings: Vec<_> =
            findings.iter().filter(|f| f.file.contains("safe_file")).collect();
        let dangerous_findings: Vec<_> =
            findings.iter().filter(|f| f.file.contains("dangerous_file")).collect();

        // Safe file should NOT have dangerous findings (excluded by "*safe_*" pattern)
        let safe_dangerous: Vec<_> =
            safe_findings.iter().filter(|f| f.finding_type == "danger_not_safe").collect();
        assert!(safe_dangerous.is_empty(), "dangerous_function should be excluded from safe file");

        // Dangerous file SHOULD have dangerous findings (not excluded)
        let dangerous_dangerous: Vec<_> =
            dangerous_findings.iter().filter(|f| f.finding_type == "danger_not_safe").collect();
        assert!(
            !dangerous_dangerous.is_empty(),
            "dangerous_function should be found in dangerous file"
        );

        // Both files should have universal findings
        let safe_universal: Vec<_> =
            safe_findings.iter().filter(|f| f.finding_type == "universal").collect();
        let dangerous_universal: Vec<_> =
            dangerous_findings.iter().filter(|f| f.finding_type == "universal").collect();
        assert!(!safe_universal.is_empty(), "universal rule should apply to safe file");
        assert!(!dangerous_universal.is_empty(), "universal rule should apply to dangerous file");
    }

    #[test]
    fn test_combined_include_exclude_patterns() {
        let rules_file = create_test_rules_with_patterns();
        let temp_dir = TempDir::new().expect("Failed to create temp directory");

        // Create test files
        let config_file = temp_dir.path().join("app_config.py");
        fs::write(&config_file, "config_function()").expect("Failed to write config file");

        let test_config_file = temp_dir.path().join("test_config.py");
        fs::write(&test_config_file, "config_function()")
            .expect("Failed to write test config file");

        let settings_file = temp_dir.path().join("settings.py");
        fs::write(&settings_file, "config_function()").expect("Failed to write settings file");

        let backup_settings_file = temp_dir.path().join("backup_settings.py");
        fs::write(&backup_settings_file, "config_function()")
            .expect("Failed to write backup settings file");

        // Load rules and create scanner
        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");
        let scanner = VulnerabilityScanner::new("python", rules).expect("Failed to create scanner");

        // Scan all files
        let findings = scanner
            .find_vulnerabilities_single_threaded(temp_dir.path().to_str().unwrap(), "python")
            .expect("Failed to scan files");

        let config_findings: Vec<_> =
            findings.iter().filter(|f| f.finding_type == "config_issue").collect();

        // Should match: config (includes "*config*"), settings (includes "*settings*")
        // Should NOT match: test_config (excluded by "*test*"), backup_settings (excluded by "*backup*")
        assert_eq!(
            config_findings.len(),
            2,
            "Should find config issues in 2 files (config and settings)"
        );

        let config_files: Vec<&str> = config_findings.iter().map(|f| f.file.as_str()).collect();

        assert!(
            config_files.iter().any(|f| f.contains("app_config.py")),
            "Should include app_config.py"
        );
        assert!(
            config_files.iter().any(|f| f.contains("settings.py")),
            "Should include settings.py"
        );
        assert!(
            !config_files.iter().any(|f| f.contains("test_config.py")),
            "Should exclude test_config.py"
        );
        assert!(
            !config_files.iter().any(|f| f.contains("backup_settings.py")),
            "Should exclude backup_settings.py"
        );
    }

    #[test]
    fn test_glob_pattern_matching() {
        let rules_file = create_test_rules_with_patterns();

        // Load rules to verify the patterns deserialized correctly into the unified list
        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");

        // The unified rule list preserves array order from the RON file
        assert_eq!(rules.rules.len(), 4);

        // Verify pattern configurations
        let test_rule = &rules.rules[0];
        let file_types = test_rule.file_types.as_ref().unwrap();
        assert_eq!(file_types.include_patterns, Some(vec!["*test*".to_string()]));
        assert_eq!(file_types.exclude_patterns, None);

        let danger_rule = &rules.rules[1];
        let file_types = danger_rule.file_types.as_ref().unwrap();
        assert_eq!(file_types.include_patterns, None);
        assert_eq!(file_types.exclude_patterns, Some(vec!["*safe_*".to_string()]));

        let config_rule = &rules.rules[2];
        let file_types = config_rule.file_types.as_ref().unwrap();
        assert_eq!(
            file_types.include_patterns,
            Some(vec!["*config*".to_string(), "*settings*".to_string()])
        );
        assert_eq!(
            file_types.exclude_patterns,
            Some(vec!["*test*".to_string(), "*backup*".to_string()])
        );
    }
}
