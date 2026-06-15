use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::common::CommonUtils;
use crate::language::LanguageSupport;

// Re-export for backward compatibility
pub use crate::models::{Condition, FileTypes, UnifiedRule};

// Embedded rules - rule files included at compile time, grouped per language.
// Each entry must be a valid `Rules` RON document; exclusion-pattern files use a
// different schema and are intentionally excluded.
const EMBEDDED_PYTHON: &[&str] = &[
    include_str!("../rules/python/general_security.ron"),
    include_str!("../rules/python/command_injection.ron"),
    include_str!("../rules/python/cryptography.ron"),
    include_str!("../rules/python/file_system.ron"),
    include_str!("../rules/python/sql_injection.ron"),
    include_str!("../rules/python/working.ron"),
];

// Always-on JavaScript/TypeScript rules (frontend + Node backend).
const EMBEDDED_JAVASCRIPT: &[&str] = &[
    include_str!("../rules/javascript/frontend_security.ron"),
    include_str!("../rules/javascript/frontend_taint_security.ron"),
    include_str!("../rules/javascript/backend_node_security.ron"),
];

// Additional backend JS rules, loaded only when code_type is not "frontend".
const EMBEDDED_JAVASCRIPT_BACKEND: &[&str] = &[include_str!(
    "../rules/backend_javascript/backend_security.ron"
)];

const EMBEDDED_JAVA: &[&str] = &[
    include_str!("../rules/java/sql_injection.ron"),
    include_str!("../rules/java/command_injection.ron"),
    include_str!("../rules/java/path_traversal.ron"),
    include_str!("../rules/java/xss.ron"),
    include_str!("../rules/java/xxe.ron"),
    include_str!("../rules/java/deserialization.ron"),
    include_str!("../rules/java/ssrf.ron"),
    include_str!("../rules/java/weak_crypto.ron"),
    include_str!("../rules/java/open_redirect.ron"),
    include_str!("../rules/java/access_control.ron"),
    include_str!("../rules/java/broken_auth.ron"),
    include_str!("../rules/java/info_disclosure.ron"),
];

const EMBEDDED_CSHARP: &[&str] = &[
    include_str!("../rules/csharp/sql_injection.ron"),
    include_str!("../rules/csharp/injection.ron"),
    include_str!("../rules/csharp/path_traversal.ron"),
    include_str!("../rules/csharp/ssrf.ron"),
    include_str!("../rules/csharp/crypto.ron"),
    include_str!("../rules/csharp/header_injection.ron"),
    include_str!("../rules/csharp/authn_authz.ron"),
    include_str!("../rules/csharp/mass_assignment.ron"),
    include_str!("../rules/csharp/misc.ron"),
    include_str!("../rules/csharp/open_redirect.ron"),
    include_str!("../rules/csharp/info_disclosure.ron"),
];

const EMBEDDED_GO: &[&str] = &[
    include_str!("../rules/go/sql_injection.ron"),
    include_str!("../rules/go/command_injection.ron"),
    include_str!("../rules/go/code_injection.ron"),
    include_str!("../rules/go/path_traversal.ron"),
    include_str!("../rules/go/xss.ron"),
    include_str!("../rules/go/ssrf.ron"),
    include_str!("../rules/go/deserialization.ron"),
    include_str!("../rules/go/weak_crypto.ron"),
    include_str!("../rules/go/insecure_tls.ron"),
];

const EMBEDDED_RUBY: &[&str] = &[
    include_str!("../rules/ruby/sql_injection.ron"),
    include_str!("../rules/ruby/command_injection.ron"),
    include_str!("../rules/ruby/code_injection.ron"),
    include_str!("../rules/ruby/path_traversal.ron"),
    include_str!("../rules/ruby/xss.ron"),
    include_str!("../rules/ruby/ssrf.ron"),
    include_str!("../rules/ruby/deserialization.ron"),
    include_str!("../rules/ruby/mass_assignment.ron"),
    include_str!("../rules/ruby/open_redirect.ron"),
    include_str!("../rules/ruby/weak_crypto.ron"),
    include_str!("../rules/ruby/redos.ron"),
];

const EMBEDDED_HTML: &[&str] = &[
    include_str!("../rules/html/xss.ron"),
    include_str!("../rules/html/thymeleaf.ron"),
];

const EMBEDDED_PHP: &[&str] = &[
    include_str!("../rules/php/sql_injection.ron"),
    include_str!("../rules/php/command_injection.ron"),
    include_str!("../rules/php/code_injection.ron"),
    include_str!("../rules/php/ssrf.ron"),
    include_str!("../rules/php/deserialization.ron"),
    include_str!("../rules/php/file_upload.ron"),
    include_str!("../rules/php/taint.ron"),
];

// Structure for centralized exclusion patterns
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ExclusionPatterns {
    pub frontend_exclusions: Option<Vec<String>>,
    pub backend_exclusions: Option<Vec<String>>,
    pub common_exclusions: Option<Vec<String>>,
}

impl ExclusionPatterns {
    pub fn load_from_file(file_path: &str) -> Result<Self> {
        let content = fs::read_to_string(file_path).context(format!(
            "Failed to read exclusion patterns file: {}",
            file_path
        ))?;

        ron::from_str(&content).context("Failed to parse exclusion patterns RON")
    }

    pub fn get_patterns(&self, pattern_type: &str) -> Vec<String> {
        match pattern_type {
            "frontend" => {
                let mut patterns = Vec::new();
                if let Some(common) = &self.common_exclusions {
                    patterns.extend(common.clone());
                }
                if let Some(frontend) = &self.frontend_exclusions {
                    patterns.extend(frontend.clone());
                }
                patterns
            }
            "backend" => {
                let mut patterns = Vec::new();
                if let Some(common) = &self.common_exclusions {
                    patterns.extend(common.clone());
                }
                if let Some(backend) = &self.backend_exclusions {
                    patterns.extend(backend.clone());
                }
                patterns
            }
            "common" => self.common_exclusions.clone().unwrap_or_default(),
            _ => Vec::new(),
        }
    }
}

// Simple injection pattern checking for basic patterns
pub fn check_for_injection_pattern(text: &str, _language_support: &dyn LanguageSupport) -> bool {
    // Basic injection indicators that are language-agnostic
    let basic_patterns = [
        ";",
        "&&",
        "||",
        "`",
        "$(", // Command separators/chaining
        "eval(",
        "exec(",
        "system(", // Dangerous functions
        "{{",
        "{%", // Template injection
        "javascript:",
        "data:", // URL schemes
    ];

    basic_patterns.iter().any(|&pattern| text.contains(pattern))
}

// Simplified Rules structure - only unified rules
#[derive(Debug, Deserialize, Serialize, Default)]
pub struct Rules {
    #[serde(default)]
    pub rules: Vec<UnifiedRule>,
}

impl Rules {
    /// Parse a set of embedded RON documents into `Rules` instances.
    fn parse_embedded(contents: &[&str], language: &str) -> Result<Vec<Self>> {
        let mut parsed = Vec::with_capacity(contents.len());
        for content in contents {
            let rules: Rules = ron::from_str(content)
                .context(format!("Failed to parse embedded {} rules", language))?;
            parsed.push(rules);
        }
        Ok(parsed)
    }

    /// Load embedded rules for a specific language
    pub fn load_embedded_rules(language: &str, code_type: Option<&str>) -> Result<Self> {
        let mut all_rules = Vec::new();

        match language {
            "python" => all_rules.extend(Self::parse_embedded(EMBEDDED_PYTHON, "Python")?),
            "javascript" | "tsx" | "typescript" => {
                all_rules.extend(Self::parse_embedded(EMBEDDED_JAVASCRIPT, "JavaScript")?);
                // Legacy backend JS rules load only when explicitly non-frontend,
                // matching the file-rules auto-detect path the benchmark measured.
                if code_type.is_some_and(|ct| ct != "frontend") {
                    all_rules.extend(Self::parse_embedded(
                        EMBEDDED_JAVASCRIPT_BACKEND,
                        "JavaScript backend",
                    )?);
                }
            }
            "java" => all_rules.extend(Self::parse_embedded(EMBEDDED_JAVA, "Java")?),
            "csharp" => all_rules.extend(Self::parse_embedded(EMBEDDED_CSHARP, "C#")?),
            "go" => all_rules.extend(Self::parse_embedded(EMBEDDED_GO, "Go")?),
            "ruby" => all_rules.extend(Self::parse_embedded(EMBEDDED_RUBY, "Ruby")?),
            "html" | "django" => all_rules.extend(Self::parse_embedded(EMBEDDED_HTML, "HTML")?),
            "php" => all_rules.extend(Self::parse_embedded(EMBEDDED_PHP, "PHP")?),
            _ => {
                return Err(anyhow::anyhow!(
                    "No embedded rules available for language: {}",
                    language
                ));
            }
        }

        if all_rules.is_empty() {
            return Ok(Self::default());
        }

        Self::merge_rules(all_rules)
    }

    /// Load embedded rules for all detected languages
    pub fn load_all_embedded_rules(languages: &[String], code_type: Option<&str>) -> Result<Self> {
        let mut all_rules = Vec::new();

        for language in languages {
            match Self::load_embedded_rules(language, code_type) {
                Ok(rules) => all_rules.push(rules),
                Err(e) => {
                    // Log warning but continue with other languages
                    eprintln!(
                        "Warning: Failed to load embedded rules for {}: {}",
                        language, e
                    );
                }
            }
        }

        if all_rules.is_empty() {
            return Err(anyhow::anyhow!(
                "No embedded rules found for any of the detected languages"
            ));
        }

        Self::merge_rules(all_rules)
    }

    pub fn load_from_file(rules_file: &str) -> Result<Self> {
        let content = fs::read_to_string(rules_file)
            .context(format!("Failed to read rules file: {}", rules_file))?;

        let path = Path::new(rules_file);
        let extension = path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_lowercase();

        match extension.as_str() {
            "ron" => ron::from_str(&content).context("Failed to parse rules RON"),
            _ => Err(anyhow::anyhow!(
                "Unsupported file format. Only .ron files are supported for rules."
            )),
        }
    }

    /// Load rules from a file or directory
    /// If path is a file, loads that single RON file
    /// If path is a directory, loads all .ron files and merges them
    pub fn load_from_path(rules_path: &str) -> Result<Self> {
        let path = Path::new(rules_path);

        if path.is_file() {
            Self::load_from_file(rules_path)
        } else if path.is_dir() {
            Self::load_from_directory(rules_path)
        } else {
            Err(anyhow::anyhow!(
                "Rules path '{}' is neither a file nor a directory",
                rules_path
            ))
        }
    }

    /// Load all .ron files from a directory and merge them
    pub fn load_from_directory(rules_dir: &str) -> Result<Self> {
        let dir_path = Path::new(rules_dir);

        if !dir_path.is_dir() {
            return Err(anyhow::anyhow!("Path '{}' is not a directory", rules_dir));
        }

        let entries =
            fs::read_dir(dir_path).context(format!("Failed to read directory: {}", rules_dir))?;

        let mut all_rules = Vec::new();
        let mut loaded_files = Vec::new();

        for entry in entries {
            let entry = entry.context("Failed to read directory entry")?;
            let file_path = entry.path();

            // Only process .ron files
            if let Some(extension) = file_path.extension() {
                let ext_str = extension.to_string_lossy().to_lowercase();
                if ext_str == "ron" {
                    let file_path_str = file_path.to_string_lossy();

                    match Self::load_from_file(&file_path_str) {
                        Ok(rules) => {
                            all_rules.push(rules);
                            loaded_files.push(file_path_str.to_string());
                        }
                        Err(e) => {
                            eprintln!(
                                "Warning: Failed to load rules from {}: {}",
                                file_path_str, e
                            );
                        }
                    }
                }
            }
        }

        if all_rules.is_empty() {
            return Err(anyhow::anyhow!(
                "No valid .ron rules files found in directory: {}",
                rules_dir
            ));
        }

        // Merge all rules into a single Rules instance
        Self::merge_rules(all_rules)
    }

    /// Merge multiple Rules instances into one
    pub fn merge_rules(rules_list: Vec<Self>) -> Result<Self> {
        if rules_list.is_empty() {
            return Ok(Self::default());
        }

        let mut merged = Self::default();

        for rules in rules_list {
            merged.rules.extend(rules.rules);
        }

        Ok(merged)
    }

    /// Get all search mode rules
    pub fn get_search_rules(&self) -> Vec<&UnifiedRule> {
        self.rules
            .iter()
            .filter(|rule| rule.is_search_rule())
            .collect()
    }

    /// Get all taint mode rules
    pub fn get_taint_rules(&self) -> Vec<&UnifiedRule> {
        self.rules
            .iter()
            .filter(|rule| rule.is_taint_rule())
            .collect()
    }

    /// Count total number of rules
    pub fn count_rules(&self) -> usize {
        self.rules.len()
    }

    /// Get rules by category
    pub fn get_rules_by_category(&self, category: &str) -> Vec<&UnifiedRule> {
        self.rules
            .iter()
            .filter(|rule| {
                rule.category
                    .as_ref()
                    .map(|c| c == category)
                    .unwrap_or(false)
            })
            .collect()
    }

    /// Apply centralized exclusion patterns to all rules
    pub fn apply_centralized_exclusions(
        &mut self,
        exclusion_patterns: &ExclusionPatterns,
        pattern_type: &str,
    ) {
        let patterns = exclusion_patterns.get_patterns(pattern_type);

        for rule in &mut self.rules {
            if let Some(file_types) = &mut rule.file_types {
                // If rule doesn't have exclusion patterns, add the centralized ones
                if file_types.exclude_patterns.is_none() {
                    file_types.exclude_patterns = Some(patterns.clone());
                } else {
                    // If rule has exclusion patterns, merge with centralized ones
                    if let Some(existing_patterns) = &mut file_types.exclude_patterns {
                        let mut merged_patterns = patterns.clone();
                        merged_patterns.extend(existing_patterns.clone());
                        *existing_patterns = merged_patterns;
                    }
                }
            } else {
                // If rule doesn't have file_types, create one with centralized exclusions
                rule.file_types = Some(FileTypes {
                    python: None,
                    java: None,
                    javascript: None,
                    tsx: None,
                    html: None,
                    extensions: Some(vec![
                        ".js".to_string(),
                        ".jsx".to_string(),
                        ".ts".to_string(),
                        ".tsx".to_string(),
                    ]),
                    include_patterns: None,
                    exclude_patterns: Some(patterns.clone()),
                });
            }
        }
    }

    /// Load rules from directory with centralized exclusions applied
    pub fn load_from_directory_with_exclusions(
        rules_dir: &str,
        pattern_type: &str,
    ) -> Result<Self> {
        let mut rules = Self::load_from_directory(rules_dir)?;

        // Try to load exclusion patterns from the same directory
        let exclusion_file = format!("{}/exclusion_patterns.ron", rules_dir);
        if Path::new(&exclusion_file).exists() {
            match ExclusionPatterns::load_from_file(&exclusion_file) {
                Ok(exclusion_patterns) => {
                    rules.apply_centralized_exclusions(&exclusion_patterns, pattern_type);
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Failed to load exclusion patterns from {}: {}",
                        exclusion_file, e
                    );
                }
            }
        }

        Ok(rules)
    }
}

pub fn match_pattern(pattern: &str, text: &str) -> bool {
    CommonUtils::matches_unified_pattern(pattern, text)
}

// Enhanced pattern matching with multiple patterns
pub fn match_any_pattern(patterns: &[String], text: &str) -> bool {
    CommonUtils::matches_any_pattern(patterns, text)
}

pub fn rule_matches_pattern_unified(rule: &UnifiedRule, text: &str) -> bool {
    if let Some(pattern) = &rule.pattern {
        if match_pattern(pattern, text) {
            return true;
        }
    }

    if let Some(patterns) = &rule.patterns {
        for pattern in patterns {
            if match_pattern(pattern, text) {
                return true;
            }
        }
    }

    false
}

pub fn validate_unified_rule_patterns(rule: &UnifiedRule) -> Result<(), String> {
    if rule.is_search_rule() {
        if let Some(pattern) = &rule.pattern {
            if let Some(regex_pattern) = pattern.strip_prefix("regex:") {
                Regex::new(regex_pattern)
                    .map_err(|e| format!("Invalid regex pattern '{}': {}", regex_pattern, e))?;
            }
        }

        if let Some(patterns) = &rule.patterns {
            for pattern in patterns {
                if let Some(regex_pattern) = pattern.strip_prefix("regex:") {
                    Regex::new(regex_pattern)
                        .map_err(|e| format!("Invalid regex pattern '{}': {}", regex_pattern, e))?;
                }
            }
        }
    }
    Ok(())
}

pub fn is_literal_node(node: &tree_sitter::Node) -> bool {
    matches!(
        node.kind(),
        "string"
            | "string_literal"
            | "number"
            | "integer"
            | "float"
            | "boolean"
            | "true"
            | "false"
            | "null"
            | "none"
    )
}

pub fn is_in_protective_context(node: &tree_sitter::Node) -> bool {
    let mut current = node.parent();
    let mut depth = 0;
    const MAX_DEPTH: usize = 10;

    while let Some(parent) = current {
        if depth > MAX_DEPTH {
            break;
        }

        match parent.kind() {
            "try_statement" | "except_clause" | "if_statement" | "conditional_expression" => {
                return true;
            }
            "function_definition" | "method_definition" => {
                // Check if function name suggests validation/sanitization
                if let Some(_name_node) = parent.child_by_field_name("name") {
                    // This would need source bytes to extract the actual name
                    // For now, assume protective if in a function
                    return true;
                }
            }
            _ => {}
        }

        current = parent.parent();
        depth += 1;
    }

    false
}
