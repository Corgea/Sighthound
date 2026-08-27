use anyhow::{Context, Result};
use include_dir::{include_dir, Dir};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::common::CommonUtils;
use crate::language::LanguageSupport;

// Re-export for backward compatibility
pub use crate::models::{Condition, FileTypes, UnifiedRule};

// Embedded rule directories - every `.ron` rule document under each language dir is
// embedded at compile time. New rule files auto-wire: drop a `.ron` into the relevant
// dir and it loads with no edits here. `exclusion_patterns.ron` uses a different RON
// schema (see `ExclusionPatterns`) and is skipped at load time in `parse_embedded_dir`.
static RULES_PYTHON: Dir = include_dir!("$CARGO_MANIFEST_DIR/rules/python");
// Always-on JavaScript/TypeScript rules (frontend + Node backend).
static RULES_JAVASCRIPT: Dir = include_dir!("$CARGO_MANIFEST_DIR/rules/javascript");
// Additional backend JS rules, loaded only when code_type is not "frontend".
static RULES_BACKEND_JAVASCRIPT: Dir = include_dir!("$CARGO_MANIFEST_DIR/rules/backend_javascript");
static RULES_JAVA: Dir = include_dir!("$CARGO_MANIFEST_DIR/rules/java");
static RULES_CSHARP: Dir = include_dir!("$CARGO_MANIFEST_DIR/rules/csharp");
static RULES_GO: Dir = include_dir!("$CARGO_MANIFEST_DIR/rules/go");
static RULES_RUBY: Dir = include_dir!("$CARGO_MANIFEST_DIR/rules/ruby");
static RULES_HTML: Dir = include_dir!("$CARGO_MANIFEST_DIR/rules/html");
static RULES_PHP: Dir = include_dir!("$CARGO_MANIFEST_DIR/rules/php");
static RULES_OBJECTSCRIPT: Dir = include_dir!("$CARGO_MANIFEST_DIR/rules/objectscript");
static RULES_SQL: Dir = include_dir!("$CARGO_MANIFEST_DIR/rules/sql");

// Structure for centralized exclusion patterns
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ExclusionPatterns {
    pub frontend_exclusions: Option<Vec<String>>,
    pub backend_exclusions: Option<Vec<String>>,
    pub common_exclusions: Option<Vec<String>>,
}

impl ExclusionPatterns {
    pub fn load_from_file(file_path: &str) -> Result<Self> {
        let content = fs::read_to_string(file_path)
            .context(format!("Failed to read exclusion patterns file: {}", file_path))?;

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
    /// Parse every embedded `.ron` rule document in `dir` into `Rules` instances.
    ///
    /// Files are sorted by name for deterministic rule order. `exclusion_patterns.ron`
    /// uses a different RON schema (`ExclusionPatterns`) and is skipped.
    fn parse_embedded_dir(dir: &Dir, language: &str) -> Result<Vec<Self>> {
        let mut files: Vec<_> = dir
            .files()
            .filter(|file| {
                let path = file.path();
                path.extension().and_then(|ext| ext.to_str()) == Some("ron")
                    && path.file_name().and_then(|name| name.to_str())
                        != Some("exclusion_patterns.ron")
            })
            .collect();
        files.sort_by(|a, b| a.path().cmp(b.path()));

        let mut parsed = Vec::with_capacity(files.len());
        for file in files {
            let filename = file.path().display();
            let content = file.contents_utf8().with_context(|| {
                format!("Embedded {} rule {} is not valid UTF-8", language, filename)
            })?;
            let rules: Rules = ron::from_str(content).with_context(|| {
                format!("Failed to parse embedded {} rule {}", language, filename)
            })?;
            parsed.push(rules);
        }
        Ok(parsed)
    }

    /// Load embedded rules for a specific language
    pub fn load_embedded_rules(language: &str, code_type: Option<&str>) -> Result<Self> {
        let mut all_rules = Vec::new();

        match language {
            "python" => all_rules.extend(Self::parse_embedded_dir(&RULES_PYTHON, "Python")?),
            "javascript" | "tsx" | "typescript" => {
                all_rules.extend(Self::parse_embedded_dir(&RULES_JAVASCRIPT, "JavaScript")?);
                // Legacy backend JS rules load only when explicitly non-frontend,
                // matching the file-rules auto-detect path the benchmark measured.
                if code_type.is_some_and(|ct| ct != "frontend") {
                    all_rules.extend(Self::parse_embedded_dir(
                        &RULES_BACKEND_JAVASCRIPT,
                        "JavaScript backend",
                    )?);
                }
            }
            "java" => all_rules.extend(Self::parse_embedded_dir(&RULES_JAVA, "Java")?),
            "csharp" => all_rules.extend(Self::parse_embedded_dir(&RULES_CSHARP, "C#")?),
            "go" => all_rules.extend(Self::parse_embedded_dir(&RULES_GO, "Go")?),
            "ruby" => all_rules.extend(Self::parse_embedded_dir(&RULES_RUBY, "Ruby")?),
            "html" | "django" => all_rules.extend(Self::parse_embedded_dir(&RULES_HTML, "HTML")?),
            "php" => all_rules.extend(Self::parse_embedded_dir(&RULES_PHP, "PHP")?),
            "objectscript" => {
                all_rules.extend(Self::parse_embedded_dir(&RULES_OBJECTSCRIPT, "ObjectScript")?)
            }
            "sql" => all_rules.extend(Self::parse_embedded_dir(&RULES_SQL, "SQL")?),
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
                    eprintln!("Warning: Failed to load embedded rules for {}: {}", language, e);
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
        let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or("").to_lowercase();

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
            Err(anyhow::anyhow!("Rules path '{}' is neither a file nor a directory", rules_path))
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
        self.rules.iter().filter(|rule| rule.is_search_rule()).collect()
    }

    /// Get all taint mode rules
    pub fn get_taint_rules(&self) -> Vec<&UnifiedRule> {
        self.rules.iter().filter(|rule| rule.is_taint_rule()).collect()
    }

    /// Count total number of rules
    pub fn count_rules(&self) -> usize {
        self.rules.len()
    }

    /// Get rules by category
    pub fn get_rules_by_category(&self, category: &str) -> Vec<&UnifiedRule> {
        self.rules
            .iter()
            .filter(|rule| rule.category.as_ref().map(|c| c == category).unwrap_or(false))
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
                // If rule doesn't have file_types, create one with centralized exclusions without restricting extensions
                rule.file_types = Some(FileTypes {
                    python: None,
                    java: None,
                    javascript: None,
                    tsx: None,
                    html: None,
                    extensions: None,
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

/// Byte range of the first match of `pattern` inside `text`, when the pattern form can
/// express one.
///
/// Mirrors `CommonUtils::matches_unified_pattern` (src/common.rs) branch for branch, in
/// its exact order. If match and range dispatch disagree, a finding lands on the wrong
/// line.
fn pattern_match_range(pattern: &str, text: &str) -> Option<std::ops::Range<usize>> {
    if pattern == text {
        return Some(0..text.len());
    }
    if let Some(stripped) = pattern.strip_prefix("regex:") {
        return Regex::new(stripped).ok()?.find(text).map(|m| m.range());
    }
    if pattern.contains("\\\\") || pattern.contains("\\.") {
        return Regex::new(pattern).ok()?.find(text).map(|m| m.range());
    }
    if pattern.contains('\\') || pattern.contains('*') {
        // Escaped and glob forms are not range-resolvable; the caller falls back to
        // today's line attribution when no pattern resolves.
        return None;
    }
    text.find(pattern).map(|start| start..start + pattern.len())
}

/// Byte range of the first of the rule's patterns that resolves one against `text`.
///
/// Because `find_map` skips `None`, a `None` from the escaped/glob branch is
/// indistinguishable from "this pattern did not match" — iteration simply continues.
/// The caller therefore falls back to heuristic line attribution only when *every*
/// pattern returns `None`.
pub(crate) fn first_positive_match_range(
    rule: &UnifiedRule,
    text: &str,
) -> Option<std::ops::Range<usize>> {
    // Same pattern order as rule_matches_pattern_unified: `pattern` then `patterns`,
    // returning the first pattern that resolves a range.
    rule.pattern.as_deref().and_then(|pattern| pattern_match_range(pattern, text)).or_else(|| {
        rule.patterns.as_ref()?.iter().find_map(|pattern| pattern_match_range(pattern, text))
    })
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

#[cfg(test)]
mod embedded_rules_tests {
    use super::*;

    #[test]
    fn python_embedded_rules_load_and_skip_exclusion_patterns() {
        // Directory embedding must skip `exclusion_patterns.ron` (different RON schema);
        // if it were parsed as a `Rules` doc this would error instead of returning rules.
        let rules = Rules::load_embedded_rules("python", None).expect("python rules should load");
        assert!(rules.count_rules() > 0, "python embedded rules should not be empty");
    }

    #[test]
    fn javascript_backend_gate_respects_code_type() {
        let frontend = Rules::load_embedded_rules("javascript", Some("frontend"))
            .expect("frontend js rules should load");
        let backend = Rules::load_embedded_rules("javascript", Some("backend"))
            .expect("backend js rules should load");
        // Backend adds the extra backend_javascript rules on top of the always-on set.
        assert!(
            backend.count_rules() > frontend.count_rules(),
            "non-frontend code_type must load additional backend JS rules"
        );
    }
}
