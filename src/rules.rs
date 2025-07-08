use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::language::LanguageSupport;
use crate::common::CommonUtils;

// Re-export for backward compatibility
pub use crate::models::{UnifiedRule, FileTypes, Condition};

// Embedded rules - include rule files at compile time
const EMBEDDED_PYTHON_GENERAL_RULES: &str = include_str!("../rules/python/general_security.ron");
const EMBEDDED_PYTHON_COMMAND_INJECTION_RULES: &str = include_str!("../rules/python/command_injection.ron");
const EMBEDDED_PYTHON_CRYPTOGRAPHY_RULES: &str = include_str!("../rules/python/cryptography.ron");
const EMBEDDED_PYTHON_FILE_SYSTEM_RULES: &str = include_str!("../rules/python/file_system.ron");
const EMBEDDED_PYTHON_SQL_INJECTION_RULES: &str = include_str!("../rules/python/sql_injection.ron");
const EMBEDDED_PYTHON_WORKING_RULES: &str = include_str!("../rules/python/working.ron");
const EMBEDDED_JAVASCRIPT_FRONTEND_RULES: &str = include_str!("../rules/javascript/frontend_security.ron");
const EMBEDDED_JAVASCRIPT_BACKEND_RULES: &str = include_str!("../rules/backend_javascript/backend_security.ron");
const EMBEDDED_JAVASCRIPT_TAINT_RULES: &str = include_str!("../rules/javascript/frontend_taint_security.ron");

// Add more embedded rules as needed
// const EMBEDDED_JAVA_RULES: &str = include_str!("../rules/java/security.ron");
// const EMBEDDED_HTML_RULES: &str = include_str!("../rules/html/security.ron");

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
            "common" => {
                self.common_exclusions.clone().unwrap_or_default()
            }
            _ => Vec::new()
        }
    }
}

// Simple injection pattern checking for basic patterns
pub fn check_for_injection_pattern(text: &str, _language_support: &dyn LanguageSupport) -> bool {
    // Basic injection indicators that are language-agnostic
    let basic_patterns = [
        ";", "&&", "||", "`", "$(",  // Command separators/chaining
        "eval(", "exec(", "system(",  // Dangerous functions  
        "{{", "{%",                   // Template injection
        "javascript:", "data:",       // URL schemes
    ];
    
    basic_patterns.iter().any(|&pattern| text.contains(pattern))
}

// Simplified Rules structure - only unified rules
#[derive(Debug, Deserialize, Serialize)]
pub struct Rules {
    #[serde(default)]
    pub rules: Vec<UnifiedRule>,
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
        }
    }
}

impl Rules {
    /// Load embedded rules for a specific language
    pub fn load_embedded_rules(language: &str, code_type: Option<&str>) -> Result<Self> {
        let mut all_rules = Vec::new();
        
        match language {
            "python" => {
                // Load all Python rule files
                let general_rules: Rules = ron::from_str(EMBEDDED_PYTHON_GENERAL_RULES)
                    .context("Failed to parse embedded Python general rules")?;
                all_rules.push(general_rules);
                
                let command_injection_rules: Rules = ron::from_str(EMBEDDED_PYTHON_COMMAND_INJECTION_RULES)
                    .context("Failed to parse embedded Python command injection rules")?;
                all_rules.push(command_injection_rules);
                
                let cryptography_rules: Rules = ron::from_str(EMBEDDED_PYTHON_CRYPTOGRAPHY_RULES)
                    .context("Failed to parse embedded Python cryptography rules")?;
                all_rules.push(cryptography_rules);
                
                let file_system_rules: Rules = ron::from_str(EMBEDDED_PYTHON_FILE_SYSTEM_RULES)
                    .context("Failed to parse embedded Python file system rules")?;
                all_rules.push(file_system_rules);
                
                let sql_injection_rules: Rules = ron::from_str(EMBEDDED_PYTHON_SQL_INJECTION_RULES)
                    .context("Failed to parse embedded Python SQL injection rules")?;
                all_rules.push(sql_injection_rules);
                
                let working_rules: Rules = ron::from_str(EMBEDDED_PYTHON_WORKING_RULES)
                    .context("Failed to parse embedded Python working rules")?;
                all_rules.push(working_rules);
            }
            "javascript" | "tsx" => {
                // Load frontend rules by default
                let frontend_rules: Rules = ron::from_str(EMBEDDED_JAVASCRIPT_FRONTEND_RULES)
                    .context("Failed to parse embedded JavaScript frontend rules")?;
                all_rules.push(frontend_rules);
                
                // Load taint rules
                let taint_rules: Rules = ron::from_str(EMBEDDED_JAVASCRIPT_TAINT_RULES)
                    .context("Failed to parse embedded JavaScript taint rules")?;
                all_rules.push(taint_rules);
                
                // Load backend rules if requested
                if let Some(code_type) = code_type {
                    if code_type != "frontend" {
                        let backend_rules: Rules = ron::from_str(EMBEDDED_JAVASCRIPT_BACKEND_RULES)
                            .context("Failed to parse embedded JavaScript backend rules")?;
                        all_rules.push(backend_rules);
                    }
                }
            }
            // Add more languages as needed
            _ => {
                return Err(anyhow::anyhow!("No embedded rules available for language: {}", language));
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
            return Err(anyhow::anyhow!("No embedded rules found for any of the detected languages"));
        }
        
        Self::merge_rules(all_rules)
    }

    pub fn load_from_file(rules_file: &str) -> Result<Self> {
        let content = fs::read_to_string(rules_file)
            .context(format!("Failed to read rules file: {}", rules_file))?;
        
        let path = Path::new(rules_file);
        let extension = path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_lowercase();

        match extension.as_str() {
            "ron" => {
                ron::from_str(&content).context("Failed to parse rules RON")
            },
            _ => {
                Err(anyhow::anyhow!("Unsupported file format. Only .ron files are supported for rules."))
            }
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

        let entries = fs::read_dir(dir_path)
            .context(format!("Failed to read directory: {}", rules_dir))?;

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
                            eprintln!("Warning: Failed to load rules from {}: {}", file_path_str, e);
                        }
                    }
                }
            }
        }

        if all_rules.is_empty() {
            return Err(anyhow::anyhow!("No valid .ron rules files found in directory: {}", rules_dir));
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
        self.rules.iter().filter(|rule| {
            rule.category.as_ref().map(|c| c == category).unwrap_or(false)
        }).collect()
    }

    /// Apply centralized exclusion patterns to all rules
    pub fn apply_centralized_exclusions(&mut self, exclusion_patterns: &ExclusionPatterns, pattern_type: &str) {
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
                    extensions: Some(vec![".js".to_string(), ".jsx".to_string(), ".ts".to_string(), ".tsx".to_string()]),
                    include_patterns: None,
                    exclude_patterns: Some(patterns.clone()),
                });
            }
        }
    }

    /// Load rules from directory with centralized exclusions applied
    pub fn load_from_directory_with_exclusions(rules_dir: &str, pattern_type: &str) -> Result<Self> {
        let mut rules = Self::load_from_directory(rules_dir)?;
        
        // Try to load exclusion patterns from the same directory
        let exclusion_file = format!("{}/exclusion_patterns.ron", rules_dir);
        if Path::new(&exclusion_file).exists() {
            match ExclusionPatterns::load_from_file(&exclusion_file) {
                Ok(exclusion_patterns) => {
                    rules.apply_centralized_exclusions(&exclusion_patterns, pattern_type);
                }
                Err(e) => {
                    eprintln!("Warning: Failed to load exclusion patterns from {}: {}", exclusion_file, e);
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
            if pattern.starts_with("regex:") {
                let regex_pattern = &pattern[6..];
                Regex::new(regex_pattern).map_err(|e| format!("Invalid regex pattern '{}': {}", regex_pattern, e))?;
            }
        }
        
        if let Some(patterns) = &rule.patterns {
            for pattern in patterns {
                if pattern.starts_with("regex:") {
                    let regex_pattern = &pattern[6..];
                    Regex::new(regex_pattern).map_err(|e| format!("Invalid regex pattern '{}': {}", regex_pattern, e))?;
                }
            }
        }
    }
    Ok(())
}

pub fn is_literal_node(node: &tree_sitter::Node) -> bool {
    match node.kind() {
        "string" | "string_literal" | "number" | "integer" | "float" | 
        "boolean" | "true" | "false" | "null" | "none" => true,
        _ => false,
    }
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