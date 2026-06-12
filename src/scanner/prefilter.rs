use crate::config::filters::SKIP_MINIFIED_PATTERNS;
use crate::parser::{get_node_text, LanguageParser};
use crate::rules::Rules;
use crate::scanner::utils::matches_glob_pattern;
use anyhow::Result;
use std::fs;
use std::path::Path;
use tree_sitter::Node;

#[derive(Debug, Clone)]
pub struct PreFilter {
    is_malicious_scan: bool,
    language: String,
    skip_minified: bool,
    custom_minified_patterns: Vec<String>,
}

impl PreFilter {
    pub fn new(rules: &Rules, language: &str) -> Self {
        Self::with_options(rules, language, true, Vec::new())
    }

    pub fn with_options(
        rules: &Rules,
        language: &str,
        skip_minified: bool,
        custom_patterns: Vec<String>,
    ) -> Self {
        // Check if we have any malware detection rules
        let is_malicious_scan = rules.rules.iter().any(|rule| {
            rule.name.as_ref().is_some_and(|name| {
                let name_lower = name.to_lowercase();
                name_lower.contains("malware")
                    || name_lower.contains("malicious")
                    || name_lower.contains("backdoor")
                    || name_lower.contains("trojan")
            }) || rule.get_category().to_lowercase().contains("malware")
        });

        Self {
            is_malicious_scan,
            language: language.to_string(),
            skip_minified,
            custom_minified_patterns: custom_patterns,
        }
    }

    pub fn is_malicious_scan(&self) -> bool {
        self.is_malicious_scan
    }

    pub fn should_scan_file(&self, file_path: &str) -> bool {
        // Skip empty files
        if let Ok(metadata) = fs::metadata(file_path) {
            if metadata.len() == 0 {
                return false;
            }
        }

        // Always skip text/doc files for both modes
        if self.is_text_or_doc_file(file_path) {
            return false;
        }

        // Skip minified files for JavaScript/TypeScript if enabled
        if self.skip_minified && self.is_js_or_ts_language() && self.is_minified_js_file(file_path)
        {
            return false;
        }

        // For malicious scanning, scan everything else
        if self.is_malicious_scan {
            return true;
        }

        // For general scanning, also skip test/migration files
        !self.is_test_or_migration_file(file_path)
    }

    /// Simple text/doc file detection
    fn is_text_or_doc_file(&self, file_path: &str) -> bool {
        let path_lower = file_path.to_lowercase();

        // File extensions
        let skip_extensions = [
            ".txt", ".md", ".rst", ".pdf", ".doc", ".docx", ".jpg", ".png", ".gif", ".svg", ".ico",
        ];

        if skip_extensions.iter().any(|ext| path_lower.ends_with(ext)) {
            return true;
        }

        // File names
        let filename = Path::new(&path_lower)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        ["readme", "license", "changelog", "authors"]
            .iter()
            .any(|name| filename.starts_with(name))
    }

    /// Check if the current language is JavaScript or TypeScript related
    fn is_js_or_ts_language(&self) -> bool {
        matches!(self.language.as_str(), "javascript" | "typescript" | "tsx")
    }

    /// Detect minified JavaScript files using simple, effective strategies
    fn is_minified_js_file(&self, file_path: &str) -> bool {
        // Strategy 1: Filename pattern matching (covers 95% of cases)
        if self.matches_minified_patterns(file_path) {
            return true;
        }

        // Strategy 2: Simple content heuristic for edge cases
        self.is_likely_minified_content(file_path)
    }

    /// Check if file matches known minified file patterns
    fn matches_minified_patterns(&self, file_path: &str) -> bool {
        // Check built-in patterns
        for pattern in SKIP_MINIFIED_PATTERNS {
            if matches_glob_pattern(pattern, file_path) {
                return true;
            }
        }

        // Check custom patterns
        for pattern in &self.custom_minified_patterns {
            if matches_glob_pattern(pattern, file_path) {
                return true;
            }
        }

        false
    }

    /// Simple heuristic to detect minified content (edge cases only)
    fn is_likely_minified_content(&self, file_path: &str) -> bool {
        // Only check JS/TS files
        if !file_path.ends_with(".js")
            && !file_path.ends_with(".jsx")
            && !file_path.ends_with(".ts")
            && !file_path.ends_with(".tsx")
        {
            return false;
        }

        // Simple check: large single-line files are likely minified
        match fs::read_to_string(file_path) {
            Ok(content) => {
                let line_count = content.lines().count();
                let char_count = content.len();

                // Single line with lots of content = likely minified
                line_count <= 3 && char_count > 2000
            }
            Err(_) => false,
        }
    }

    /// Use tree-sitter to check if file is test or migration
    fn is_test_or_migration_file(&self, file_path: &str) -> bool {
        match self.extract_imports(file_path) {
            Ok(imports_text) => {
                self.has_test_patterns(&imports_text) || self.has_migration_patterns(&imports_text)
            }
            Err(_) => false, // If we can't parse, assume it's not test/migration
        }
    }

    /// Extract all import statements as a single text blob
    fn extract_imports(&self, file_path: &str) -> Result<String> {
        let source = fs::read(file_path)?;
        let mut parser = LanguageParser::new(&self.language)?;
        let tree = parser.parse(&source)?;

        let mut imports_text = String::new();
        self.collect_imports(&tree.root_node(), &source, &mut imports_text);

        Ok(imports_text.to_lowercase())
    }

    /// Recursively collect all import-like text
    fn collect_imports(&self, node: &Node, source: &[u8], imports_text: &mut String) {
        // Check if this looks like an import statement
        let node_kind = node.kind();
        if node_kind.contains("import") {
            let text = get_node_text(node, source);
            imports_text.push_str(&text);
            imports_text.push(' ');
        }

        // Recurse through children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                self.collect_imports(&cursor.node(), source, imports_text);
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    /// Simple pattern matching for test frameworks
    fn has_test_patterns(&self, imports_text: &str) -> bool {
        let test_patterns = [
            // Universal test indicators
            "test",
            "mock",
            "spec",
            "jest",
            "pytest",
            "unittest",
            "cypress",
            "selenium",
            "junit",
            "testng",
            "mocha",
            // Language specific
            "django.test",
            "flask.testing",
            "@testing-library",
            "org.junit",
            "org.mockito",
            "org.testng",
        ];

        test_patterns
            .iter()
            .any(|pattern| imports_text.contains(pattern))
    }

    /// Simple pattern matching for migration frameworks
    fn has_migration_patterns(&self, imports_text: &str) -> bool {
        let migration_patterns = [
            "migration",
            "migrations",
            "migrate",
            "alembic",
            "flyway",
            "liquibase",
            "django.db.migrations",
            "sequelize",
            "knex",
            "typeorm",
        ];

        migration_patterns
            .iter()
            .any(|pattern| imports_text.contains(pattern))
    }

    pub fn filter_files(
        &self,
        files: Vec<std::path::PathBuf>,
    ) -> (Vec<std::path::PathBuf>, FilterStats) {
        let mut included = 0;
        let mut filtered_out = 0;
        let mut minified_filtered = 0;
        let mut test_filtered = 0;
        let mut doc_filtered = 0;

        let filtered: Vec<_> = files
            .into_iter()
            .filter(|path| {
                let path_str = path.to_string_lossy();

                // Optimized filtering with single-pass checks to avoid redundancy
                let filter_result = self.check_file_with_reason(&path_str);

                match filter_result {
                    FilterReason::Include => {
                        included += 1;
                        true
                    }
                    FilterReason::Doc => {
                        filtered_out += 1;
                        doc_filtered += 1;
                        false
                    }
                    FilterReason::Minified => {
                        filtered_out += 1;
                        minified_filtered += 1;
                        false
                    }
                    FilterReason::Test => {
                        filtered_out += 1;
                        test_filtered += 1;
                        false
                    }
                }
            })
            .collect();

        let stats = FilterStats {
            included,
            filtered_out,
            minified_filtered,
            test_filtered,
            doc_filtered,
        };
        (filtered, stats)
    }

    /// Single-pass filtering with reason tracking to avoid duplicate checks
    fn check_file_with_reason(&self, file_path: &str) -> FilterReason {
        // Skip empty files first (fastest check)
        if let Ok(metadata) = fs::metadata(file_path) {
            if metadata.len() == 0 {
                return FilterReason::Doc; // Treat empty files as doc files
            }
        }

        // Check text/doc files next (relatively fast)
        if self.is_text_or_doc_file(file_path) {
            return FilterReason::Doc;
        }

        // For malicious scanning, include everything else (skip other checks)
        if self.is_malicious_scan {
            return FilterReason::Include;
        }

        // Check minified files for JS/TS (potentially expensive, so do conditionally)
        if self.skip_minified && self.is_js_or_ts_language() && self.is_minified_js_file(file_path)
        {
            return FilterReason::Minified;
        }

        // Check test/migration files last (most expensive due to parsing)
        if self.is_test_or_migration_file(file_path) {
            return FilterReason::Test;
        }

        FilterReason::Include
    }
}

/// Enum to track why a file was filtered (avoids duplicate checks)
#[derive(Debug, Clone)]
enum FilterReason {
    Include,
    Doc,
    Minified,
    Test,
}

#[derive(Debug, Clone)]
pub struct FilterStats {
    pub included: usize,
    pub filtered_out: usize,
    pub minified_filtered: usize,
    pub test_filtered: usize,
    pub doc_filtered: usize,
}

impl FilterStats {
    pub fn total(&self) -> usize {
        self.included + self.filtered_out
    }

    pub fn filter_percentage(&self) -> f32 {
        if self.total() == 0 {
            0.0
        } else {
            (self.filtered_out as f32 / self.total() as f32) * 100.0
        }
    }
}

impl std::fmt::Display for FilterStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "pre-filter: {} included, {} filtered out ({:.1}% reduction)",
            self.included,
            self.filtered_out,
            self.filter_percentage()
        )?;

        if self.minified_filtered > 0 || self.test_filtered > 0 || self.doc_filtered > 0 {
            write!(f, "\n     ")?;
            let mut details = Vec::new();
            if self.minified_filtered > 0 {
                details.push(format!("{} minified", self.minified_filtered));
            }
            if self.test_filtered > 0 {
                details.push(format!("{} test/migration", self.test_filtered));
            }
            if self.doc_filtered > 0 {
                details.push(format!("{} doc/media", self.doc_filtered));
            }
            write!(f, "{}", details.join(", "))?;
        }

        Ok(())
    }
}
