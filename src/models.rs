use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Core vulnerability finding data structure
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub end_line: usize,
    pub end_column: usize,
    pub function: String,
    pub finding_type: String,
    pub snippet: String,
    pub severity: String,
    pub confidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_info: Option<SourceInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sink_info: Option<SinkInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traces: Option<Vec<TraceStep>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

/// Information about the source of tainted data
#[derive(Debug, Clone, Serialize)]
pub struct SourceInfo {
    pub source_type: String,
    pub location: String,
    pub context: String,
}

/// Information about where tainted data is used (sink)
#[derive(Debug, Clone, Serialize)]
pub struct SinkInfo {
    pub sink_type: String,
    pub function_name: String,
    pub location: String,
    pub variable: Option<String>,
}

/// A step in the data flow trace
#[derive(Debug, Clone, Serialize)]
pub struct TraceStep {
    pub file: String,
    pub line: usize,
    pub code: String,
    pub variable: String,
    pub operation: String,   // "assignment", "parameter", "return", "method_call"
    pub function: String,    // Containing function name
}

/// Core taint flow data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintFlow {
    pub flow_id: String,
    pub flow_name: Option<String>,
    pub severity: String,
    pub confidence: String,
    pub source: TaintSource,
    pub sink: TaintSink,
    pub traces: Vec<TaintTrace>,
    pub is_sanitized: bool,
    pub sanitization_points: Vec<TaintTrace>,
    pub is_cross_file: bool,
    // Rule information for better reporting
    pub rule_id: Option<String>,
    pub rule_name: Option<String>, 
    pub rule_description: Option<String>,
    pub rule_finding_type: Option<String>,
}

/// Source of tainted data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSource {
    pub file: String,
    pub line: usize,
    pub function: String,
    pub variable: String,
    pub operation: String,
    pub code: String,
    // Branch tracking for control flow awareness
    pub branch_id: Option<String>,
}

/// Sink where tainted data is used
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSink {
    pub file: String,
    pub line: usize,
    pub function: String,
    pub variable: String,
    pub operation: String,
    pub code: String,
    // Branch tracking for control flow awareness  
    pub branch_id: Option<String>,
}

/// A step in the taint trace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintTrace {
    pub file: String,
    pub line: usize,
    pub function: String,
    pub variable: String,
    pub code: String,
    pub trace_type: TraceType,
}

/// Trace operation type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TraceType {
    Propagation,
    Assignment,
    Sanitization,
    FunctionCall,
    CrossFileImport,
}

/// Summary of taint analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSummary {
    pub total_flows: usize,
    pub unsanitized_flows: usize,
    pub sanitized_flows: usize,
    pub cross_file_flows: usize,
    pub files_analyzed: usize,
    pub functions_analyzed: usize,
}

/// File information for scanning
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub path: PathBuf,
    pub size: u64,
    pub extension: Option<String>,
}

/// Standard language information structure
pub struct LanguageInfo {
    pub name: &'static str,
    pub extension: &'static str,
    pub call_types: &'static [&'static str],
}

/// Core rule configuration structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UnifiedRule {
    // Rule identification and metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub id: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub name: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub description: Option<String>,
    
    // Category field for organization
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub category: Option<String>,
    
    // Analysis mode - determines how the rule is processed
    #[serde(default = "default_search_mode")]
    pub mode: String, // "search" (default) or "taint"
    
    // Pattern matching (used in search mode)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub pattern: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub patterns: Option<Vec<String>>,
    
    // Taint analysis fields (used when mode = "taint")
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub sources: Option<Vec<String>>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub sinks: Option<Vec<String>>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub propagators: Option<Vec<String>>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub sanitizers: Option<Vec<String>>,
    
    // Metadata and configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub finding_type: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub severity: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub confidence: Option<String>,
    
    // File filtering
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub file_types: Option<FileTypes>,
    
    // Advanced conditions for pattern matching
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    
    // Additional metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub cwe_id: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub message: Option<String>,
}

/// File type filtering configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileTypes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub python: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub java: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub javascript: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tsx: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_patterns: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_patterns: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<String>>,
}

/// AST condition for rule matching
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Condition {
    pub field: String,
    pub operator: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argument_position: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patterns: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_in: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ancestor_types: Option<Vec<String>>,
}



/// CLI configuration structure
#[derive(clap::Parser)]
#[command(
    name = "find_vulns",
    about = "A fast vulnerability scanner for source code",
    long_about = "Corgea Greppy - A high-performance vulnerability scanner that uses tree-sitter for AST-based analysis with parallel processing support.\n\nSupports both explicit mode (specify language and rules) and auto-detection mode (automatically detect file types and load appropriate rules). Rules must be in RON format."
)]
pub struct Cli {
    /// Root directory to scan
    #[arg(help = "Root directory to scan for vulnerabilities")]
    pub root_dir: String,
    
    /// Language to scan (optional - triggers explicit mode when used with rules_path)
    #[arg(help = "Programming language to scan (python, java, javascript, tsx, html, django)")]
    pub language: Option<String>,
    
    /// Rules file or directory path (optional - triggers explicit mode when used with language)
    #[arg(help = "Path to rules file (.ron) or directory containing multiple .ron rule files")]
    pub rules_path: Option<String>,
    
    /// Custom rules directory (overrides default 'rules' directory)
    #[arg(long, help = "Custom rules directory to use instead of default 'rules' directory")]
    pub rules_dir: Option<String>,
    
    /// Use embedded rules instead of loading from files (default: true)
    #[arg(long, default_value = "true", help = "Use rules embedded in the binary instead of loading from files (default: true)")]
    pub use_embedded_rules: bool,
    
    /// Disable embedded rules and use file-based rules instead
    #[arg(long, help = "Disable embedded rules and load rules from files (overrides --use-embedded-rules)")]
    pub use_file_rules: bool,
    
    /// Output format (text, json, csv)
    #[arg(short, long, default_value = "text", help = "Output format: text, json, or csv")]
    pub output_format: String,
    
    /// Verbose output
    #[arg(short, long, help = "Enable verbose output showing more details")]
    pub verbose: bool,
    
    /// Only show summary
    #[arg(short, long, help = "Only show vulnerability summary without individual findings")]
    pub summary_only: bool,

    /// Disable parallel processing (use single-threaded mode)
    #[arg(long, help = "Disable parallel processing for debugging or specific use cases")]
    pub single_threaded: bool,

    /// Number of threads to use for parallel processing (default: CPU cores)
    #[arg(long, help = "Number of threads for parallel processing (default: auto-detect CPU cores)")]
    pub threads: Option<usize>,

    /// Enable taint analysis mode
    #[arg(long, help = "Enable taint analysis to track data flows from sources to sinks")]
    pub taint_analysis: bool,

    /// Skip minified JavaScript files (default: true)
    #[arg(long, help = "Skip minified JavaScript files during scanning")]
    pub skip_minified: Option<bool>,

    /// Filter by code type (frontend, backend, or both)
    #[arg(long, help = "Filter by code type: frontend, backend, or both (default: both)")]
    pub code_type: Option<String>,

    /// Filter by programming language
    #[arg(long, help = "Filter by programming language: javascript, typescript, python, java, etc.")]
    pub language_filter: Option<String>,
}

// Helper function for default search mode
fn default_search_mode() -> String {
    "search".to_string()
}

// UnifiedRule implementation methods
impl UnifiedRule {
    pub fn is_taint_rule(&self) -> bool {
        self.mode == "taint"
    }
    
    pub fn is_search_rule(&self) -> bool {
        self.mode == "search"
    }
    
    pub fn get_category(&self) -> &str {
        self.category.as_deref().unwrap_or("unknown")
    }
    
    pub fn get_finding_type(&self) -> &str {
        self.finding_type.as_deref().unwrap_or("vulnerability")
    }
    
    pub fn get_severity(&self) -> &str {
        self.severity.as_deref().unwrap_or("Medium")
    }
    
    pub fn get_confidence(&self) -> &str {
        self.confidence.as_deref().unwrap_or("Medium")
    }
}

// Finding implementation methods
impl Finding {
    pub fn new(file: &str, line: usize, function: &str, finding_type: &str) -> Self {
        Self {
            file: file.to_string(),
            line,
            column: 0,
            end_line: line,
            end_column: 0,
            function: function.to_string(),
            finding_type: finding_type.to_string(),
            snippet: String::new(),
            severity: "Medium".to_string(),
            confidence: "Medium".to_string(),
            description: None,
            cwe_id: None,
            source_info: None,
            sink_info: None,
            traces: None,
            tags: None,
        }
    }
    
    pub fn is_critical(&self) -> bool {
        self.severity.to_lowercase() == "high" || self.severity.to_lowercase() == "critical"
    }
    
    pub fn add_trace(&mut self, trace: TraceStep) {
        if let Some(ref mut traces) = self.traces {
            traces.push(trace);
        } else {
            self.traces = Some(vec![trace]);
        }
    }
    
    /// Extract CWE ID from tags field and set the cwe_id field
    pub fn extract_cwe_id(&mut self) {
        if let Some(ref tags) = self.tags {
            // Look for tags that start with "cwe-" and extract the first one
            for tag in tags {
                if tag.starts_with("cwe-") {
                    self.cwe_id = Some(tag.clone());
                    break;
                }
            }
        }
    }
    
    /// Extract CWE ID from tags if present
    pub fn extract_cwe_id_from_tags(tags: &Option<Vec<String>>) -> Option<String> {
        tags.as_ref()
            .and_then(|tag_list| {
                tag_list.iter()
                    .find(|tag| tag.starts_with("cwe-"))
                    .map(|tag| tag.to_string())
            })
    }
    
    /// Extract CWE ID from rule tags (kept for backward compatibility)
    pub fn extract_cwe_id_with_fallback(tags: &[String], _finding_type: &str) -> Option<String> {
        // Get CWE from rule tags only
        Finding::extract_cwe_id_from_tags(&Some(tags.to_vec()))
    }
} 