pub mod cli;
pub mod common;
pub mod config;
pub mod language;
pub mod models;
pub mod parser;
pub mod rules;
pub mod scanner;
pub mod code_type_detector;

// Re-export the main types and functions that main.rs needs
pub use scanner::{
    VulnerabilityScanner, ScanningLogic, PreFilter, FilterStats, 
    run_explicit_scan, run_auto_detection_scan, run_taint_analysis
};
pub use scanner::modes::run_taint_analysis_with_verbosity;

// Re-export types needed by tests and library users
pub use common::CommonUtils;
pub use config::ScanDefaults;
pub use rules::{Rules, match_pattern, check_for_injection_pattern};

// Re-export code type detection
pub use code_type_detector::{CodeTypeDetector, CodeType};

// Re-export commonly used items from models
pub use models::{
    Finding, TaintFlow, TaintSource, TaintSink, TaintTrace, TaintSummary,
    UnifiedRule, FileTypes, Condition, Cli, LanguageInfo, FileInfo
};

pub use parser::traverse_calls_only;