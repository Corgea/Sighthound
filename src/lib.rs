//! Sighthound — a fast, AST-based static analysis scanner for security
//! vulnerabilities in source code.
//!
//! Sighthound parses source with [tree-sitter](https://tree-sitter.github.io/) and
//! applies RON-encoded rules in two modes:
//!
//! - **Search rules** match dangerous patterns directly in the AST.
//! - **Taint rules** track untrusted data from sources to sinks.
//!
//! # Example
//!
//! ```no_run
//! use anyhow::Result;
//! use clap::Parser;
//! use sighthound::{run_auto_detection_scan, Cli};
//!
//! fn scan(path: &str) -> Result<()> {
//!     let cli = Cli::parse_from(["sighthound", path]);
//!     let findings = run_auto_detection_scan(&cli, path, false)?;
//!     println!("{} findings", findings.len());
//!     Ok(())
//! }
//! ```
//!
//! # Stability
//!
//! The library API is **unstable** before v1.0. Minor releases may include
//! breaking changes to public modules.

pub mod cli;
pub mod code_type_detector;
pub mod common;
pub mod config;
pub mod language;
pub mod models;
pub mod parser;
pub mod rules;
pub mod scanner;
pub mod ui;

pub use scanner::modes::run_taint_analysis_with_verbosity;
pub use scanner::{
    FilterStats, PreFilter, ScanningLogic, VulnerabilityScanner, run_auto_detection_scan,
    run_explicit_scan, run_taint_analysis,
};

pub use common::CommonUtils;
pub use config::ScanDefaults;
pub use rules::{Rules, check_for_injection_pattern, match_pattern};

pub use code_type_detector::{CodeType, CodeTypeDetector};

pub use models::{
    Cli, Condition, FileInfo, FileTypes, Finding, LanguageInfo, TaintFlow, TaintSink, TaintSource,
    TaintSummary, TaintTrace, UnifiedRule,
};

pub use parser::traverse_calls_only;
