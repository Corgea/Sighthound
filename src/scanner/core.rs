//! Core vulnerability scanning engine compatibility facade.
//!
//! The scanner implementation lives in focused sibling modules. This module keeps the
//! existing `crate::scanner::core::*` paths stable.

pub use super::output::{
    ProgressManager, print_findings_csv, print_findings_json, print_findings_sarif,
    print_findings_text,
};
pub use super::scanning_logic::ScanningLogic;
pub use super::vulnerability_scanner::VulnerabilityScanner;
