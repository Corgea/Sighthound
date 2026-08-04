use std::path::PathBuf;

use crate::scanner::taint_utils::TaintRuleDeduplicator;

pub(crate) struct SinkSite<'a> {
    pub(crate) node_text: &'a str,
    pub(crate) filepath: &'a str,
    pub(crate) line: usize,
    pub(crate) func_name: &'a str,
    pub(crate) sink_pattern: &'a str,
}

/// Discovered scan files grouped by detected language.
pub(crate) type FilesByLanguage = std::collections::BTreeMap<String, Vec<PathBuf>>;

/// The search/taint rule sets (and whether each is non-empty) used to scan every file in a
/// unified scan, bundled to keep the per-file scan helpers' parameter counts small.
pub(crate) struct ScanRuleSet<'a> {
    pub(crate) has_search_rules: bool,
    pub(crate) has_taint_rules: bool,
    pub(crate) search_rules: &'a [&'a crate::rules::UnifiedRule],
    pub(crate) taint_rules: &'a [&'a crate::rules::UnifiedRule],
    pub(crate) embedded_dom_xss_rules: &'a [&'a crate::rules::UnifiedRule],
}

/// Invariant context threaded through [`ScanningLogic::scan_file_with_rules_and_taint_context`]'s
/// phase-2 (enhanced search) helpers.
pub(crate) struct EnhancedSearchContext<'a> {
    pub(crate) source: &'a [u8],
    pub(crate) filepath: &'a str,
    pub(crate) language_support: &'a dyn crate::language::LanguageSupport,
    pub(crate) applicable_search_rules: &'a [&'a crate::rules::UnifiedRule],
    pub(crate) rule_deduplicator: &'a TaintRuleDeduplicator,
    pub(crate) has_taint_rules: bool,
}

/// Invariant context threaded through [`ScanningLogic::scan_file_with_taint_rules`]'s
/// per-node helpers: everything that doesn't change while scanning a single file.
pub(crate) struct TaintScanContext<'a> {
    pub(crate) source: &'a [u8],
    pub(crate) filepath: &'a str,
    pub(crate) is_embedded_javascript: bool,
    pub(crate) tree: &'a tree_sitter::Tree,
    pub(crate) language_support: &'a dyn crate::language::LanguageSupport,
    pub(crate) applicable_rules: &'a [&'a crate::rules::UnifiedRule],
    pub(crate) rule_deduplicator: &'a TaintRuleDeduplicator,
}
