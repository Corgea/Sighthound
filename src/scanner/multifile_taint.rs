#![allow(clippy::too_many_arguments, clippy::large_enum_variant, clippy::needless_range_loop)]

use anyhow::Result;

use crate::common::CommonUtils;
use crate::scanner::dataflow::DataFlowTracer;
use crate::scanner::flow_tracker::{AnalysisResult, CrossFileFlowKey, VerifiedTaintFlow};
use crate::scanner::parser_helper::with_local_parser_for_path;
use crate::scanner::scanning_logic::ScanningLogic;
use crate::scanner::taint_utils::TaintRuleDeduplicator;

#[derive(Debug)]
pub(crate) struct MultiFileTaintAnalyzer {
    /// Maps file paths to their imported functions/variables
    file_imports: std::collections::BTreeMap<String, FileImports>,
}

#[derive(Debug, Clone)]
struct FileImports {
    /// Functions imported into this file
    functions: std::collections::BTreeMap<String, String>, // local_name -> source_file
    /// Taint sinks in this file
    taint_sinks: Vec<TaintSinkInfo>,
}

#[derive(Debug, Clone)]
struct TaintSinkInfo {
    function: String,
    line: usize,
    pattern: String,
    used_variable: String,
}

impl MultiFileTaintAnalyzer {
    pub(crate) fn new() -> Self {
        Self { file_imports: std::collections::BTreeMap::new() }
    }

    /// NEW: Analyze cross-file taint flows using the enhanced DataFlowTracer
    /// Select the target language and its files for cross-file analysis: `language_filter`'s
    /// files if present and non-empty (no fallback when it yields nothing), else Python (the
    /// legacy default) if present and non-empty.
    fn select_cross_file_targets<'a>(
        files_by_language: &'a std::collections::BTreeMap<String, Vec<std::path::PathBuf>>,
        language_filter: Option<&'a str>,
    ) -> Option<(Vec<std::path::PathBuf>, &'a str)> {
        if let Some(filter_lang) = language_filter {
            let filtered_files = files_by_language.get(filter_lang)?;
            if filtered_files.is_empty() {
                return None;
            }
            log::debug!(
                "[CROSS_FILE_NEW] Using language_filter: {} ({} files)",
                filter_lang,
                filtered_files.len()
            );
            return Some((filtered_files.clone(), filter_lang));
        }

        let python_files = files_by_language.get("python")?;
        if python_files.is_empty() {
            return None;
        }
        Some((python_files.clone(), "python"))
    }

    /// Handle one sink's analysis result: for a definite taint flow, record a deduplicated
    /// finding via the rule matching the source/sink pattern combination; safe/unknown results
    /// produce no finding.
    fn process_sink_analysis_result(
        &self,
        analysis_result: AnalysisResult,
        sink_info: &TaintSinkInfo,
        rule_deduplicator: &TaintRuleDeduplicator,
        seen_flows: &mut std::collections::BTreeSet<CrossFileFlowKey>,
        findings: &mut Vec<crate::models::Finding>,
    ) {
        match analysis_result {
            AnalysisResult::DefinitelyTainted { flow } => {
                log::debug!(
                    "[CROSS_FILE_NEW] VERIFIED taint flow: {} -> {}",
                    flow.source_pattern,
                    flow.sink_pattern
                );

                // Get the appropriate rule for this flow
                let Some(rule) = rule_deduplicator
                    .get_rule_for_combination(&flow.source_pattern, &flow.sink_pattern)
                else {
                    return;
                };
                let flow_key = (
                    flow.sink_file.clone(),
                    flow.sink_line,
                    flow.sink_variable.clone(),
                    flow.sink_pattern.clone(),
                    flow.source_file.clone(),
                    flow.source_line,
                    flow.source_pattern.clone(),
                );
                if !seen_flows.insert(flow_key) {
                    log::debug!(
                        "[CROSS_FILE_NEW] Skipping duplicate flow: {} ({}:{}) -> {} ({}:{})",
                        flow.source_pattern,
                        flow.source_file,
                        flow.source_line,
                        flow.sink_pattern,
                        flow.sink_file,
                        flow.sink_line
                    );
                    return;
                }
                let finding = self.create_finding_from_verified_flow(&flow, rule);
                findings.push(finding);
            }
            AnalysisResult::DefinitelySafe => {
                log::debug!("[CROSS_FILE_NEW] SAFE: No taint flow to {}", sink_info.used_variable);
                // Don't create any finding - this is definitely safe
            }
            AnalysisResult::Unknown { reason } => {
                log::debug!("[CROSS_FILE_NEW] UNKNOWN: {} for {}", reason, sink_info.used_variable);
                // For now, don't create findings for unknown cases to reduce false positives
                // Could add a flag to include these if needed
            }
        }
    }

    pub(crate) fn analyze_cross_file_flows(
        &mut self,
        files_by_language: &std::collections::BTreeMap<String, Vec<std::path::PathBuf>>,
        taint_rules: &[&crate::rules::UnifiedRule],
        language_filter: Option<&str>,
    ) -> Result<Vec<crate::models::Finding>> {
        log::debug!("[CROSS_FILE_NEW] Starting enhanced cross-file taint analysis");

        // If still no files, skip cross-file analysis
        let Some((target_files, language)) =
            Self::select_cross_file_targets(files_by_language, language_filter)
        else {
            log::debug!("[CROSS_FILE_NEW] No suitable files found for cross-file analysis");
            return Ok(Vec::new());
        };
        log::debug!(
            "[CROSS_FILE_NEW] Analyzing {} {} files for cross-file taint flows",
            target_files.len(),
            language
        );

        let mut data_flow_tracer = DataFlowTracer::new();

        let mut findings = Vec::new();
        let rule_deduplicator = TaintRuleDeduplicator::new(taint_rules);

        // Dedup verified cross-file flows within this invocation. The same flow can be
        // rediscovered when multiple sink_info entries / rule patterns match the same
        // (sink_file, sink_variable). We key on the full flow identity rather than the sink
        // line alone so that distinct tainted variables on the same line (now emitted as
        // separate TaintSinkInfo per used variable) stay separate findings; only a flow whose
        // source AND sink are byte-for-byte identical is collapsed. BTreeSet keeps the dedup
        // deterministic per repo convention.
        // Key: (sink_file, sink_line, sink_variable, sink_pattern, source_file, source_line,
        // source_pattern) -- see `CrossFileFlowKey`.
        let mut seen_flows: std::collections::BTreeSet<CrossFileFlowKey> =
            std::collections::BTreeSet::new();

        // Build legacy import/export maps for sink discovery (temporary)
        self.build_import_export_maps(files_by_language, taint_rules, language_filter)?;

        // Hand the parsed import data to the tracer so it can resolve `from foo import bar`
        // statements to their source file via real imports (no re-parsing). This is derived
        // from `self.file_imports.functions`, which already maps imported function name ->
        // resolved source file per calling file.
        let import_map = self
            .file_imports
            .iter()
            .map(|(file, imports)| (file.clone(), imports.functions.clone()))
            .collect();
        data_flow_tracer.set_import_map(import_map);

        log::debug!("[CROSS_FILE_NEW] Analyzing {} files with sinks", self.file_imports.len());

        // For each file with sinks, use the new precise analysis
        for (sink_file, imports) in &self.file_imports {
            for sink_info in &imports.taint_sinks {
                log::debug!(
                    "[CROSS_FILE_NEW] Analyzing sink: {} in {}::{}",
                    sink_info.used_variable,
                    sink_file,
                    sink_info.function
                );

                // Use the new DataFlowTracer for precise analysis
                let analysis_result = data_flow_tracer.analyze_sink_variable(
                    sink_file,
                    &sink_info.function,
                    &sink_info.used_variable,
                    &sink_info.pattern,
                    sink_info.line,
                    &rule_deduplicator,
                );

                self.process_sink_analysis_result(
                    analysis_result,
                    sink_info,
                    &rule_deduplicator,
                    &mut seen_flows,
                    &mut findings,
                );
            }
        }

        log::debug!(
            "[CROSS_FILE_NEW] Enhanced analysis complete. Found {} verified flows",
            findings.len()
        );
        Ok(findings)
    }

    /// Create a Finding from a verified taint flow (helper method)
    fn create_finding_from_verified_flow(
        &self,
        flow: &VerifiedTaintFlow,
        rule: &crate::rules::UnifiedRule,
    ) -> crate::models::Finding {
        let description = if flow.source_file == flow.sink_file {
            format!(
                "Verified taint flow: {} -> {} within {}",
                flow.source_pattern, flow.sink_pattern, flow.source_file
            )
        } else {
            format!(
                "Verified cross-file taint flow: {} in {} -> {} in {} via {} call(s)",
                flow.source_pattern,
                flow.source_file,
                flow.sink_pattern,
                flow.sink_file,
                flow.call_chain_len
            )
        };

        let mut finding = crate::models::Finding {
            file: flow.sink_file.clone(),
            line: flow.sink_line,
            column: 0,
            end_line: flow.sink_line,
            end_column: 0,
            function: flow.sink_function.clone(),
            finding_type: rule.finding_type.clone().unwrap_or_else(|| "Unknown".to_string()),
            snippet: format!("Sink: {}", flow.sink_pattern),
            severity: rule.severity.clone().unwrap_or_else(|| "Medium".to_string()),
            confidence: rule.confidence.clone().unwrap_or_else(|| "High".to_string()),
            description: Some(description),
            cwe_id: None,
            source_info: Some(crate::models::SourceInfo {
                source_type: flow.source_pattern.clone(),
                location: format!("{}:{}", flow.source_file, flow.source_line),
                context: format!("function: {}", flow.source_function),
            }),
            sink_info: Some(crate::models::SinkInfo {
                sink_type: flow.sink_pattern.clone(),
                function_name: flow.sink_function.clone(),
                location: format!("{}:{}", flow.sink_file, flow.sink_line),
                variable: Some(flow.sink_variable.clone()),
            }),
            traces: None,
            tags: Some(vec!["taint_analysis".to_string(), "cross_file".to_string()]),
        };

        // Use CWE ID directly from rule, with fallback to tags for backward compatibility
        finding.cwe_id = rule.cwe_id.clone().or_else(|| {
            // Fallback: extract from tags if rule doesn't have cwe_id field
            if let Some(ref tags) = rule.tags {
                crate::models::Finding::extract_cwe_id_from_tags(&Some(tags.clone()))
            } else {
                None
            }
        });

        finding
    }

    /// Build import/export maps for all files
    /// Parse one file and feed it into [`Self::analyze_file_imports_exports`] for
    /// import/export/taint-sink discovery.
    fn analyze_file_for_imports_exports(
        &mut self,
        file_path: &std::path::Path,
        language: &str,
        rule_deduplicator: &TaintRuleDeduplicator,
    ) -> Result<()> {
        let filepath = file_path.to_string_lossy();
        let source = std::fs::read(file_path)?;

        with_local_parser_for_path(language, file_path, |parser| {
            let tree = parser.parse(&source)?;

            self.analyze_file_imports_exports(
                &filepath,
                &source,
                &tree,
                rule_deduplicator,
                parser.language_support(),
            );

            Ok(())
        })
    }

    fn build_import_export_maps(
        &mut self,
        files_by_language: &std::collections::BTreeMap<String, Vec<std::path::PathBuf>>,
        taint_rules: &[&crate::rules::UnifiedRule],
        language_filter: Option<&str>,
    ) -> Result<()> {
        let rule_deduplicator = TaintRuleDeduplicator::new(taint_rules);

        // UPDATED: Use same logic as analyze_cross_file_flows
        if let Some(filter_lang) = language_filter {
            // If language_filter is specified, use that language exclusively
            if let Some(files) = files_by_language.get(filter_lang) {
                for file_path in files {
                    self.analyze_file_for_imports_exports(
                        file_path,
                        filter_lang,
                        &rule_deduplicator,
                    )?;
                }
            }
        } else {
            // Original fallback logic: process JavaScript and Python files
            for (language, files) in files_by_language {
                if language == "javascript" || language == "python" {
                    for file_path in files {
                        self.analyze_file_for_imports_exports(
                            file_path,
                            language,
                            &rule_deduplicator,
                        )?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Analyze a single file for imports, exports, and taint sources/sinks - ENHANCED with better debugging
    fn analyze_file_imports_exports(
        &mut self,
        filepath: &str,
        source: &[u8],
        tree: &tree_sitter::Tree,
        rule_deduplicator: &TaintRuleDeduplicator,
        _language_support: &dyn crate::language::LanguageSupport,
    ) {
        let mut imports =
            FileImports { functions: std::collections::BTreeMap::new(), taint_sinks: Vec::new() };

        // Collect all relevant nodes with error handling
        let mut all_nodes = Vec::new();
        ScanningLogic::collect_all_relevant_nodes(tree.root_node(), &mut all_nodes, Some(source));

        for node in all_nodes {
            // Safely extract node text to avoid panics
            let node_text = crate::parser::get_node_text(&node, source);

            let line = node.start_position().row + 1;
            let func_name = crate::scanner::utils::AstUtils::get_function_context(&node, source);

            // Skip string literals and metadata
            if node_text.trim().starts_with('"')
                || node_text.trim().starts_with("'")
                || node_text.contains("__all__")
                || node_text.contains("__version__")
            {
                continue;
            }

            // Check for imports
            if let Some(import_list) = Self::extract_import_info(&node_text) {
                for (func_name, module_name) in import_list {
                    // Convert module name to full file path to match export keys
                    let module_file_path = if module_name.ends_with(".py") {
                        module_name
                    } else {
                        // Convert module_a -> tests/test_files/accuracy_tests/cross_file/module_a.py
                        let base_dir = std::path::Path::new(filepath)
                            .parent()
                            .unwrap_or(std::path::Path::new(""));
                        let module_file = format!("{}.py", module_name);
                        base_dir.join(module_file).to_string_lossy().to_string()
                    };

                    imports.functions.insert(func_name, module_file_path);
                }
            }

            // Check for taint sinks (eval, exec, os.system, etc.)
            if let Some(sink_pattern) =
                Self::extract_taint_sink_pattern(&node, source, rule_deduplicator)
            {
                // Extract variables from function call arguments.
                // `extract_all_variables` sorts+dedups its result, so `.first()`
                // would return the lexicographically smallest name rather than the
                // tainted argument (e.g. `subprocess.run(["sh","-c",cmd])` or
                // `os.system(prefix + cmd)` could record the wrong variable).
                // Record one sink per used variable so the data-flow tracer can
                // check every argument — the tainted one is never dropped by sort
                // order. This mirrors the "check ANY used variable" handling in the
                // single-file sink analysis above.
                let used_variables = CommonUtils::extract_all_variables(&node_text);
                for used_variable in used_variables {
                    imports.taint_sinks.push(TaintSinkInfo {
                        function: func_name.clone(),
                        line,
                        pattern: sink_pattern.clone(),
                        used_variable,
                    });
                }
            }
        }

        self.file_imports.insert(filepath.to_string(), imports);
    }

    /// Extract taint sink pattern by analyzing the node more intelligently - FIXED for context awareness
    fn extract_taint_sink_pattern(
        node: &tree_sitter::Node,
        source: &[u8],
        rule_deduplicator: &TaintRuleDeduplicator,
    ) -> Option<String> {
        let node_text = crate::parser::get_node_text(node, source);
        log::debug!("[EXTRACT_SINK] Node kind: '{}', text: '{}'", node.kind(), node_text);

        // Skip string literals and other non-code nodes
        if node.kind() == "string" || node.kind() == "string_literal" {
            log::debug!("[EXTRACT_SINK] Skipping string literal");
            return None;
        }

        // For call nodes, extract the function name
        if node.kind() == "call" {
            if let Some(func_name) =
                crate::scanner::utils::AstUtils::extract_function_name(node, source)
            {
                log::debug!("[EXTRACT_SINK] Call node with function: '{}'", func_name);
                // Check if this function name matches any taint sink patterns
                for pattern in &rule_deduplicator.sink_patterns {
                    if Self::function_matches_pattern(&func_name, pattern) {
                        log::debug!(
                            "[EXTRACT_SINK] Function '{}' matched sink pattern: '{}'",
                            func_name,
                            pattern
                        );
                        return Some(pattern.clone());
                    }
                }
                log::debug!("[EXTRACT_SINK] Function '{}' matched no sink patterns", func_name);
            } else {
                log::debug!("[EXTRACT_SINK] Could not extract function name from call node");
            }
        }

        // For expression nodes, check the full expression
        if node.kind() == "expression_statement" || node.kind() == "binary_expression" {
            log::debug!(
                "[EXTRACT_SINK] Checking expression node against {} patterns",
                rule_deduplicator.sink_patterns.len()
            );
            for pattern in &rule_deduplicator.sink_patterns {
                if CommonUtils::matches_taint_pattern_in_context(
                    pattern,
                    &node_text,
                    node.kind(),
                    "expression",
                ) {
                    log::debug!(
                        "[EXTRACT_SINK] Expression '{}' matched sink pattern: '{}'",
                        node_text,
                        pattern
                    );
                    return Some(pattern.clone());
                }
            }
            log::debug!("[EXTRACT_SINK] Expression '{}' matched no sink patterns", node_text);
        }

        log::debug!("[EXTRACT_SINK] No patterns matched for node");
        None
    }

    /// Check if a function name matches a taint pattern
    fn function_matches_pattern(func_name: &str, pattern: &str) -> bool {
        // Clean up the pattern to extract just the function name
        let clean_pattern =
            pattern.replace("\\(", "").replace("\\)", "").replace("\\.", ".").replace("\\\\", "\\");

        log::debug!(
            "[FUNC_MATCH] Checking function '{}' against pattern '{}' (clean: '{}')",
            func_name,
            pattern,
            clean_pattern
        );

        // Check if the function name matches the pattern
        if clean_pattern.contains(func_name) {
            log::debug!(
                "[FUNC_MATCH] Match via contains: '{}' contains '{}'",
                clean_pattern,
                func_name
            );
            return true;
        }

        // Handle patterns like "os\\.system" -> "os.system"
        if clean_pattern.contains(".") && func_name.contains(".") && clean_pattern == func_name {
            log::debug!(
                "[FUNC_MATCH] Match via exact dot notation: '{}' == '{}'",
                clean_pattern,
                func_name
            );
            return true;
        }

        // Handle patterns like "eval\\(" -> "eval"
        if clean_pattern.ends_with(func_name) {
            log::debug!(
                "[FUNC_MATCH] Match via ends_with: '{}' ends with '{}'",
                clean_pattern,
                func_name
            );
            return true;
        }

        log::debug!(
            "[FUNC_MATCH] No match: '{}' vs pattern '{}' (clean: '{}')",
            func_name,
            pattern,
            clean_pattern
        );
        false
    }

    /// Extract import information from node text - FIXED for multi-line imports and parentheses
    /// Parse `from module import a, b, c` into `[(name, module), ...]`, skipping quoted or
    /// `__all__`-style entries. Empty when `trimmed_text` isn't a `from ... import ...` line.
    fn parse_from_import(trimmed_text: &str) -> Vec<(String, String)> {
        let mut imports = Vec::new();
        if !(trimmed_text.starts_with("from ") && trimmed_text.contains(" import ")) {
            return imports;
        }
        let Some(from_start) = trimmed_text.find("from ") else {
            return imports;
        };
        let Some(import_start) = trimmed_text.find(" import ") else {
            return imports;
        };

        let module_part = trimmed_text[from_start + 5..import_start].trim();
        let import_part = trimmed_text[import_start + 8..].trim();

        // Clean up import part - remove parentheses and newlines
        let cleaned_import_part = import_part.replace(['(', ')'], "").replace(['\n', '\r'], " ");

        // Handle multiple imports: "from module import func1, func2"
        for import in cleaned_import_part.split(',') {
            let func_name = import.trim();
            if !func_name.is_empty()
                && !func_name.starts_with('"')
                && !func_name.starts_with('\'')
                && !func_name.contains("__")
            {
                // Skip __all__ etc
                imports.push((func_name.to_string(), module_part.to_string()));
            }
        }
        imports
    }

    /// Parse `import module` (module-level import, no `from`) into `[(module, module)]`. Empty
    /// when `trimmed_text` isn't a bare `import ...` line.
    fn parse_bare_import(trimmed_text: &str) -> Vec<(String, String)> {
        if !trimmed_text.starts_with("import ") || trimmed_text.contains(" from ") {
            return Vec::new();
        }
        let module_part = trimmed_text[7..].trim();
        if module_part.is_empty() || module_part.starts_with('"') || module_part.starts_with('\'') {
            return Vec::new();
        }
        // For module imports, we'll track the module name itself
        vec![(module_part.to_string(), module_part.to_string())]
    }

    fn extract_import_info(text: &str) -> Option<Vec<(String, String)>> {
        let trimmed_text = text.trim();

        // Only parse actual import statements, not string literals
        let mut imports = Self::parse_from_import(trimmed_text);
        // Handle "import module" pattern (for module-level imports)
        imports.extend(Self::parse_bare_import(trimmed_text));

        if imports.is_empty() { None } else { Some(imports) }
    }
}
