#![allow(clippy::too_many_arguments, clippy::large_enum_variant, clippy::needless_range_loop)]

use crate::common::CommonUtils;
use crate::scanner::ast_provenance;
use crate::scanner::flow_tracker::{TaintVariableInfo, VariableFlowTracker};
use crate::scanner::scan_context::{EnhancedSearchContext, SinkSite, TaintScanContext};
use crate::scanner::taint_utils::{TaintExpressionUtils, TaintRuleDeduplicator};

pub struct ScanningLogic;

impl ScanningLogic {
    pub fn check_rule_against_node(
        rule: &crate::rules::UnifiedRule,
        node: &tree_sitter::Node,
        source: &[u8],
        filepath: &str,
        func_name: &str,
        language_support: &dyn crate::language::LanguageSupport,
    ) -> Option<crate::models::Finding> {
        let pattern_matches = if Self::rule_needs_full_context(rule) {
            let node_text = crate::parser::get_node_text(node, source);
            crate::rules::rule_matches_pattern_unified(rule, &node_text)
        } else {
            crate::rules::rule_matches_pattern_unified(rule, func_name)
        };

        if !pattern_matches {
            return None;
        }

        if !crate::scanner::utils::rule_applies_to_file(rule.file_types.as_ref(), filepath) {
            return None;
        }

        if let Some(conditions) = &rule.conditions {
            if !crate::scanner::conditions::check_ast_conditions(
                conditions,
                node,
                source,
                language_support,
            ) {
                return None;
            }
        }

        if language_support.name() == "javascript" || language_support.name() == "typescript" {
            let node_text = crate::parser::get_node_text(node, source);
            if !Self::should_apply_rule_with_sanitization(rule, &node_text) {
                return None;
            }
        }

        if Self::should_check_injection_patterns(rule)
            && !Self::has_injection_pattern(node, source, language_support)
        {
            return None;
        }

        let mut finding = Self::create_finding_with_rule(
            filepath,
            node,
            func_name,
            rule.get_finding_type(),
            source,
            rule.get_severity(),
            rule,
        );

        Self::add_finding_metadata(&mut finding, rule, node);

        if let Some(source_info) = Self::detect_source_pattern(node, source, language_support) {
            finding.source_info = Some(source_info);
        }

        if let Some(sink_info) =
            Self::detect_sink_pattern(node, source, func_name, rule.get_finding_type())
        {
            finding.sink_info = Some(sink_info);
        }

        Some(finding)
    }

    fn rule_needs_full_context(rule: &crate::rules::UnifiedRule) -> bool {
        const CONTEXT_INDICATORS: &[&str] = &[
            "%",
            "+",
            "DROP",
            "DELETE",
            "UNION",
            "innerHTML",
            "outerHTML",
            "location",
            "postMessage",
            "localStorage",
            "sessionStorage",
            "console.log",
            "console.debug",
            "fetch",
            "axios",
            "password",
            "token",
            "secret",
            "key",
            "http://",
            "=",
        ];

        let check_pattern = |pattern: &str| {
            CONTEXT_INDICATORS.iter().any(|indicator| pattern.contains(indicator))
                || (rule.get_category() == "database"
                    && (pattern.contains('.')
                        || pattern.contains('*')
                        || pattern.contains('(')
                        || pattern.contains("f\"")
                        || pattern.contains("f'")))
        };

        if let Some(patterns) = &rule.patterns {
            patterns.iter().any(|p| check_pattern(p))
        } else if let Some(pattern) = &rule.pattern {
            check_pattern(pattern)
        } else {
            false
        }
    }

    fn should_check_injection_patterns(rule: &crate::rules::UnifiedRule) -> bool {
        rule.get_category() == "injection"
    }
    pub fn scan_file_with_rules(
        filepath: &str,
        source: &[u8],
        tree: &tree_sitter::Tree,
        rules: &[&crate::rules::UnifiedRule],
        language_support: &dyn crate::language::LanguageSupport,
    ) -> Vec<crate::models::Finding> {
        let mut findings = Vec::new();
        let mut processed_lines = std::collections::HashSet::new();

        let call_nodes: Vec<tree_sitter::Node> =
            crate::parser::traverse_calls_only(tree.root_node(), language_support).collect();

        for node in call_nodes.iter() {
            if let Some(func_name) = language_support.get_function_name(node, source) {
                let relevant_rules: Vec<(usize, &crate::rules::UnifiedRule)> = rules
                    .iter()
                    .enumerate()
                    .filter(|(_, rule)| Self::rule_might_match_function(rule, func_name))
                    .map(|(idx, rule)| (idx, *rule))
                    .collect();

                for (_, rule) in relevant_rules {
                    if let Some(finding) = Self::check_rule_against_node(
                        rule,
                        node,
                        source,
                        filepath,
                        func_name,
                        language_support,
                    ) {
                        let line_key =
                            (finding.line, finding.function.clone(), finding.finding_type.clone());
                        if !processed_lines.contains(&line_key) {
                            processed_lines.insert(line_key);
                            findings.push(finding);
                        }
                    }
                }
            }
        }

        if language_support.name() == "javascript"
            || language_support.name() == "typescript"
            || language_support.name() == "tsx"
            || language_support.name() == "php"
        {
            Self::scan_assignments(
                tree.root_node(),
                source,
                filepath,
                rules,
                language_support,
                &mut findings,
                &mut processed_lines,
            );
        }

        findings
    }

    fn scan_assignments(
        node: tree_sitter::Node,
        source: &[u8],
        filepath: &str,
        rules: &[&crate::rules::UnifiedRule],
        language_support: &dyn crate::language::LanguageSupport,
        findings: &mut Vec<crate::models::Finding>,
        processed_lines: &mut std::collections::HashSet<(usize, String, String)>,
    ) {
        let assignment_rules: Vec<&crate::rules::UnifiedRule> =
            rules.iter().filter(|rule| Self::rule_has_assignment_patterns(rule)).copied().collect();

        if !assignment_rules.is_empty() {
            Self::scan_node_for_assignments(
                node,
                source,
                filepath,
                &assignment_rules,
                language_support,
                findings,
                processed_lines,
            );
        }
    }

    fn scan_node_for_assignments(
        node: tree_sitter::Node,
        source: &[u8],
        filepath: &str,
        assignment_rules: &[&crate::rules::UnifiedRule],
        language_support: &dyn crate::language::LanguageSupport,
        findings: &mut Vec<crate::models::Finding>,
        processed_lines: &mut std::collections::HashSet<(usize, String, String)>,
    ) {
        // Python represents assignments as `assignment` / `augmented_assignment`
        // nodes; matching them directly avoids the comparison-operator heuristic
        // below (which would reject SQL strings containing `>=` / `<=`).
        let is_definite_assignment = matches!(node.kind(), "assignment" | "augmented_assignment");

        if is_definite_assignment
            || matches!(
                node.kind(),
                "assignment_expression" | "expression_statement" | "member_expression"
            )
        {
            let node_text = crate::parser::get_node_text(&node, source);

            // Check for direct assignment patterns (e.g., element.innerHTML = value)
            if is_definite_assignment
                || CommonUtils::is_valid_assignment_text(&node_text)
                || Self::is_dom_assignment(&node_text)
            {
                let assignment_target =
                    CommonUtils::extract_variable_from_assignment(&node_text, true)
                        .unwrap_or_else(|| Self::extract_assignment_target(&node_text));

                for rule in assignment_rules {
                    if Self::rule_might_match_assignment(rule, &node_text) {
                        if let Some(finding) = Self::check_rule_against_node(
                            rule,
                            &node,
                            source,
                            filepath,
                            &assignment_target,
                            language_support,
                        ) {
                            let line_key = (
                                finding.line,
                                finding.function.clone(),
                                finding.finding_type.clone(),
                            );
                            // A call-shaped sink (e.g. subprocess.Popen(shell=True)) can be
                            // matched both by the call pass and here via its `=`-bearing
                            // pattern; the call pass records a different `function`, so also
                            // guard on (line, finding_type) to avoid a duplicate finding.
                            let already = processed_lines.contains(&line_key)
                                || findings.iter().any(|f| {
                                    f.line == finding.line && f.finding_type == finding.finding_type
                                });
                            if !already {
                                processed_lines.insert(line_key);
                                findings.push(finding);
                            }
                        }
                    }
                }
            }
        }

        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                Self::scan_node_for_assignments(
                    cursor.node(),
                    source,
                    filepath,
                    assignment_rules,
                    language_support,
                    findings,
                    processed_lines,
                );
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    fn rule_has_assignment_patterns(rule: &crate::rules::UnifiedRule) -> bool {
        const ASSIGNMENT_INDICATORS: &[&str] = &[
            "innerHTML",
            "outerHTML",
            "location",
            "localStorage",
            "sessionStorage",
            "__proto__",
            "=",
            "prototype",
            "src",
            "href",
            "textContent",
            "setAttribute",
            "document.write",
            "insertAdjacentHTML",
        ];

        let check_pattern = |pattern: &str| {
            ASSIGNMENT_INDICATORS.iter().any(|indicator| pattern.contains(indicator))
        };

        // Also check if this is a taint rule with sinks
        let has_taint_sinks = rule.sinks.as_ref().is_some_and(|sinks| !sinks.is_empty());

        if let Some(patterns) = &rule.patterns {
            patterns.iter().any(|p| check_pattern(p)) || has_taint_sinks
        } else if let Some(pattern) = &rule.pattern {
            check_pattern(pattern) || has_taint_sinks
        } else {
            has_taint_sinks
        }
    }

    fn rule_might_match_assignment(rule: &crate::rules::UnifiedRule, node_text: &str) -> bool {
        const ASSIGNMENT_INDICATORS: &[&str] = &[
            "innerHTML",
            "outerHTML",
            "location",
            "localStorage",
            "sessionStorage",
            "__proto__",
            "=",
            "src",
            "href",
            "textContent",
            "setAttribute",
        ];

        let check_and_match = |pattern: &str| {
            ASSIGNMENT_INDICATORS.iter().any(|indicator| pattern.contains(indicator))
                && CommonUtils::matches_rule_pattern(pattern, node_text)
        };

        // Check if this is a taint rule with sinks that match the assignment
        if let Some(sinks) = &rule.sinks {
            for sink in sinks {
                if CommonUtils::matches_rule_pattern(sink, node_text) {
                    return true;
                }
            }
        }

        if let Some(patterns) = &rule.patterns {
            patterns.iter().any(|p| check_and_match(p))
        } else if let Some(pattern) = &rule.pattern {
            check_and_match(pattern)
        } else {
            false
        }
    }

    /// Check if the text represents a DOM assignment (innerHTML, outerHTML, etc.)
    fn is_dom_assignment(text: &str) -> bool {
        const DOM_ASSIGNMENT_PATTERNS: &[&str] = &[
            ".innerHTML",
            ".outerHTML",
            ".textContent",
            ".innerText",
            ".src",
            ".href",
            ".setAttribute",
            ".insertAdjacentHTML",
        ];

        // Check for direct assignment or TypeScript casting assignment
        let has_assignment = text.contains('=') && !text.contains("==") && !text.contains("!=");
        let has_dom_property = DOM_ASSIGNMENT_PATTERNS.iter().any(|pattern| text.contains(pattern));

        has_assignment && has_dom_property
    }

    /// Extract assignment target from complex assignment expressions
    fn extract_assignment_target(text: &str) -> String {
        if let Some(eq_pos) = text.find('=') {
            let left_side = text[..eq_pos].trim();
            // For expressions like "element.innerHTML", extract "element"
            if let Some(dot_pos) = left_side.rfind('.') {
                left_side[..dot_pos].trim().to_string()
            } else {
                left_side.to_string()
            }
        } else {
            text.trim().to_string()
        }
    }

    fn detect_source_pattern(
        node: &tree_sitter::Node,
        source: &[u8],
        _language_support: &dyn crate::language::LanguageSupport,
    ) -> Option<crate::models::SourceInfo> {
        let node_text = crate::parser::get_node_text(node, source);

        const SOURCE_PATTERNS: &[(&str, &str)] = &[
            ("request", "HTTP Request"),
            ("input", "User Input"),
            ("sys.argv", "Command Line"),
            ("environ", "Environment Variable"),
            ("cookie", "HTTP Cookie"),
            ("header", "HTTP Header"),
            ("form", "Form Data"),
            ("query", "Query Parameter"),
            ("file", "File Input"),
            ("socket", "Network Socket"),
            ("subprocess", "External Process"),
            ("json.loads", "JSON Parsing"),
            ("pickle.loads", "Pickle Deserialization"),
            ("eval", "Dynamic Evaluation"),
            ("exec", "Dynamic Execution"),
        ];

        SOURCE_PATTERNS.iter().find(|(pattern, _)| node_text.contains(pattern)).map(
            |(_, source_type)| crate::models::SourceInfo {
                source_type: source_type.to_string(),
                location: format!("Line {}", node.start_position().row + 1),
                context: crate::scanner::utils::AstUtils::get_function_context(node, source),
            },
        )
    }

    fn detect_sink_pattern(
        node: &tree_sitter::Node,
        source: &[u8],
        func_name: &str,
        finding_type: &str,
    ) -> Option<crate::models::SinkInfo> {
        let node_text = crate::parser::get_node_text(node, source);
        let finding_lower = finding_type.to_lowercase();

        let sink_category = match finding_lower.as_str() {
            s if s.contains("sql") => "Database Query",
            s if s.contains("command") => "Command Execution",
            s if s.contains("path") => "File System",
            s if s.contains("xss") => "Web Output",
            _ => "General Sink",
        };

        Some(crate::models::SinkInfo {
            sink_type: sink_category.to_string(),
            function_name: func_name.to_string(),
            location: format!("Line {}", node.start_position().row + 1),
            variable: CommonUtils::extract_variable_from_pattern(&node_text),
        })
    }

    fn should_apply_rule_with_sanitization(
        rule: &crate::rules::UnifiedRule,
        node_text: &str,
    ) -> bool {
        let finding_type = rule.get_finding_type().to_lowercase();

        if finding_type.contains("xss") || finding_type.contains("dom") {
            !crate::scanner::utils::AstUtils::check_for_sanitization(node_text, "javascript")
        } else if finding_type.contains("prototype") {
            node_text.contains("__proto__")
                || node_text.contains("['__proto__']")
                || node_text.contains("[\"__proto__\"]")
        } else {
            true
        }
    }

    /// Check if a rule might match the function name (optimized pattern-based pre-filter)
    fn rule_might_match_function(rule: &crate::rules::UnifiedRule, func_name: &str) -> bool {
        let patterns_to_check = if let Some(patterns) = &rule.patterns {
            patterns.as_slice()
        } else if let Some(pattern) = &rule.pattern {
            std::slice::from_ref(pattern)
        } else {
            return false;
        };

        for pattern in patterns_to_check {
            if Self::pattern_might_match_function(pattern, func_name) {
                return true;
            }
        }

        false
    }

    fn pattern_might_match_function(pattern: &str, func_name: &str) -> bool {
        if pattern == func_name || pattern.contains(func_name) || func_name.contains(pattern) {
            return true;
        }

        if pattern.contains('*') {
            return CommonUtils::matches_unified_pattern(pattern, func_name);
        }

        // Check specific pattern matches
        const EXACT_MATCHES: &[&str] = &[
            "eval",
            "Function",
            "setTimeout",
            "setInterval",
            "fetch",
            "Math.random",
            "RegExp",
            "import",
            "require",
        ];

        const CONTAINS_MATCHES: &[&str] = &[
            "document.write",
            "console.",
            "localStorage",
            "sessionStorage",
            "postMessage",
            "axios",
        ];

        if EXACT_MATCHES.contains(&pattern) {
            func_name == pattern
        } else if CONTAINS_MATCHES.iter().any(|p| pattern.contains(p)) {
            CONTAINS_MATCHES.iter().any(|p| pattern.contains(p) && func_name.contains(p))
        } else {
            false
        }
    }

    // Public utility methods for rule access
    pub fn has_matching_rules(rules: &crate::rules::Rules, func_name: &str) -> bool {
        rules
            .get_search_rules()
            .iter()
            .any(|rule| crate::rules::rule_matches_pattern_unified(rule, func_name))
    }

    pub fn get_all_search_rules(rules: &crate::rules::Rules) -> Vec<&crate::rules::UnifiedRule> {
        rules.get_search_rules()
    }

    pub fn get_all_taint_rules(rules: &crate::rules::Rules) -> Vec<&crate::rules::UnifiedRule> {
        rules.get_taint_rules()
    }

    pub fn count_total_rules(rules: &crate::rules::Rules) -> usize {
        rules.count_rules()
    }

    // Public methods for finding creation and validation
    pub fn has_injection_pattern(
        node: &tree_sitter::Node,
        source: &[u8],
        language_support: &dyn crate::language::LanguageSupport,
    ) -> bool {
        if let Some(args_node) = language_support.get_arguments_node(node) {
            for i in 0..args_node.named_child_count() {
                if let Some(arg) = args_node.named_child(i as u32) {
                    let arg_text = crate::parser::get_node_text(&arg, source);
                    if !crate::rules::is_literal_node(&arg)
                        && crate::rules::check_for_injection_pattern(&arg_text, language_support)
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn add_finding_metadata(
        finding: &mut crate::models::Finding,
        rule: &crate::rules::UnifiedRule,
        _node: &tree_sitter::Node,
    ) {
        finding.severity = rule.get_severity().to_string();
        finding.confidence = rule.get_confidence().to_string();
        finding.description = rule.description.clone();
        finding.tags = rule.tags.clone();

        // Use CWE ID directly from rule, with fallback to tags for backward compatibility
        finding.cwe_id = rule.cwe_id.clone().or_else(|| {
            // Fallback: extract from tags if rule doesn't have cwe_id field
            if let Some(ref tags) = rule.tags {
                crate::models::Finding::extract_cwe_id_from_tags(&Some(tags.clone()))
            } else {
                None
            }
        });
    }

    pub fn create_finding(
        file: &str,
        node: &tree_sitter::Node,
        function: &str,
        finding_type: &str,
        source: &[u8],
        severity: &str,
    ) -> crate::models::Finding {
        // Try to find the most specific vulnerable line within the node
        let vulnerable_line = Self::find_vulnerable_line_in_node(node, source, finding_type, None);

        crate::models::Finding {
            file: file.to_string(),
            line: vulnerable_line,
            column: node.start_position().column + 1,
            end_line: node.end_position().row + 1,
            end_column: node.end_position().column + 1,
            function: function.to_string(),
            finding_type: finding_type.to_string(),
            severity: severity.to_string(),
            confidence: "Medium".to_string(),
            snippet: crate::parser::get_node_text(node, source),
            description: None,
            cwe_id: None,
            source_info: None,
            sink_info: None,
            traces: None,
            tags: None,
        }
    }

    pub fn create_finding_with_rule(
        file: &str,
        node: &tree_sitter::Node,
        function: &str,
        finding_type: &str,
        source: &[u8],
        severity: &str,
        rule: &crate::rules::UnifiedRule,
    ) -> crate::models::Finding {
        // Try to find the most specific vulnerable line within the node using rule sink patterns
        let vulnerable_line =
            Self::find_vulnerable_line_in_node(node, source, finding_type, Some(rule));

        crate::models::Finding {
            file: file.to_string(),
            line: vulnerable_line,
            column: node.start_position().column + 1,
            end_line: node.end_position().row + 1,
            end_column: node.end_position().column + 1,
            function: function.to_string(),
            finding_type: finding_type.to_string(),
            severity: severity.to_string(),
            confidence: "Medium".to_string(),
            snippet: crate::parser::get_node_text(node, source),
            description: None,
            cwe_id: None,
            source_info: None,
            sink_info: None,
            traces: None,
            tags: None,
        }
    }

    /// Resolve the sink patterns to search for: the rule's `sinks`/`pattern`/`patterns` if
    /// available, otherwise a hardcoded fallback keyed off the finding type (for simple search
    /// rules with no rule reference).
    fn sink_patterns_for_finding(
        finding_type: &str,
        rule: Option<&crate::rules::UnifiedRule>,
    ) -> Vec<String> {
        if let Some(rule) = rule {
            if let Some(ref sinks) = rule.sinks {
                return sinks.clone();
            }
            if let Some(ref pattern) = rule.pattern {
                return vec![pattern.clone()];
            }
            if let Some(ref patterns) = rule.patterns {
                return patterns.clone();
            }
            return vec![];
        }

        // Fallback to hardcoded patterns if no rule provided such as for simple search rule cases.
        match finding_type.to_lowercase().as_str() {
            s if s.contains("xss") || s.contains("cross-site") => vec![
                ".innerHTML".to_string(),
                ".outerHTML".to_string(),
                "document.write".to_string(),
                ".insertAdjacentHTML".to_string(),
            ],
            s if s.contains("redirect") || s.contains("open redirect") => vec![
                "window.location.href =".to_string(),
                "location.href =".to_string(),
                "location.assign(".to_string(),
                "location.replace(".to_string(),
                ".href =".to_string(),
                "window.open(".to_string(),
                ".setState(".to_string(),
            ],
            s if s.contains("injection") || s.contains("command") => vec![
                "eval(".to_string(),
                "system(".to_string(),
                "exec(".to_string(),
                "popen(".to_string(),
                "subprocess".to_string(),
            ],
            s if s.contains("sql") => vec![
                "execute(".to_string(),
                "query(".to_string(),
                "cursor.execute".to_string(),
                "db.query".to_string(),
            ],
            _ => vec![],
        }
    }

    /// Search for the first line matching one of the sink patterns.
    fn find_line_matching_sink_pattern(
        lines: &[&str],
        start_line: usize,
        sink_patterns: &[String],
    ) -> Option<usize> {
        for (line_offset, line) in lines.iter().enumerate() {
            for pattern in sink_patterns {
                // Clean pattern for matching (remove wildcards and make more flexible)
                let clean_pattern = pattern.replace("*.", "").replace("*", "").trim().to_string();
                if !clean_pattern.is_empty() && line.contains(&clean_pattern) {
                    return Some(start_line + line_offset);
                }
            }
        }
        None
    }

    /// Fallback search: the first line with an assignment operation (common vulnerability
    /// pattern), skipping comments and declarations without assignment.
    fn find_line_with_assignment(lines: &[&str], start_line: usize) -> Option<usize> {
        for (line_offset, line) in lines.iter().enumerate() {
            if line.contains('=')
                && !line.trim().starts_with("//")
                && !line.trim().starts_with("/*")
            {
                // Skip function declarations and variable declarations without assignment
                if !line.contains("function")
                    && !line.contains("def ")
                    && !line.contains("const ")
                    && !line.contains("let ")
                    && !line.contains("var ")
                {
                    return Some(start_line + line_offset);
                }
            }
        }
        None
    }

    /// Find the most specific line where the vulnerability actually occurs within a node
    fn find_vulnerable_line_in_node(
        node: &tree_sitter::Node,
        source: &[u8],
        finding_type: &str,
        rule: Option<&crate::rules::UnifiedRule>,
    ) -> usize {
        let node_text = crate::parser::get_node_text(node, source);
        let lines: Vec<&str> = node_text.lines().collect();
        let start_line = node.start_position().row + 1;

        let sink_patterns = Self::sink_patterns_for_finding(finding_type, rule);

        if let Some(line) =
            Self::find_line_matching_sink_pattern(&lines, start_line, &sink_patterns)
        {
            return line;
        }
        // If no specific sink pattern found, look for assignment operations (common vulnerability pattern)
        if let Some(line) = Self::find_line_with_assignment(&lines, start_line) {
            return line;
        }
        // Fallback to the original node start line
        start_line
    }

    /// If `node` is a function definition, mark any parameters matching a taint source pattern
    /// as tainted.
    fn track_function_parameter_sources(
        node: &tree_sitter::Node,
        ctx: &TaintScanContext,
        line: usize,
        func_name: &str,
        flow_tracker: &mut VariableFlowTracker,
    ) {
        log::debug!(
            "[FUNCTION_CHECK] Checking node kind '{}' for function definitions",
            node.kind()
        );
        if !matches!(
            node.kind(),
            "function_definition"
                | "function_declaration"
                | "method_definition"
                | "arrow_function"
                | "function_expression"
                | "generator_function"
                | "async_function"
                | "constructor_definition"
        ) {
            return;
        }

        log::debug!("[FUNCTION_PARAM_ANALYSIS] Found function definition: {}", node.kind());
        let Some(params) = Self::extract_function_parameters(node, ctx.source) else {
            log::debug!("[FUNCTION_PARAM_ANALYSIS] No parameters extracted from function");
            return;
        };
        log::debug!("[FUNCTION_PARAM_ANALYSIS] Extracted parameters: {:?}", params);
        for param in params {
            // Check if parameter name matches any taint source pattern
            log::debug!(
                "[FUNCTION_PARAM_ANALYSIS] Checking parameter '{}' against source patterns",
                param
            );
            if let Some(source_pattern) = ctx.rule_deduplicator.matches_source_pattern(&param) {
                log::debug!(
                    "[FUNCTION_PARAM_ANALYSIS] Function parameter '{}' matches source pattern '{}'",
                    param,
                    source_pattern
                );
                flow_tracker.record_tainted_variable(
                    param.clone(),
                    TaintVariableInfo {
                        source_line: line,
                        source_pattern,
                        source_function: func_name.to_string(),
                        assignment_code: format!("function parameter: {}", param),
                    },
                );
            } else {
                log::debug!("[FUNCTION_PARAM_ANALYSIS] Function parameter '{}' does not match any source pattern", param);
            }
        }
    }

    /// If `node_text` is an assignment whose value matches a taint source pattern (and isn't
    /// sanitized), mark the assigned variable as tainted.
    fn track_assignment_source(
        node_text: &str,
        line: usize,
        func_name: &str,
        ctx: &TaintScanContext,
        flow_tracker: &mut VariableFlowTracker,
    ) {
        if !CommonUtils::is_valid_assignment_text(node_text) {
            return;
        }
        let Some(var_name) = Self::extract_taint_assignment_target(node_text)
            .or_else(|| CommonUtils::extract_variable_from_assignment(node_text, false))
        else {
            return;
        };
        // Extract the right side of assignment for source matching
        let Some(eq_pos) = node_text.find('=') else {
            return;
        };
        let assignment_value = node_text[eq_pos + 1..].trim();
        log::debug!(
            "[ASSIGNMENT_ANALYSIS] Processing assignment '{}' -> checking value '{}'",
            node_text,
            assignment_value
        );

        // Check if the assignment value matches any taint source
        let Some(source_pattern) = ctx.rule_deduplicator.matches_source_pattern(assignment_value)
        else {
            log::debug!(
                "[ASSIGNMENT_ANALYSIS] Assignment value '{}' does not match any source patterns",
                assignment_value
            );
            return;
        };

        if TaintExpressionUtils::expression_has_any_sanitizer(
            ctx.applicable_rules,
            assignment_value,
        ) {
            log::debug!(
                "[ASSIGNMENT_ANALYSIS] Assignment value '{}' contains sanitizer; not recording taint",
                assignment_value
            );
            return;
        }

        log::debug!(
            "[ASSIGNMENT_ANALYSIS] Assignment value '{}' matches source pattern '{}'",
            assignment_value,
            source_pattern
        );
        flow_tracker.record_tainted_variable(
            var_name,
            TaintVariableInfo {
                source_line: line,
                source_pattern,
                source_function: func_name.to_string(),
                assignment_code: node_text.to_string(),
            },
        );
    }

    /// If `node_text` contains a detectable taint-propagation operation (and isn't sanitized),
    /// record it and, when a dependent variable is already tainted, propagate that taint to the
    /// target variable.
    fn propagate_taint_for_node(
        node_text: &str,
        func_name: &str,
        ctx: &TaintScanContext,
        flow_tracker: &mut VariableFlowTracker,
    ) {
        if TaintExpressionUtils::expression_has_any_sanitizer(ctx.applicable_rules, node_text) {
            return;
        }
        let Some((target_var, dependent_vars)) = Self::detect_taint_propagation(node_text) else {
            return;
        };
        log::debug!(
            "[TAINT_PROPAGATION] Detected propagation: '{}' depends on {:?} in '{}'",
            target_var,
            dependent_vars,
            node_text
        );
        flow_tracker.record_taint_propagation(&target_var, &dependent_vars);

        // Check if any dependent variables are tainted and propagate to target
        for dep_var in &dependent_vars {
            if let Some(taint_info) = flow_tracker.is_variable_tainted(dep_var, func_name).cloned()
            {
                log::debug!(
                    "[TAINT_PROPAGATION] Propagating taint from '{}' to '{}' ({})",
                    dep_var,
                    target_var,
                    taint_info.source_pattern
                );

                // Mark target variable as tainted (inheriting from the dependent variable)
                flow_tracker.record_tainted_variable(
                    target_var.clone(),
                    TaintVariableInfo {
                        source_line: taint_info.source_line,
                        source_pattern: taint_info.source_pattern.clone(),
                        source_function: taint_info.source_function.clone(),
                        assignment_code: format!("Propagated from {} via: {}", dep_var, node_text),
                    },
                );
                break; // Only need one tainted dependency to taint the target
            }
        }
    }

    /// Phase 1 per-node step: track function-parameter and assignment taint sources, and
    /// propagate taint through detected dependency operations, for a single AST node.
    fn track_taint_sources_for_node(
        node: &tree_sitter::Node,
        ctx: &TaintScanContext,
        flow_tracker: &mut VariableFlowTracker,
    ) {
        let node_text = crate::parser::get_node_text(node, ctx.source);
        let line = node.start_position().row + 1;
        let func_name = crate::scanner::utils::AstUtils::get_function_context(node, ctx.source);

        Self::track_function_parameter_sources(node, ctx, line, &func_name, flow_tracker);
        if ast_provenance::is_python_source(ctx.filepath) {
            Self::track_python_assignment_source(
                node,
                &node_text,
                line,
                &func_name,
                ctx,
                flow_tracker,
            );
        } else {
            Self::track_assignment_source(&node_text, line, &func_name, ctx, flow_tracker);
        }
        Self::propagate_taint_for_node(&node_text, &func_name, ctx, flow_tracker);
    }

    /// Python phase-1 assignment tracking: record assignment-borne taint only
    /// from real assignment AST nodes, extracted structurally. Text that only
    /// looks like an assignment (docstrings, string literals) records nothing,
    /// while annotated, augmented, chained, tuple, multiline, and
    /// subscript-target assignments — which the text scan cannot parse — plus
    /// collection-mutating method calls (`x.append(source)`) are all covered.
    /// Assignment nodes whose target shape yields no structural facts (e.g.
    /// attribute targets like `self.cmd = ...`) fall back to the text tracker
    /// so its coverage is never lost.
    fn track_python_assignment_source(
        node: &tree_sitter::Node,
        node_text: &str,
        line: usize,
        func_name: &str,
        ctx: &TaintScanContext,
        flow_tracker: &mut VariableFlowTracker,
    ) {
        // Mutating a collection with tainted data taints the collection:
        // `parts.append(input())` taints `parts`. Handled here because a method
        // call is not an assignment node.
        if node.kind() == "call" {
            if let Some((base, args)) =
                ast_provenance::collection_mutation_target(*node, ctx.source)
            {
                Self::record_python_taint_if_source(
                    &base,
                    &args,
                    line,
                    func_name,
                    node_text,
                    ctx,
                    flow_tracker,
                );
            }
            return;
        }

        let facts = match node.kind() {
            "assignment" | "augmented_assignment" => {
                ast_provenance::assignment_facts_for_node(*node, ctx.source)
            }
            // Augmented assignments are not collected as standalone nodes, so
            // pull them out of their statement wrapper here.
            "expression_statement" => {
                ast_provenance::augmented_facts_in_statement(*node, ctx.source)
            }
            _ => return,
        };

        // A real assignment node whose target shape the AST extraction does not
        // model (e.g. an attribute target: `self.cmd = input()`) must keep the
        // text tracker's coverage — dropping it silently would lose taint the
        // text scan used to record. Guarded to assignment nodes so plain
        // expression statements (docstrings, string literals) still record
        // nothing.
        if facts.is_empty() && matches!(node.kind(), "assignment" | "augmented_assignment") {
            Self::track_assignment_source(node_text, line, func_name, ctx, flow_tracker);
            return;
        }

        for fact in facts {
            Self::record_python_taint_if_source(
                &fact.target,
                &fact.rhs,
                line,
                func_name,
                node_text,
                ctx,
                flow_tracker,
            );
        }
    }

    /// Record `target` as tainted when `rhs` matches a source pattern and is not
    /// sanitized. Shared by the assignment and collection-mutation paths.
    fn record_python_taint_if_source(
        target: &str,
        rhs: &str,
        line: usize,
        func_name: &str,
        node_text: &str,
        ctx: &TaintScanContext,
        flow_tracker: &mut VariableFlowTracker,
    ) {
        let Some(source_pattern) = ctx.rule_deduplicator.matches_source_pattern(rhs) else {
            return;
        };
        if TaintExpressionUtils::expression_has_any_sanitizer(ctx.applicable_rules, rhs) {
            return;
        }
        log::debug!(
            "[ASSIGNMENT_ANALYSIS] AST source '{}' matches pattern '{}' -> taint '{}'",
            rhs,
            source_pattern,
            target
        );
        flow_tracker.record_tainted_variable(
            target.to_string(),
            TaintVariableInfo {
                source_line: line,
                source_pattern,
                source_function: func_name.to_string(),
                assignment_code: node_text.to_string(),
            },
        );
    }

    /// Extract the variables referenced in a sink expression: PHP-specific `$var` extraction
    /// for PHP, the generic extractor otherwise. Deduplicated and sorted.
    fn extract_sink_variables(node_text: &str, ctx: &TaintScanContext) -> Vec<String> {
        let mut used_variables = if ctx.language_support.name() == "php" {
            TaintExpressionUtils::extract_php_variables(node_text)
        } else {
            CommonUtils::extract_all_variables(node_text)
        };
        used_variables.sort();
        used_variables.dedup();
        used_variables
    }

    /// If the sink node's own expression text also matches a taint source pattern (a "bare
    /// call" source used directly as a sink argument, e.g. `execute(input())`), record a
    /// same-expression taint finding.
    fn check_bare_call_source_sink(
        node: &tree_sitter::Node,
        site: &SinkSite,
        ctx: &TaintScanContext,
        flow_tracker: &mut VariableFlowTracker,
        used_variables: &[String],
        findings: &mut Vec<crate::models::Finding>,
    ) {
        if used_variables.is_empty() || !Self::is_actionable_sink_node(node.kind()) {
            return;
        }
        let Some(source_pattern) = ctx.rule_deduplicator.matches_source_pattern(site.node_text)
        else {
            return;
        };
        let Some(rule) =
            ctx.rule_deduplicator.get_rule_for_combination(&source_pattern, site.sink_pattern)
        else {
            return;
        };
        if TaintExpressionUtils::expression_has_sanitizer(rule, site.node_text) {
            return;
        }
        if flow_tracker.is_flow_processed(site.line, &source_pattern, site.sink_pattern) {
            return;
        }
        flow_tracker.mark_flow_processed(site.line, &source_pattern, site.sink_pattern);

        let taint_source = crate::models::TaintSource {
            file: site.filepath.to_string(),
            line: site.line,
            function: site.func_name.to_string(),
            variable: source_pattern.clone(),
            operation: source_pattern.clone(),
            code: site.node_text.to_string(),
            branch_id: None,
        };
        let taint_sink = crate::models::TaintSink {
            file: site.filepath.to_string(),
            line: site.line,
            function: site.func_name.to_string(),
            variable: source_pattern.clone(),
            operation: site.sink_pattern.to_string(),
            code: site.node_text.to_string(),
            branch_id: None,
        };
        findings.push(Self::create_taint_finding(
            &taint_source,
            &taint_sink,
            rule,
            ctx.tree,
            ctx.source,
        ));
    }

    /// For each already-tainted variable used in the sink, record a finding when there's a
    /// legitimate source-sink rule for it and it isn't sanitized or already processed.
    fn collect_tainted_variable_sink_findings(
        site: &SinkSite,
        ctx: &TaintScanContext,
        used_variables: &[String],
        flow_tracker: &mut VariableFlowTracker,
        findings: &mut Vec<crate::models::Finding>,
    ) {
        for used_variable in used_variables {
            let Some(taint_info) =
                flow_tracker.is_variable_tainted(used_variable, site.func_name).cloned()
            else {
                continue;
            };
            let Some(rule) = ctx
                .rule_deduplicator
                .get_rule_for_combination(&taint_info.source_pattern, site.sink_pattern)
            else {
                continue;
            };
            if TaintExpressionUtils::expression_has_sanitizer(rule, site.node_text) {
                log::debug!(
                    "[SANITIZER_CHECK] Skipping finding due to sanitization: '{}'",
                    site.node_text
                );
                continue; // Skip this finding as it's sanitized
            }
            if flow_tracker.is_flow_processed(
                site.line,
                &taint_info.source_pattern,
                site.sink_pattern,
            ) {
                continue;
            }
            flow_tracker.mark_flow_processed(
                site.line,
                &taint_info.source_pattern,
                site.sink_pattern,
            );

            let taint_source = crate::models::TaintSource {
                file: site.filepath.to_string(),
                line: taint_info.source_line,
                function: taint_info.source_function.clone(),
                variable: used_variable.clone(),
                operation: taint_info.source_pattern.clone(),
                code: taint_info.assignment_code.clone(),
                branch_id: None,
            };
            let taint_sink = crate::models::TaintSink {
                file: site.filepath.to_string(),
                line: site.line,
                function: site.func_name.to_string(),
                variable: used_variable.clone(),
                operation: site.sink_pattern.to_string(),
                code: site.node_text.to_string(),
                branch_id: None,
            };
            findings.push(Self::create_taint_finding(
                &taint_source,
                &taint_sink,
                rule,
                ctx.tree,
                ctx.source,
            ));
        }
    }

    /// Phase 2 per-node step: if this node is a sink, check both a direct "bare call" source
    /// used inline and any already-tainted variables it references, recording findings for
    /// legitimate, unsanitized, not-yet-processed source-sink flows.
    fn collect_taint_sink_findings_for_node(
        node: &tree_sitter::Node,
        ctx: &TaintScanContext,
        flow_tracker: &mut VariableFlowTracker,
        findings: &mut Vec<crate::models::Finding>,
    ) {
        let node_text = crate::parser::get_node_text(node, ctx.source);
        let line = node.start_position().row + 1;
        let func_name = crate::scanner::utils::AstUtils::get_function_context(node, ctx.source);

        // Check if this node matches any sink pattern
        let Some(sink_pattern) = ctx.rule_deduplicator.matches_sink_pattern(&node_text) else {
            return;
        };
        log::debug!(
            "[SINK_ANALYSIS] Found sink '{}' with pattern '{}' at line {}",
            node_text,
            sink_pattern,
            line
        );
        // Extract ALL variables used in this sink (enhanced extraction)
        let used_variables = Self::extract_sink_variables(&node_text, ctx);
        log::debug!("[SINK_ANALYSIS] Extracted variables from sink: {:?}", used_variables);

        let site = SinkSite {
            node_text: &node_text,
            filepath: ctx.filepath,
            line,
            func_name: &func_name,
            sink_pattern: &sink_pattern,
        };

        Self::check_bare_call_source_sink(
            node,
            &site,
            ctx,
            flow_tracker,
            &used_variables,
            findings,
        );

        // Check if ANY of these variables are tainted
        Self::collect_tainted_variable_sink_findings(
            &site,
            ctx,
            &used_variables,
            flow_tracker,
            findings,
        );
    }

    /// Scan file with taint analysis rules (fixed implementation with proper flow tracking)
    pub fn scan_file_with_taint_rules(
        filepath: &str,
        source: &[u8],
        tree: &tree_sitter::Tree,
        taint_rules: &[&crate::rules::UnifiedRule],
        language_support: &dyn crate::language::LanguageSupport,
    ) -> Vec<crate::models::Finding> {
        let mut findings = Vec::new();

        // Filter out rules that don't apply to this file (same as search rules)
        let applicable_rules: Vec<&crate::rules::UnifiedRule> = taint_rules
            .iter()
            .filter(|rule| {
                crate::scanner::utils::rule_applies_to_file(rule.file_types.as_ref(), filepath)
            })
            .copied()
            .collect();

        // If no rules apply to this file, return empty findings
        if applicable_rules.is_empty() {
            return findings;
        }

        // Create rule deduplicator to prevent cartesian product problems
        let rule_deduplicator = TaintRuleDeduplicator::new(&applicable_rules);

        // Create variable flow tracker for legitimate flows only
        let mut flow_tracker = VariableFlowTracker::new();

        // Use broader traversal to include assignment statements
        let mut all_nodes = Vec::new();
        Self::collect_all_relevant_nodes(tree.root_node(), &mut all_nodes, None);

        let ctx = TaintScanContext {
            source,
            filepath,
            tree,
            language_support,
            applicable_rules: &applicable_rules,
            rule_deduplicator: &rule_deduplicator,
        };

        // Phase 1: Track variable assignments from taint sources
        for node in all_nodes.iter() {
            Self::track_taint_sources_for_node(node, &ctx, &mut flow_tracker);
        }

        // Phase 2: Find sinks that use tainted variables
        for node in all_nodes.iter() {
            Self::collect_taint_sink_findings_for_node(
                node,
                &ctx,
                &mut flow_tracker,
                &mut findings,
            );
        }
        findings
    }

    /// Detect taint propagation in expressions
    /// Assignment right-hand-side propagation via an f-string/template literal, e.g.
    /// `query = f"SELECT {username}"`.
    fn detect_fstring_assignment_propagation(
        left_side: &str,
        right_side: &str,
    ) -> Option<(String, Vec<String>)> {
        if !(right_side.contains('{') && right_side.contains('}')) {
            return None;
        }
        log::debug!("   Right side contains f-string braces");
        let mut dependent_vars = CommonUtils::extract_f_string_variables(right_side);

        // Also check for JavaScript/TypeScript template literals
        if right_side.contains("${") {
            log::debug!("   Right side contains template literal interpolation");
            dependent_vars.extend(CommonUtils::extract_template_literal_variables(right_side));
        }

        log::debug!("   Extracted dependent_vars from interpolation: {:?}", dependent_vars);
        if dependent_vars.is_empty() || !CommonUtils::is_valid_variable_name(left_side) {
            return None;
        }
        log::debug!(
            "[PROPAGATION_CHECK] Template/F-string assignment propagation detected: '{}' depends on {:?}",
            left_side,
            dependent_vars
        );
        Some((left_side.to_string(), dependent_vars))
    }

    /// Assignment right-hand-side propagation via a `.format(...)` call.
    fn detect_format_assignment_propagation(
        left_side: &str,
        right_side: &str,
    ) -> Option<(String, Vec<String>)> {
        if !right_side.contains(".format(") {
            return None;
        }
        log::debug!("   Right side contains .format( pattern");
        let dependent_vars = CommonUtils::extract_format_variables(right_side);
        log::debug!("   Extracted dependent_vars from format: {:?}", dependent_vars);
        if dependent_vars.is_empty() || !CommonUtils::is_valid_variable_name(left_side) {
            return None;
        }
        log::debug!(
            "[PROPAGATION_CHECK] Format assignment propagation detected: '{}' depends on {:?}",
            left_side,
            dependent_vars
        );
        Some((left_side.to_string(), dependent_vars))
    }

    /// Fallback assignment propagation: any variables referenced on the right-hand side
    /// (other than the target itself) taint the target.
    fn detect_generic_assignment_propagation(
        left_side: &str,
        right_side: &str,
    ) -> Option<(String, Vec<String>)> {
        let target_var = TaintExpressionUtils::normalize_variable(left_side);
        let mut dependent_vars = CommonUtils::extract_all_variables(right_side);
        dependent_vars.extend(TaintExpressionUtils::extract_php_variables(right_side));
        dependent_vars.retain(|var| var != &target_var);
        dependent_vars.sort();
        dependent_vars.dedup();

        if target_var.is_empty() || dependent_vars.is_empty() {
            return None;
        }
        log::debug!(
            "[PROPAGATION_CHECK] Assignment propagation detected: '{}' depends on {:?}",
            target_var,
            dependent_vars
        );
        Some((target_var, dependent_vars))
    }

    /// Detect propagation via an assignment (e.g. `query = f"SELECT {username}"`), trying the
    /// f-string/template, `.format(...)`, and generic-reference cases in turn.
    fn detect_assignment_propagation(node_text: &str) -> Option<(String, Vec<String>)> {
        if !node_text.contains('=') || node_text.contains("==") {
            return None;
        }
        let eq_pos = node_text.find('=')?;
        let left_side = node_text[..eq_pos].trim();
        let right_side = node_text[eq_pos + 1..].trim();

        log::debug!("   Found assignment: '{}' = '{}'", left_side, right_side);

        Self::detect_fstring_assignment_propagation(left_side, right_side)
            .or_else(|| Self::detect_format_assignment_propagation(left_side, right_side))
            .or_else(|| Self::detect_generic_assignment_propagation(left_side, right_side))
    }

    /// Detect simple (non-assignment) f-string propagation, e.g. a sink call built directly
    /// from an f-string/template literal referencing tainted variables.
    fn detect_direct_fstring_propagation(node_text: &str) -> Option<(String, Vec<String>)> {
        if !node_text.contains('{') || !node_text.contains('}') {
            return None;
        }
        log::debug!("   Found f-string pattern with braces (non-assignment)");
        let source_var = Self::extract_direct_variable(node_text)?;
        let dependent_vars = CommonUtils::extract_f_string_variables(node_text);
        log::debug!(
            "   Extracted source_var: '{}', dependent_vars: {:?}",
            source_var,
            dependent_vars
        );
        if dependent_vars.is_empty() {
            return None;
        }
        log::debug!("[PROPAGATION_CHECK] F-string propagation detected");
        Some((source_var, dependent_vars))
    }

    /// Detect simple (non-assignment) `.format(...)` propagation.
    fn detect_direct_format_propagation(node_text: &str) -> Option<(String, Vec<String>)> {
        if !node_text.contains(".format(") {
            return None;
        }
        log::debug!("   Found .format( pattern (non-assignment)");
        let source_var = Self::extract_direct_variable(node_text)?;
        let dependent_vars = CommonUtils::extract_format_variables(node_text);
        log::debug!(
            "   Extracted source_var: '{}', dependent_vars: {:?}",
            source_var,
            dependent_vars
        );
        if dependent_vars.is_empty() {
            return None;
        }
        log::debug!("[PROPAGATION_CHECK] Format propagation detected");
        Some((source_var, dependent_vars))
    }

    /// Detect taint propagation in expressions
    fn detect_taint_propagation(node_text: &str) -> Option<(String, Vec<String>)> {
        log::debug!("[PROPAGATION_CHECK] Checking for taint propagation in: '{}'", node_text);

        let result = Self::detect_assignment_propagation(node_text)
            .or_else(|| Self::detect_direct_fstring_propagation(node_text))
            .or_else(|| Self::detect_direct_format_propagation(node_text));

        if result.is_none() {
            log::debug!("[PROPAGATION_CHECK] No propagation detected");
        }
        result
    }

    fn extract_taint_assignment_target(node_text: &str) -> Option<String> {
        let eq_pos = node_text.find('=')?;
        let left_side = node_text[..eq_pos].trim();
        let variable = TaintExpressionUtils::normalize_variable(left_side);
        (!variable.is_empty()).then_some(variable)
    }

    fn is_actionable_sink_node(node_kind: &str) -> bool {
        node_kind == "call"
            || node_kind == "expression_statement"
            || node_kind.contains("call_expression")
            || node_kind.contains("invocation")
    }

    /// Extract direct variable from simple expressions
    fn extract_direct_variable(expr: &str) -> Option<String> {
        let trimmed = expr.trim();
        log::debug!("[EXTRACT_DIRECT] Checking if '{}' is a valid variable name", trimmed);
        if CommonUtils::is_valid_variable_name(trimmed) {
            log::debug!("[EXTRACT_DIRECT] Valid variable: '{}'", trimmed);
            return Some(trimmed.to_string());
        }
        log::debug!("[EXTRACT_DIRECT] Invalid variable: '{}'", trimmed);
        None
    }

    /// Extract function parameters from function definition node
    fn extract_function_parameters(
        func_node: &tree_sitter::Node,
        source: &[u8],
    ) -> Option<Vec<String>> {
        let mut parameters = Vec::new();
        let mut cursor = func_node.walk();

        // Look for parameter list in function definition
        if cursor.goto_first_child() {
            loop {
                let node = cursor.node();

                // Check for formal_parameters, parameter_list, or arguments
                if node.kind() == "formal_parameters"
                    || node.kind() == "parameter_list"
                    || node.kind() == "arguments"
                {
                    let mut param_cursor = node.walk();
                    if param_cursor.goto_first_child() {
                        loop {
                            let param_node = param_cursor.node();

                            // Skip punctuation like parentheses and commas
                            if param_node.kind() != "("
                                && param_node.kind() != ")"
                                && param_node.kind() != ","
                            {
                                // Handle different parameter node types
                                let param_text = match param_node.kind() {
                                    "identifier" => {
                                        // Simple parameter: function(param)
                                        crate::parser::get_node_text(&param_node, source)
                                    }
                                    "parameter" => {
                                        // TypeScript parameter: function(param: type)
                                        Self::extract_parameter_name(&param_node, source)
                                    }
                                    "required_parameter" | "optional_parameter" => {
                                        // TypeScript parameter variants
                                        Self::extract_parameter_name(&param_node, source)
                                    }
                                    _ => {
                                        // Try to extract identifier from complex parameter
                                        Self::extract_parameter_name(&param_node, source)
                                    }
                                };

                                if !param_text.is_empty()
                                    && CommonUtils::is_valid_variable_name(&param_text)
                                {
                                    parameters.push(param_text);
                                }
                            }

                            if !param_cursor.goto_next_sibling() {
                                break;
                            }
                        }
                    }
                    break;
                }

                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        if parameters.is_empty() {
            None
        } else {
            Some(parameters)
        }
    }

    /// Extract parameter name from complex parameter node
    fn extract_parameter_name(param_node: &tree_sitter::Node, source: &[u8]) -> String {
        let mut cursor = param_node.walk();

        // Look for identifier child node
        if cursor.goto_first_child() {
            loop {
                let node = cursor.node();
                if node.kind() == "identifier" {
                    return crate::parser::get_node_text(&node, source);
                }

                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        // Fallback: use the whole node text and try to extract identifier
        let full_text = crate::parser::get_node_text(param_node, source);
        if let Some(colon_pos) = full_text.find(':') {
            // TypeScript parameter with type annotation: "param: string"
            full_text[..colon_pos].trim().to_string()
        } else if let Some(equals_pos) = full_text.find('=') {
            // Parameter with default value: "param = default"
            full_text[..equals_pos].trim().to_string()
        } else {
            full_text.trim().to_string()
        }
    }

    /// Collect all relevant nodes for taint analysis (assignments and calls)
    /// Unified version that supports optional source filtering
    /// True unless the node's text is empty, a bare string literal, or an `__all__` declaration.
    fn is_relevant_node_text(node_text: &str) -> bool {
        !node_text.trim().is_empty()
            && !node_text.starts_with('"')
            && !node_text.starts_with('\'')
            && !node_text.contains("__all__")
    }

    /// Whether `node` should be collected by [`Self::collect_all_relevant_nodes`], based on its
    /// kind and (when source filtering is enabled) whether its text looks like real code.
    fn should_collect_node(node: tree_sitter::Node, source: Option<&[u8]>) -> bool {
        match node.kind() {
            // Always-relevant node kinds: collect unconditionally, or filtered by source text
            // when source filtering is enabled.
            "assignment"
            | "call"
            | "expression_statement"
            | "assignment_expression"
            | "variable_declaration"
            | "lexical_declaration"
            | "variable_declarator"
            | "function_definition"
            | "function_declaration"
            | "method_definition"
            | "arrow_function"
            | "function_expression"
            | "generator_function"
            | "async_function"
            | "constructor_definition"
            | "template_literal"
            | "template_string"
            | "template_substitution" => match source {
                Some(source_bytes) => {
                    Self::is_relevant_node_text(&crate::parser::get_node_text(&node, source_bytes))
                }
                None => true,
            },
            // Only collect these additional types when doing source filtering
            "import_statement"
            | "import_from_statement"
            | "return_statement"
            | "binary_expression"
            | "identifier" => match source {
                Some(src) => Self::is_relevant_node_text(&crate::parser::get_node_text(&node, src)),
                None => false,
            },
            // Skip string literals, comments, and metadata
            "string" | "string_literal" | "comment" | "module" => false,
            // For other node types, check if they contain actual code when source filtering is enabled
            _ => match source {
                Some(source_bytes) => {
                    Self::is_relevant_node_text(&crate::parser::get_node_text(&node, source_bytes))
                }
                None => false,
            },
        }
    }

    pub(crate) fn collect_all_relevant_nodes<'a>(
        node: tree_sitter::Node<'a>,
        nodes: &mut Vec<tree_sitter::Node<'a>>,
        source: Option<&[u8]>,
    ) {
        if Self::should_collect_node(node, source) {
            nodes.push(node);
        }

        // Recursively traverse children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                Self::collect_all_relevant_nodes(cursor.node(), nodes, source);
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    /// Create taint finding from source-sink pair (reusing existing infrastructure)
    fn create_taint_finding(
        source: &crate::models::TaintSource,
        sink: &crate::models::TaintSink,
        rule: &crate::rules::UnifiedRule,
        _tree: &tree_sitter::Tree,
        _source_bytes: &[u8],
    ) -> crate::models::Finding {
        let mut finding = crate::models::Finding {
            file: sink.file.clone(),
            line: sink.line,
            column: 0,
            end_line: sink.line,
            end_column: 0,
            function: sink.function.clone(),
            finding_type: rule.finding_type.clone().unwrap_or_else(|| "Taint Flow".to_string()),
            snippet: sink.code.clone(),
            severity: rule.severity.clone().unwrap_or_else(|| "High".to_string()),
            confidence: rule.confidence.clone().unwrap_or_else(|| "Medium".to_string()),
            description: rule.description.clone().or_else(|| {
                Some(format!(
                    "Taint flow detected from {} (line {}) to {} (line {})",
                    source.operation, source.line, sink.operation, sink.line
                ))
            }),
            cwe_id: None,
            source_info: Some(crate::models::SourceInfo {
                source_type: source.operation.clone(),
                location: format!("{}:{}", source.file, source.line),
                context: source.code.clone(),
            }),
            sink_info: Some(crate::models::SinkInfo {
                sink_type: sink.operation.clone(),
                function_name: sink.function.clone(),
                location: format!("{}:{}", sink.file, sink.line),
                variable: Some(sink.variable.clone()),
            }),
            traces: None,
            tags: Some(vec![
                "taint_analysis".to_string(),
                "data_flow".to_string(),
                rule.category.clone().unwrap_or_else(|| "injection".to_string()),
            ]),
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
}

impl ScanningLogic {
    /// Enhanced search mode that leverages taint context for sophisticated analysis
    /// This function allows search mode rules to benefit from the same contextual analysis as taint mode
    /// If `node_text` is an assignment whose value matches a taint source pattern, mark the
    /// assigned variable as tainted. (Simpler than the full taint-mode version: no function-
    /// parameter tracking, no sanitizer check -- this is only for building enhanced-search
    /// context, not for recording taint findings directly.)
    fn track_search_assignment_source(
        node_text: &str,
        line: usize,
        func_name: &str,
        rule_deduplicator: &TaintRuleDeduplicator,
        flow_tracker: &mut VariableFlowTracker,
    ) {
        if !CommonUtils::is_valid_assignment_text(node_text) {
            return;
        }
        let Some(var_name) = CommonUtils::extract_variable_from_assignment(node_text, false) else {
            return;
        };
        let Some(eq_pos) = node_text.find('=') else {
            return;
        };
        let assignment_value = node_text[eq_pos + 1..].trim();

        let Some(source_pattern) = rule_deduplicator.matches_source_pattern(assignment_value)
        else {
            return;
        };
        flow_tracker.record_tainted_variable(
            var_name,
            TaintVariableInfo {
                source_line: line,
                source_pattern,
                source_function: func_name.to_string(),
                assignment_code: node_text.to_string(),
            },
        );
    }

    /// If `node_text` contains a detectable taint-propagation operation (and isn't sanitized),
    /// record it and, when a dependent variable is already tainted, propagate that taint to the
    /// target variable.
    fn propagate_search_taint_for_node(
        node_text: &str,
        func_name: &str,
        taint_rules: &[&crate::rules::UnifiedRule],
        flow_tracker: &mut VariableFlowTracker,
    ) {
        if TaintExpressionUtils::expression_has_any_sanitizer(taint_rules, node_text) {
            return;
        }
        let Some((target_var, dependent_vars)) = ScanningLogic::detect_taint_propagation(node_text)
        else {
            return;
        };
        flow_tracker.record_taint_propagation(&target_var, &dependent_vars);

        // Check if any dependent variables are tainted and propagate to target
        for dep_var in &dependent_vars {
            if let Some(taint_info) = flow_tracker.is_variable_tainted(dep_var, func_name).cloned()
            {
                // Mark target variable as tainted (inheriting from the dependent variable)
                flow_tracker.record_tainted_variable(
                    target_var.to_string(),
                    TaintVariableInfo {
                        source_line: taint_info.source_line,
                        source_pattern: taint_info.source_pattern.clone(),
                        source_function: taint_info.source_function.clone(),
                        assignment_code: format!("Propagated from {} via: {}", dep_var, node_text),
                    },
                );
                break; // Only need one tainted dependency to taint the target
            }
        }
    }

    /// Phase 1 per-node step: build enhanced-search taint context (assignment sources and
    /// propagation) for a single AST node.
    fn build_taint_context_for_node(
        node: &tree_sitter::Node,
        source: &[u8],
        taint_rules: &[&crate::rules::UnifiedRule],
        rule_deduplicator: &TaintRuleDeduplicator,
        flow_tracker: &mut VariableFlowTracker,
    ) {
        let node_text = crate::parser::get_node_text(node, source);
        let line = node.start_position().row + 1;
        let func_name = crate::scanner::utils::AstUtils::get_function_context(node, source);

        Self::track_search_assignment_source(
            &node_text,
            line,
            &func_name,
            rule_deduplicator,
            flow_tracker,
        );
        Self::propagate_search_taint_for_node(&node_text, &func_name, taint_rules, flow_tracker);
    }

    /// Tag a finding to distinguish it as an enhanced-search result, noting whether taint
    /// context was available while checking it.
    fn apply_taint_context_tags(finding: &mut crate::models::Finding, has_taint_rules: bool) {
        if finding.tags.is_none() {
            finding.tags = Some(Vec::new());
        }
        if let Some(ref mut tags) = finding.tags {
            tags.push("enhanced_search".to_string());
            if has_taint_rules {
                tags.push("taint_context_available".to_string());
            } else {
                tags.push("taint_context_unavailable".to_string());
            }
        }
    }

    /// Phase 2 per-call-node step: check every search rule that might match this call against
    /// the node (with taint context), recording deduplicated, tagged findings.
    fn apply_search_rules_to_call_node(
        node: &tree_sitter::Node,
        ctx: &EnhancedSearchContext,
        flow_tracker: &VariableFlowTracker,
        processed_lines: &mut std::collections::HashSet<(usize, String, String)>,
        findings: &mut Vec<crate::models::Finding>,
    ) {
        let Some(func_name) = ctx.language_support.get_function_name(node, ctx.source) else {
            return;
        };
        let relevant_rules: Vec<&crate::rules::UnifiedRule> = ctx
            .applicable_search_rules
            .iter()
            .filter(|rule| ScanningLogic::rule_might_match_function(rule, func_name))
            .copied()
            .collect();

        for rule in relevant_rules {
            // Enhanced rule checking with taint context
            let Some(mut finding) = ScanningLogic::check_rule_against_node_with_taint_context(
                rule,
                node,
                ctx.source,
                ctx.filepath,
                func_name,
                ctx.language_support,
                flow_tracker,
                ctx.rule_deduplicator,
            ) else {
                continue;
            };

            let line_key = (finding.line, finding.function.clone(), finding.finding_type.clone());
            if processed_lines.contains(&line_key) {
                continue;
            }
            processed_lines.insert(line_key);

            // Add taint context tags to distinguish from basic search findings
            Self::apply_taint_context_tags(&mut finding, ctx.has_taint_rules);
            findings.push(finding);
        }
    }

    pub fn scan_file_with_rules_and_taint_context(
        filepath: &str,
        source: &[u8],
        tree: &tree_sitter::Tree,
        search_rules: &[&crate::rules::UnifiedRule],
        taint_rules: &[&crate::rules::UnifiedRule],
        language_support: &dyn crate::language::LanguageSupport,
    ) -> Vec<crate::models::Finding> {
        let mut findings = Vec::new();
        let mut processed_lines = std::collections::HashSet::new();

        // Filter search rules that don't apply to this file (same as taint rules)
        let applicable_search_rules: Vec<&crate::rules::UnifiedRule> = search_rules
            .iter()
            .filter(|rule| {
                crate::scanner::utils::rule_applies_to_file(rule.file_types.as_ref(), filepath)
            })
            .copied()
            .collect();

        // If no search rules apply to this file, return empty findings
        if applicable_search_rules.is_empty() {
            return findings;
        }

        // Create taint rule deduplicator to leverage taint context
        let rule_deduplicator = TaintRuleDeduplicator::new(taint_rules);

        // Create variable flow tracker for sophisticated analysis
        let mut flow_tracker = VariableFlowTracker::new();

        // Use broader traversal to include assignment statements (like taint mode)
        let mut all_nodes = Vec::new();
        Self::collect_all_relevant_nodes(tree.root_node(), &mut all_nodes, None);

        // Phase 1: Build taint context by tracking variable assignments from taint sources (only if taint rules exist)
        let has_taint_rules = !taint_rules.is_empty();

        if has_taint_rules {
            for node in all_nodes.iter() {
                Self::build_taint_context_for_node(
                    node,
                    source,
                    taint_rules,
                    &rule_deduplicator,
                    &mut flow_tracker,
                );
            }
        }

        // Phase 2: Apply search rules with enhanced context awareness
        let call_nodes: Vec<tree_sitter::Node> =
            crate::parser::traverse_calls_only(tree.root_node(), language_support).collect();

        let ctx = EnhancedSearchContext {
            source,
            filepath,
            language_support,
            applicable_search_rules: &applicable_search_rules,
            rule_deduplicator: &rule_deduplicator,
            has_taint_rules,
        };

        for node in call_nodes.iter() {
            Self::apply_search_rules_to_call_node(
                node,
                &ctx,
                &flow_tracker,
                &mut processed_lines,
                &mut findings,
            );
        }

        findings
    }

    /// Enhanced rule checking that leverages taint context for more accurate analysis
    /// Whether the rule's `patterns`/`pattern` match `node_text`.
    fn rule_pattern_matches_node(rule: &crate::rules::UnifiedRule, node_text: &str) -> bool {
        if let Some(patterns) = &rule.patterns {
            return patterns
                .iter()
                .any(|pattern| CommonUtils::matches_rule_pattern(pattern, node_text));
        }
        if let Some(pattern) = &rule.pattern {
            return CommonUtils::matches_rule_pattern(pattern, node_text);
        }
        false
    }

    /// The first tainted variable (if any) among `used_variables`, with its taint info.
    fn find_tainted_variable_context<'a>(
        used_variables: &[String],
        function_context: &str,
        flow_tracker: &'a VariableFlowTracker,
    ) -> Option<(String, &'a TaintVariableInfo)> {
        for var in used_variables {
            if let Some(taint_info) = flow_tracker.is_variable_tainted(var, function_context) {
                return Some((var.clone(), taint_info));
            }
        }
        None
    }

    /// Build the base finding for a matched rule (before taint/source-sink enrichment).
    fn build_base_finding(
        rule: &crate::rules::UnifiedRule,
        node: &tree_sitter::Node,
        node_text: &str,
        source: &[u8],
        filepath: &str,
        func_name: &str,
    ) -> crate::models::Finding {
        // Create enhanced finding with taint context - always point to the sink line
        let vulnerable_line =
            Self::find_vulnerable_line_in_node(node, source, rule.get_finding_type(), Some(rule));
        let mut finding = crate::models::Finding {
            file: filepath.to_string(),
            line: vulnerable_line,
            column: node.start_position().column,
            end_line: node.end_position().row + 1,
            end_column: node.end_position().column,
            function: func_name.to_string(),
            finding_type: rule.get_finding_type().to_string(),
            snippet: node_text.to_string(),
            severity: rule.get_severity().to_string(),
            confidence: rule.get_confidence().to_string(),
            description: rule.description.clone(),
            cwe_id: None,
            source_info: None,
            sink_info: None,
            traces: None,
            tags: rule.tags.clone(),
        };

        // Use CWE ID directly from rule, with fallback to tags for backward compatibility
        finding.cwe_id = rule.cwe_id.clone().or_else(|| {
            // Fallback: extract from tags if rule doesn't have cwe_id field
            rule.tags.as_ref().and_then(|tags| {
                crate::models::Finding::extract_cwe_id_from_tags(&Some(tags.clone()))
            })
        });

        finding
    }

    /// Add enhanced source/sink info from taint context when available, otherwise fall back to
    /// regular (non-taint) source/sink pattern detection.
    fn enrich_finding_with_taint_or_source_context(
        finding: &mut crate::models::Finding,
        node: &tree_sitter::Node,
        source: &[u8],
        func_name: &str,
        language_support: &dyn crate::language::LanguageSupport,
        rule: &crate::rules::UnifiedRule,
        line: usize,
        taint_context_info: Option<(String, &TaintVariableInfo)>,
    ) {
        let Some((tainted_var, taint_info)) = taint_context_info else {
            // Regular source/sink detection for non-taint context
            finding.source_info =
                ScanningLogic::detect_source_pattern(node, source, language_support);
            finding.sink_info = ScanningLogic::detect_sink_pattern(
                node,
                source,
                func_name,
                rule.get_finding_type(),
            );
            return;
        };

        finding.source_info = Some(crate::models::SourceInfo {
            source_type: format!("{} (Taint Context)", taint_info.source_pattern),
            location: format!("Line {} ({})", taint_info.source_line, taint_info.source_function),
            context: taint_info.assignment_code.clone(),
        });

        finding.sink_info = Some(crate::models::SinkInfo {
            sink_type: rule.get_finding_type().to_string(),
            function_name: func_name.to_string(),
            location: format!("Line {}", line),
            variable: Some(tainted_var),
        });

        // Increase confidence when we have taint context
        finding.confidence = "High".to_string();
    }

    fn check_rule_against_node_with_taint_context(
        rule: &crate::rules::UnifiedRule,
        node: &tree_sitter::Node,
        source: &[u8],
        filepath: &str,
        func_name: &str,
        language_support: &dyn crate::language::LanguageSupport,
        flow_tracker: &VariableFlowTracker,
        _rule_deduplicator: &TaintRuleDeduplicator,
    ) -> Option<crate::models::Finding> {
        let node_text = crate::parser::get_node_text(node, source);

        if !Self::rule_pattern_matches_node(rule, &node_text) {
            return None;
        }

        if let Some(conditions) = &rule.conditions {
            if !crate::scanner::conditions::check_ast_conditions(
                conditions,
                node,
                source,
                language_support,
            ) {
                return None;
            }
        }

        // Extract variables used in this node
        let used_variables = CommonUtils::extract_all_variables(&node_text);
        let line = node.start_position().row + 1;
        let function_context = crate::scanner::utils::AstUtils::get_function_context(node, source);

        // Check if any used variables are tainted (enhanced context)
        let taint_context_info =
            Self::find_tainted_variable_context(&used_variables, &function_context, flow_tracker);

        let mut finding =
            Self::build_base_finding(rule, node, &node_text, source, filepath, func_name);
        Self::enrich_finding_with_taint_or_source_context(
            &mut finding,
            node,
            source,
            func_name,
            language_support,
            rule,
            line,
            taint_context_info,
        );

        Some(finding)
    }
}
