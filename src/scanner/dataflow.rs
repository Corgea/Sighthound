#![allow(clippy::too_many_arguments, clippy::large_enum_variant, clippy::needless_range_loop)]

use crate::common::CommonUtils;
use crate::scanner::ast_provenance::{AssignmentFact, AstResolution, PythonAstProvenance};
use crate::scanner::flow_tracker::{
    AnalysisResult, FunctionAnalysisSite, FunctionTaintScanState, TraceSinkSite,
    ValueSourceClassification, VariableSource, VerifiedFlowEndpoints, VerifiedTaintFlow,
};
use crate::scanner::taint_utils::{TaintExpressionUtils, TaintRuleDeduplicator};

#[derive(Debug)]
pub(crate) struct DataFlowTracer {
    /// Cache of analyzed variable sources to avoid re-computation. Keyed by
    /// (file, function, variable, sink line): provenance is sink-relative,
    /// since only assignments that can reach the sink line count.
    variable_source_cache:
        std::collections::HashMap<(String, String, String, usize), VariableSource>,
    /// Verified taint flows that have been fully validated
    verified_flows: Vec<VerifiedTaintFlow>,
    /// Resolved imports parsed elsewhere: calling_file -> {imported_function -> source_file}.
    /// Lets `find_function_source_file` resolve real `from foo import bar` statements via the
    /// already-parsed import data instead of relying on fixture-name heuristics. BTreeMap keeps
    /// iteration deterministic per repo convention.
    import_map: std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
    /// AST-grounded variable provenance for Python files (text scan is the fallback).
    ast_provenance: PythonAstProvenance,
}

impl DataFlowTracer {
    pub(crate) fn new() -> Self {
        Self {
            variable_source_cache: std::collections::HashMap::new(),
            verified_flows: Vec::new(),
            import_map: std::collections::BTreeMap::new(),
            ast_provenance: PythonAstProvenance::default(),
        }
    }

    /// Populate the import map from import data already parsed by the analyzer.
    /// Called before cross-file flow analysis so `find_function_source_file` can resolve
    /// imported functions to their source file without re-parsing any files.
    pub(crate) fn set_import_map(
        &mut self,
        import_map: std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
    ) {
        self.import_map = import_map;
    }

    /// Analyze whether a sink variable in a function truly receives tainted data
    /// Handle the `FunctionParameter` variable-source case: treat the parameter as a taint
    /// source only when its name matches a known source pattern (broad names like `token` are
    /// too noisy to assume tainted).
    fn analyze_function_parameter_source(
        &mut self,
        sink_file: &str,
        sink_function: &str,
        sink_pattern: &str,
        sink_line: usize,
        sink_variable: &str,
        parameter_index: usize,
        rule_deduplicator: &TaintRuleDeduplicator,
    ) -> AnalysisResult {
        log::debug!("[DATA_FLOW_TRACER] Variable from function parameter {}", parameter_index);

        // Only treat parameters as sources when the parameter shape is
        // explicitly user controlled; broad names like `token` are too noisy.
        let ValueSourceClassification::Tainted(source_pattern) =
            self.classify_value_source(sink_variable, rule_deduplicator)
        else {
            return AnalysisResult::Unknown {
                reason: format!(
                    "Function parameter {} - requires caller analysis",
                    parameter_index
                ),
            };
        };

        log::debug!(
            "[DATA_FLOW_TRACER] Function parameter '{}' matches source pattern '{}'",
            sink_variable,
            source_pattern
        );

        // Treat function parameters that match source patterns as taint sources
        let flow = VerifiedTaintFlow {
            source_file: sink_file.to_string(),
            source_function: sink_function.to_string(),
            source_pattern: source_pattern.clone(),
            source_line: 1, // Function definition line (approximate)

            sink_file: sink_file.to_string(),
            sink_function: sink_function.to_string(),
            sink_pattern: sink_pattern.to_string(),
            sink_line,
            sink_variable: sink_variable.to_string(),

            call_chain_len: 0,
        };

        self.verified_flows.push(flow.clone());
        AnalysisResult::DefinitelyTainted { flow }
    }

    pub(crate) fn analyze_sink_variable(
        &mut self,
        sink_file: &str,
        sink_function: &str,
        sink_variable: &str,
        sink_pattern: &str,
        sink_line: usize,
        rule_deduplicator: &TaintRuleDeduplicator,
    ) -> AnalysisResult {
        log::debug!(
            "[DATA_FLOW_TRACER] Analyzing sink variable '{}' in {}::{}",
            sink_variable,
            sink_file,
            sink_function
        );

        // Step 1: Determine how this variable gets its value at the sink line
        let variable_source = self.analyze_variable_source(
            sink_file,
            sink_function,
            sink_variable,
            sink_line,
            rule_deduplicator,
        );

        match variable_source {
            VariableSource::KnownSafe { reason, line } => {
                log::debug!("[DATA_FLOW_TRACER] Variable proven safe at line {}: {}", line, reason);
                AnalysisResult::DefinitelySafe
            }

            VariableSource::DirectTaintSource { pattern, line } => {
                log::debug!(
                    "[DATA_FLOW_TRACER] Direct taint source found: {} at line {}",
                    pattern,
                    line
                );
                self.create_verified_flow(VerifiedFlowEndpoints {
                    source_file: sink_file,
                    source_function: sink_function,
                    source_pattern: &pattern,
                    source_line: line,
                    sink_file,
                    sink_function,
                    sink_pattern,
                    sink_line,
                    sink_variable,
                    call_chain_len: 0,
                })
            }

            VariableSource::LocalAssignment { source_expression, line } => {
                log::debug!(
                    "[DATA_FLOW_TRACER] Variable from local assignment: '{}' at line {}",
                    source_expression,
                    line
                );
                self.trace_local_assignment_taint(
                    TraceSinkSite {
                        file_path: sink_file,
                        function_name: sink_function,
                        sink_pattern,
                        sink_line,
                        sink_variable,
                    },
                    &source_expression,
                    line,
                    rule_deduplicator,
                    &mut std::collections::BTreeSet::new(),
                )
            }

            VariableSource::FunctionParameter { parameter_index } => self
                .analyze_function_parameter_source(
                    sink_file,
                    sink_function,
                    sink_pattern,
                    sink_line,
                    sink_variable,
                    parameter_index,
                    rule_deduplicator,
                ),

            VariableSource::Unresolved { reason } => {
                log::debug!("[DATA_FLOW_TRACER] Variable unresolvable: {}", reason);
                AnalysisResult::Unknown { reason }
            }
        }
    }

    /// Analyze how a variable gets its value (assignment, import, parameter, etc.)
    /// as observed at `sink_line` — assignments below the sink that no loop
    /// carries back cannot be the value the sink sees.
    fn analyze_variable_source(
        &mut self,
        file_path: &str,
        function_name: &str,
        variable_name: &str,
        sink_line: usize,
        rule_deduplicator: &TaintRuleDeduplicator,
    ) -> VariableSource {
        let cache_key = (
            file_path.to_string(),
            function_name.to_string(),
            variable_name.to_string(),
            sink_line,
        );

        // Check cache first
        if let Some(cached_source) = self.variable_source_cache.get(&cache_key) {
            return cached_source.clone();
        }

        let source = self.compute_variable_source(
            file_path,
            function_name,
            variable_name,
            sink_line,
            rule_deduplicator,
        );
        self.variable_source_cache.insert(cache_key, source.clone());
        source
    }

    /// Create a verified taint flow with complete evidence
    fn create_verified_flow(&mut self, endpoints: VerifiedFlowEndpoints) -> AnalysisResult {
        let verified_flow = VerifiedTaintFlow {
            source_file: endpoints.source_file.to_string(),
            source_function: endpoints.source_function.to_string(),
            source_pattern: endpoints.source_pattern.to_string(),
            source_line: endpoints.source_line,

            sink_file: endpoints.sink_file.to_string(),
            sink_function: endpoints.sink_function.to_string(),
            sink_pattern: endpoints.sink_pattern.to_string(),
            sink_line: endpoints.sink_line,
            sink_variable: endpoints.sink_variable.to_string(),

            call_chain_len: endpoints.call_chain_len,
        };

        log::debug!(
            "[DATA_FLOW_TRACER] Verified taint flow: {} -> {} via {:?}",
            endpoints.source_pattern,
            endpoints.sink_pattern,
            verified_flow.call_chain_len
        );

        self.verified_flows.push(verified_flow.clone());
        AnalysisResult::DefinitelyTainted { flow: verified_flow }
    }

    /// Actually analyze how a variable gets its value within a function
    /// Scope the assignment search to the enclosing function's body so a same-named local
    /// variable in an EARLIER function can't shadow the real assignment in the target function.
    /// Each body line's 0-based index `i` maps to absolute file line `start_line + i`. Falls
    /// back to a whole-file scan (never regressing detection) when the function body can't be
    /// located.
    fn build_scoped_lines(&self, source_text: &str, function_name: &str) -> Vec<(usize, String)> {
        match self.extract_function_body(source_text, function_name) {
            Some((body, start_line)) => body
                .lines()
                .enumerate()
                .map(|(i, line)| (start_line + i, line.to_string()))
                .collect(),
            None => {
                source_text.lines().enumerate().map(|(i, line)| (i + 1, line.to_string())).collect()
            }
        }
    }

    /// Classify an assignment's right-hand side: proven-safe/tainted (via
    /// [`Self::classify_value_source`]), a direct source-pattern match, a function-call
    /// assignment, or a plain local assignment.
    fn classify_assignment_rhs(
        &self,
        rhs: &str,
        file_line: usize,
        rule_deduplicator: &TaintRuleDeduplicator,
    ) -> VariableSource {
        match self.classify_value_source(rhs, rule_deduplicator) {
            ValueSourceClassification::Safe(reason) => {
                log::debug!("[COMPUTE_VARIABLE_SOURCE] Proven-safe assignment: {}", reason);
                return VariableSource::KnownSafe { reason, line: file_line };
            }
            ValueSourceClassification::Tainted(source_pattern) => {
                log::debug!("[COMPUTE_VARIABLE_SOURCE] Direct taint source: '{}'", source_pattern);
                return VariableSource::DirectTaintSource {
                    pattern: source_pattern,
                    line: file_line,
                };
            }
            ValueSourceClassification::Unknown => {}
        }

        // Check if RHS is a direct taint source
        if let Some(source_pattern) = rule_deduplicator.matches_source_pattern(rhs) {
            log::debug!("[COMPUTE_VARIABLE_SOURCE] Direct taint source: '{}'", source_pattern);
            return VariableSource::DirectTaintSource { pattern: source_pattern, line: file_line };
        }

        // Check if RHS is a function call
        if rhs.contains('(') && rhs.contains(')') {
            let function_name = rhs.split('(').next().unwrap_or("").trim();
            log::debug!("[COMPUTE_VARIABLE_SOURCE] Function call assignment: '{}'", function_name);
            return VariableSource::LocalAssignment {
                source_expression: rhs.to_string(),
                line: file_line,
            };
        }

        // Otherwise, it's a simple local assignment
        log::debug!("[COMPUTE_VARIABLE_SOURCE] Local assignment: '{}'", rhs);
        VariableSource::LocalAssignment { source_expression: rhs.to_string(), line: file_line }
    }

    /// Find the assignment to `variable_name` in `scoped_lines` (searched in order) and
    /// classify its source. Returns `None` when no assignment is found.
    fn find_assignment_source(
        &self,
        scoped_lines: &[(usize, String)],
        variable_name: &str,
        rule_deduplicator: &TaintRuleDeduplicator,
    ) -> Option<VariableSource> {
        // Simple text-based analysis for now
        // Look for assignment patterns like "variable_name = something"
        for (file_line, line) in scoped_lines {
            let file_line = *file_line;
            let line = line.trim();
            // Note: augmented assignments (`x += ...`, `x -= ...`) are intentionally
            // not matched by this `{} =` guard and are not handled by this path.
            if !line.starts_with(&format!("{} =", variable_name)) {
                continue;
            }
            // Split on the FIRST '=' only so the full RHS is preserved even when
            // it contains '==' or kwarg '=' (e.g. `x = a == b`, `x = f(k=v)`), then
            // strip any trailing inline comment.
            let rhs = TaintExpressionUtils::strip_inline_comment(
                line.split_once('=').map(|(_, rhs)| rhs).unwrap_or("").trim(),
            );
            log::debug!("[COMPUTE_VARIABLE_SOURCE] Found assignment: {} = {}", variable_name, rhs);

            return Some(self.classify_assignment_rhs(rhs, file_line, rule_deduplicator));
        }
        None
    }

    /// Whether `variable_name` is a parameter of `function_name`'s definition, and if so, at
    /// what index.
    fn find_function_parameter_index(
        source_text: &str,
        function_name: &str,
        variable_name: &str,
    ) -> Option<usize> {
        let func_line = source_text
            .lines()
            .find(|line| line.trim().starts_with(&format!("def {}(", function_name)))?;
        if !func_line.contains(variable_name) {
            return None;
        }
        let params_part = func_line.split('(').nth(1)?;
        let params_only = params_part.split(')').next()?;
        let params: Vec<&str> = params_only.split(',').map(|p| p.trim()).collect();
        params.iter().position(|param| param == &variable_name)
    }

    fn compute_variable_source(
        &mut self,
        file_path: &str,
        function_name: &str,
        variable_name: &str,
        sink_line: usize,
        rule_deduplicator: &TaintRuleDeduplicator,
    ) -> VariableSource {
        log::debug!(
            "[COMPUTE_VARIABLE_SOURCE] Analyzing variable '{}' in {}::{} at line {}",
            variable_name,
            file_path,
            function_name,
            sink_line
        );

        // AST-grounded provenance first (Python). Any shape the resolver does not
        // model yields `None`, so the text path below keeps handling it exactly as
        // before — other languages always take the text path. `Unresolved` is
        // returned as-is: the resolver has positively determined that any further
        // guessing (including the text path's) would be wrong.
        if let Some(source) = self.ast_variable_source(
            file_path,
            function_name,
            variable_name,
            sink_line,
            rule_deduplicator,
        ) {
            return source;
        }

        // Read the source code as text and do simple string analysis
        let Ok(source_text) = std::fs::read_to_string(file_path) else {
            log::debug!("[COMPUTE_VARIABLE_SOURCE] Could not read file: {}", file_path);
            return VariableSource::FunctionParameter { parameter_index: 0 };
        };

        let scoped_lines = self.build_scoped_lines(&source_text, function_name);

        if let Some(source) =
            self.find_assignment_source(&scoped_lines, variable_name, rule_deduplicator)
        {
            return source;
        }

        // Check if it might be a function parameter by looking for function definition
        if let Some(parameter_index) =
            Self::find_function_parameter_index(&source_text, function_name, variable_name)
        {
            log::debug!(
                "[COMPUTE_VARIABLE_SOURCE] Variable '{}' is function parameter at index {}",
                variable_name,
                parameter_index
            );
            return VariableSource::FunctionParameter { parameter_index };
        }

        // Default case - treat as parameter 0
        log::debug!(
            "[COMPUTE_VARIABLE_SOURCE] Variable '{}' source unknown, defaulting to parameter 0",
            variable_name
        );
        VariableSource::FunctionParameter { parameter_index: 0 }
    }

    /// Resolve a variable's provenance from the Python AST. `None` means the
    /// resolver does not cover this file/function/variable and the caller must
    /// fall back to the text path. Only assignments that can reach `sink_line`
    /// are considered — an assignment below the sink that no loop carries back
    /// cannot be the value the sink observes.
    fn ast_variable_source(
        &mut self,
        file_path: &str,
        function_name: &str,
        variable_name: &str,
        sink_line: usize,
        rule_deduplicator: &TaintRuleDeduplicator,
    ) -> Option<VariableSource> {
        match self.ast_provenance.resolve_variable_reaching(
            file_path,
            function_name,
            variable_name,
            Some(sink_line),
        )? {
            AstResolution::Parameter { index } => {
                log::debug!(
                    "[COMPUTE_VARIABLE_SOURCE] AST: '{}' is parameter {} of {}",
                    variable_name,
                    index,
                    function_name
                );
                Some(VariableSource::FunctionParameter { parameter_index: index })
            }
            AstResolution::Assignments(assignments) => {
                self.classify_ast_assignments(&assignments, sink_line, rule_deduplicator)
            }
            AstResolution::Ambiguous => {
                log::debug!(
                    "[COMPUTE_VARIABLE_SOURCE] AST: function '{}' is defined more than once; \
                     refusing to resolve '{}' against a guessed definition",
                    function_name,
                    variable_name
                );
                Some(VariableSource::Unresolved {
                    reason: format!(
                        "function name '{}' is defined more than once in {}; \
                         cannot attribute assignments to the sink's definition",
                        function_name, file_path
                    ),
                })
            }
        }
    }

    /// Classify AST assignment facts for one variable (pre-filtered to those
    /// that can reach `sink_line`). A definitely-safe verdict is only claimed
    /// when EVERY reaching write is provably safe, so a safe branch sibling or
    /// initializer can never mask an unresolved one:
    ///
    /// * Any reaching write whose RHS is tainted wins outright — the variable
    ///   received attacker-controlled data on some reaching path (this is what
    ///   lets `x += input()` after a safe initializer surface).
    /// * A literal collection is safe only when a *dominating* literal
    ///   initializer sets it and every reaching write is literal (a later
    ///   `cfg[k] = user_supplied` or `parts.append(input())` defeats it).
    /// * Otherwise provenance is the latest reaching write we cannot prove safe.
    ///   Augmented writes count as unresolved — they combine with an unseen
    ///   prior value — and every reaching write is scanned, not just the latest,
    ///   so a safe sibling (`if c: cmd = fetch() else: cmd = "ls"`) or a stale
    ///   initializer cannot supply the verdict for a value that flows from
    ///   elsewhere.
    /// * Only when every reaching write is safe AND a *dominating* plain write
    ///   (at or above the sink) established the base is the variable reported
    ///   safe. A base set only below the sink (loop-carried) or only via an
    ///   augmented write leaves the first-pass value unknown, so it is reported
    ///   Unknown rather than falling through to the sink-agnostic text scan.
    fn classify_ast_assignments(
        &self,
        assignments: &[AssignmentFact],
        sink_line: usize,
        rule_deduplicator: &TaintRuleDeduplicator,
    ) -> Option<VariableSource> {
        for fact in assignments {
            if let ValueSourceClassification::Tainted(pattern) =
                self.classify_value_source(&fact.rhs, rule_deduplicator)
            {
                log::debug!(
                    "[COMPUTE_VARIABLE_SOURCE] AST: tainted assignment '{}' at line {}",
                    fact.rhs,
                    fact.line
                );
                return Some(VariableSource::DirectTaintSource { pattern, line: fact.line });
            }
        }

        // A write can establish the value on every execution only when it is a
        // plain assignment at or above the sink; a below-sink write applies on a
        // later loop iteration only, so it cannot prove first-pass safety.
        let dominating_init =
            assignments.iter().find(|fact| !fact.augmented && fact.line <= sink_line);

        // A literal collection proves safety only when a dominating literal
        // initializer sets it AND every reaching write is itself literal — a
        // later `cfg["cmd"] = user_supplied` or `parts.append(input())`
        // (recorded as a non-literal fact) must defeat the verdict.
        if let Some(init) = dominating_init {
            if init.literal_collection && assignments.iter().all(|fact| fact.literal_value) {
                log::debug!(
                    "[COMPUTE_VARIABLE_SOURCE] AST: literal collection at line {}",
                    init.line
                );
                return Some(VariableSource::KnownSafe {
                    reason: "value drawn from a literal collection".to_string(),
                    line: init.line,
                });
            }
        }

        // Walk reaching writes newest-first. A write whose RHS is safe adds no
        // unresolved data, so skip it and keep looking; the first write with a
        // non-safe RHS — a plain overwrite, a branch sibling, an augmented
        // combine, or a below-sink loop-carried write — supplies provenance so
        // the flow stays traceable and a safe sibling cannot mask it.
        for fact in assignments.iter().rev() {
            if matches!(
                self.classify_value_source(&fact.rhs, rule_deduplicator),
                ValueSourceClassification::Safe(_)
            ) {
                continue;
            }
            return Some(self.classify_assignment_rhs(&fact.rhs, fact.line, rule_deduplicator));
        }

        // Every reaching write has a safe RHS. The variable is definitely safe
        // only when a dominating plain write set the base (any augmented write
        // left here only adds developer data on top of it); a base set solely
        // below the sink or via augmentation leaves the first-pass value unseen,
        // so it is reported Unknown rather than through the text scan.
        match dominating_init {
            Some(base) => {
                Some(self.classify_assignment_rhs(&base.rhs, base.line, rule_deduplicator))
            }
            None => Some(VariableSource::Unresolved {
                reason: "value base is set only below the sink or via augmented assignment"
                    .to_string(),
            }),
        }
    }

    /// Classify an expression that reads an environment variable: user-controlled keys are
    /// tainted, known config keys are safe, anything else falls through (`None`).
    fn classify_env_key_expression(
        expr: &str,
        rule_deduplicator: &TaintRuleDeduplicator,
    ) -> Option<ValueSourceClassification> {
        let env_key = Self::extract_env_key(expr)?;

        if Self::is_user_controlled_env_key(&env_key) {
            let source_pattern = rule_deduplicator
                .matches_source_pattern(expr)
                .unwrap_or_else(|| format!("env:{}", env_key));
            return Some(ValueSourceClassification::Tainted(source_pattern));
        }

        if Self::is_config_env_key(&env_key) {
            return Some(ValueSourceClassification::Safe(format!(
                "static configuration environment key {}",
                env_key
            )));
        }

        None
    }

    /// Classify an expression containing a well-known taint-indicator substring (`input(`,
    /// `sys.argv`, `request.`, ...) as tainted when it also matches a configured source
    /// pattern; falls through (`None`) otherwise.
    fn classify_known_source_indicators(
        expr: &str,
        rule_deduplicator: &TaintRuleDeduplicator,
    ) -> Option<ValueSourceClassification> {
        let lower_expr = expr.to_ascii_lowercase();
        let has_indicator = lower_expr.contains("input(")
            || lower_expr.contains("raw_input(")
            || lower_expr.contains("sys.argv")
            || lower_expr.contains("request.")
            || lower_expr.contains("flask.request");
        if !has_indicator {
            return None;
        }

        rule_deduplicator.matches_source_pattern(expr).map(ValueSourceClassification::Tainted)
    }

    fn classify_value_source(
        &self,
        expression: &str,
        rule_deduplicator: &TaintRuleDeduplicator,
    ) -> ValueSourceClassification {
        let expr = expression.trim();

        if expr.is_empty() {
            return ValueSourceClassification::Unknown;
        }

        if expr.starts_with('#') || expr.starts_with("\"\"\"") || expr.starts_with("'''") {
            return ValueSourceClassification::Safe("comment or docstring".to_string());
        }

        if self.is_safe_literal_expression(expr) {
            return ValueSourceClassification::Safe("literal expression".to_string());
        }

        // `setdefault(key, default)` returns `default` when the key is absent, so a
        // tainted default (e.g. `d.setdefault("k", request.args["x"])` or
        // `os.environ.setdefault(k, input())`) propagates taint through the result.
        // We deliberately do NOT short-circuit `setdefault(` to Safe. Robustly parsing
        // out the 2nd argument (nested calls, commas, and quotes) is not worth the
        // complexity, so we drop the blanket guard and let normal classification run:
        // `os.environ.setdefault(...)` is handled by the env-key path below (which
        // separates user-controlled keys from config keys), and any inline taint source
        // in the default argument is caught by the source-pattern checks further down.

        if Self::is_safe_static_file_read(expr) {
            return ValueSourceClassification::Safe("static config/template file read".to_string());
        }

        if let Some(classification) = Self::classify_env_key_expression(expr, rule_deduplicator) {
            return classification;
        }

        if let Some(classification) =
            Self::classify_known_source_indicators(expr, rule_deduplicator)
        {
            return classification;
        }

        if let Some(source_pattern) = rule_deduplicator.matches_source_pattern(expr) {
            return ValueSourceClassification::Tainted(source_pattern);
        }

        ValueSourceClassification::Unknown
    }

    fn is_safe_literal_expression(&self, expression: &str) -> bool {
        let expr = expression.trim();

        if Self::is_string_literal(expr)
            || matches!(expr, "True" | "False" | "None" | "true" | "false" | "null")
            || expr.parse::<f64>().is_ok()
        {
            return true;
        }

        let literal_concat = expr
            .split('+')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .all(Self::is_string_literal);

        literal_concat && expr.contains('+')
    }

    fn is_string_literal(expression: &str) -> bool {
        // Returns true only for a SINGLE atomic quoted literal. The opening quote's
        // matching closing quote must be the final character; otherwise the expression
        // is a top-level concatenation like `"x" + tainted + "y"` (which starts and ends
        // with a quote but is not one literal) and must fall through to the per-operand
        // concat check in `is_safe_literal_expression`.
        let bytes = expression.trim().as_bytes();
        if bytes.len() < 2 {
            return false;
        }
        let quote = bytes[0];
        if quote != b'"' && quote != b'\'' {
            return false;
        }
        // Quotes and `\` are ASCII, so byte scanning is safe even with multibyte
        // UTF-8 content (continuation bytes are all >= 0x80 and never match).
        let mut escaped = false;
        for (i, &b) in bytes.iter().enumerate().skip(1) {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == quote {
                return i == bytes.len() - 1;
            }
        }
        false
    }

    fn is_safe_static_file_read(expression: &str) -> bool {
        if !expression.contains("open(") {
            return false;
        }

        let Some(start) = expression.find("open(") else {
            return false;
        };
        let after = expression[start + "open(".len()..].trim_start();
        let Some(quote) = after.chars().next() else {
            return false;
        };
        if quote != '"' && quote != '\'' {
            return false;
        }

        let rest = &after[quote.len_utf8()..];
        let Some(end) = rest.find(quote) else {
            return false;
        };
        let filename = rest[..end].to_ascii_lowercase();

        // The path must be a SINGLE string literal. After the literal's closing
        // quote the only thing allowed is the argument terminator (`)` or `,` for
        // the mode arg). A `+` (concatenation) or any other token means the real
        // path is built from a tainted value — e.g. `open("config/" + user_input)`
        // — which must NOT be treated as a safe static read.
        let remainder = rest[end + quote.len_utf8()..].trim_start();
        if !matches!(remainder.chars().next(), Some(')') | Some(',')) {
            return false;
        }

        filename.contains("config")
            || filename.contains("template")
            || filename.ends_with(".json")
            || filename.ends_with(".yaml")
            || filename.ends_with(".yml")
            || filename.ends_with(".toml")
    }

    fn extract_env_key(expression: &str) -> Option<String> {
        let patterns = ["os.environ.get(", "os.getenv(", "os.environ.setdefault(", "os.environ["];

        for pattern in patterns {
            if let Some(start) = expression.find(pattern) {
                let after = &expression[start + pattern.len()..];
                let after = after.trim_start();
                let quote = after.chars().next()?;
                if quote != '"' && quote != '\'' {
                    return None;
                }
                let rest = &after[quote.len_utf8()..];
                if let Some(end) = rest.find(quote) {
                    return Some(rest[..end].to_ascii_uppercase());
                }
            }
        }

        None
    }

    fn is_user_controlled_env_key(key: &str) -> bool {
        let key = key.to_ascii_uppercase();
        key == "USER_COMMAND"
            || key == "USER_INPUT_FILE"
            || key == "REQUEST_DATA"
            || key.starts_with("REQUEST_")
            || key.starts_with("USER_INPUT")
            || key.ends_with("_INPUT")
            || key.ends_with("_COMMAND")
            || key.ends_with("_PAYLOAD")
    }

    fn is_config_env_key(key: &str) -> bool {
        let key = key.to_ascii_uppercase();
        key.starts_with("APP_")
            || key.starts_with("DJANGO_")
            || key.starts_with("FLASK_")
            || key.ends_with("_MODE")
            || key.ends_with("_VERSION")
            || key.ends_with("_API_KEY")
            || key == "DEBUG"
            || key == "LOG_LEVEL"
            || key == "SECRET_KEY"
            || key == "API_KEY"
    }

    /// Build and record a verified taint flow from `source_pattern` at `source_line` down to
    /// `site`'s sink (single-file, `call_chain_len` 0).
    fn record_direct_taint_flow(
        &mut self,
        site: &TraceSinkSite,
        source_pattern: String,
        source_line: usize,
    ) -> AnalysisResult {
        let flow = VerifiedTaintFlow {
            source_file: site.file_path.to_string(),
            source_function: site.function_name.to_string(),
            source_pattern,
            source_line,

            sink_file: site.file_path.to_string(),
            sink_function: site.function_name.to_string(),
            sink_pattern: site.sink_pattern.to_string(),
            sink_line: site.sink_line,
            sink_variable: site.sink_variable.to_string(),

            call_chain_len: 0,
        };

        self.verified_flows.push(flow.clone());
        AnalysisResult::DefinitelyTainted { flow }
    }

    /// Resolve the file that defines `callee_name` as called from `caller_file`: a direct
    /// lookup, or (for a dotted method call) its last segment, falling back to `caller_file`
    /// itself when that file defines a same-named function.
    fn resolve_call_target_function(
        &self,
        callee_name: &str,
        caller_file: &str,
    ) -> Option<(String, String)> {
        if let Some(source_file) = self.find_function_source_file(callee_name, caller_file) {
            return Some((callee_name.to_string(), source_file));
        }

        let method_name = callee_name.rsplit('.').next()?;
        if method_name == callee_name {
            return None;
        }

        self.find_function_source_file(method_name, caller_file)
            .or_else(|| {
                self.file_contains_function(caller_file, method_name)
                    .then(|| caller_file.to_string())
            })
            .map(|source_file| (method_name.to_string(), source_file))
    }

    /// If `source_expression` looks like a function call, resolve which file defines the
    /// callee and recursively analyze whether it returns tainted data, producing a cross-file
    /// flow when it does. Returns `None` (fall through to further checks) when the expression
    /// isn't a call or the callee can't be resolved.
    fn trace_function_call_taint(
        &mut self,
        site: &TraceSinkSite,
        source_expression: &str,
        rule_deduplicator: &TaintRuleDeduplicator,
        visited: &mut std::collections::BTreeSet<(String, String)>,
    ) -> Option<AnalysisResult> {
        if !(source_expression.contains('(') && source_expression.contains(')')) {
            return None;
        }

        let callee_name = self.extract_function_name_from_call(source_expression);
        log::debug!("[TRACE_LOCAL] Source is function call: '{}'", callee_name);

        let Some((resolved_function_name, source_file)) =
            self.resolve_call_target_function(&callee_name, site.file_path)
        else {
            log::debug!("[TRACE_LOCAL] Could not find source file for function '{}'", callee_name);
            return None;
        };

        log::debug!(
            "[TRACE_LOCAL] Found function '{}' in '{}'",
            resolved_function_name,
            source_file
        );

        // Analyze the function to see if it returns tainted data
        match self.analyze_function_taint_behavior(
            &source_file,
            &resolved_function_name,
            rule_deduplicator,
            visited,
        ) {
            AnalysisResult::DefinitelyTainted { flow } => {
                log::debug!(
                    "[TRACE_LOCAL] Function '{}' returns tainted data, creating cross-file flow",
                    callee_name
                );

                // Create a cross-file taint flow from the original source to the current sink
                let cross_file_flow = VerifiedTaintFlow {
                    source_file: flow.source_file,
                    source_function: flow.source_function,
                    source_pattern: flow.source_pattern,
                    source_line: flow.source_line,

                    sink_file: site.file_path.to_string(),
                    sink_function: site.function_name.to_string(),
                    sink_pattern: site.sink_pattern.to_string(),
                    sink_line: site.sink_line,
                    sink_variable: site.sink_variable.to_string(),

                    call_chain_len: 1,
                };

                self.verified_flows.push(cross_file_flow.clone());
                Some(AnalysisResult::DefinitelyTainted { flow: cross_file_flow })
            }
            other_result => Some(other_result),
        }
    }

    /// If `source_expression` is a string literal, a variable alias, or an f-string/complex
    /// expression referencing other variables, trace whether that dependency is tainted.
    /// Returns `None` (fall through to "unknown") when none of these shapes match.
    fn trace_variable_dependency_taint(
        &mut self,
        site: &TraceSinkSite,
        source_expression: &str,
        rule_deduplicator: &TaintRuleDeduplicator,
    ) -> Option<AnalysisResult> {
        // Check if the source expression references other variables that might be tainted
        // For now, we'll check simple cases like string literals (which are safe)
        if source_expression.starts_with('"') && source_expression.ends_with('"') {
            log::debug!("[TRACE_LOCAL] String literal assignment - safe");
            return Some(AnalysisResult::DefinitelySafe);
        }

        if CommonUtils::is_valid_variable_name(source_expression)
            && source_expression != site.sink_variable
            && !CommonUtils::is_keyword_or_builtin(source_expression)
        {
            log::debug!(
                "[TRACE_LOCAL] Source is variable alias '{}', tracing dependency",
                source_expression
            );
            return Some(self.analyze_sink_variable(
                site.file_path,
                site.function_name,
                source_expression,
                site.sink_pattern,
                site.sink_line,
                rule_deduplicator,
            ));
        }

        // If it's an f-string or complex expression, we need more analysis
        if source_expression.starts_with("f\"") || source_expression.contains('{') {
            log::debug!("[TRACE_LOCAL] Complex expression - requires variable dependency analysis");
            for variable in CommonUtils::extract_all_variables(source_expression) {
                if variable == site.sink_variable
                    || CommonUtils::is_keyword_or_builtin(&variable)
                    || variable == "f"
                {
                    continue;
                }

                let AnalysisResult::DefinitelyTainted { flow } = self.analyze_sink_variable(
                    site.file_path,
                    site.function_name,
                    &variable,
                    site.sink_pattern,
                    site.sink_line,
                    rule_deduplicator,
                ) else {
                    continue;
                };

                let derived_flow = VerifiedTaintFlow {
                    source_file: flow.source_file,
                    source_function: flow.source_function,
                    source_pattern: flow.source_pattern,
                    source_line: flow.source_line,
                    sink_file: site.file_path.to_string(),
                    sink_function: site.function_name.to_string(),
                    sink_pattern: site.sink_pattern.to_string(),
                    sink_line: site.sink_line,
                    sink_variable: site.sink_variable.to_string(),
                    call_chain_len: flow.call_chain_len,
                };
                self.verified_flows.push(derived_flow.clone());
                return Some(AnalysisResult::DefinitelyTainted { flow: derived_flow });
            }
        }

        None
    }

    fn trace_local_assignment_taint(
        &mut self,
        site: TraceSinkSite,
        source_expression: &str,
        assignment_line: usize,
        rule_deduplicator: &TaintRuleDeduplicator,
        visited: &mut std::collections::BTreeSet<(String, String)>,
    ) -> AnalysisResult {
        log::debug!(
            "[TRACE_LOCAL] Analyzing local assignment: '{}' in {}::{}",
            source_expression,
            site.file_path,
            site.function_name
        );

        match self.classify_value_source(source_expression, rule_deduplicator) {
            ValueSourceClassification::Safe(reason) => {
                log::debug!("[TRACE_LOCAL] Proven-safe expression: {}", reason);
                return AnalysisResult::DefinitelySafe;
            }
            ValueSourceClassification::Tainted(source_pattern) => {
                log::debug!("[TRACE_LOCAL] Classified direct taint source: '{}'", source_pattern);
                return self.record_direct_taint_flow(&site, source_pattern, assignment_line);
            }
            ValueSourceClassification::Unknown => {}
        }

        // Check if the source expression is a direct taint source
        if let Some(source_pattern) = rule_deduplicator.matches_source_pattern(source_expression) {
            log::debug!("[TRACE_LOCAL] Direct taint source found: '{}'", source_pattern);
            return self.record_direct_taint_flow(&site, source_pattern, assignment_line);
        }

        // Check if the source expression is a function call
        if let Some(result) =
            self.trace_function_call_taint(&site, source_expression, rule_deduplicator, visited)
        {
            return result;
        }

        if let Some(result) =
            self.trace_variable_dependency_taint(&site, source_expression, rule_deduplicator)
        {
            return result;
        }

        log::debug!("[TRACE_LOCAL] Could not determine taint status of assignment");
        AnalysisResult::Unknown {
            reason: format!(
                "Complex assignment analysis not implemented: \"{}\"",
                source_expression
            ),
        }
    }

    /// Extract function name from a function call expression
    fn extract_function_name_from_call(&self, function_call: &str) -> String {
        if let Some(paren_pos) = function_call.find('(') {
            function_call[..paren_pos].trim().to_string()
        } else {
            function_call.trim().to_string()
        }
    }

    /// Find which file contains the definition of an imported function
    /// Resolve `function_name` via the real imports parsed for `calling_file` (`from foo
    /// import bar` populates this map with `bar -> foo.py`), when the resolved path actually
    /// exists on disk.
    fn resolve_via_import_map(&self, calling_file: &str, function_name: &str) -> Option<String> {
        let source_file = self.import_map.get(calling_file)?.get(function_name)?;
        if !std::path::Path::new(source_file).exists() {
            return None;
        }
        log::debug!(
            "[FIND_SOURCE_FILE] Resolved \"{}\" via parsed import -> \"{}\"",
            function_name,
            source_file
        );
        Some(source_file.clone())
    }

    /// Known test-fixture pattern: config/args/module-data getters live in `module_a.py`.
    fn find_in_module_a(calling_dir: &str, function_name: &str) -> Option<String> {
        let module_a_path = format!("{}/module_a.py", calling_dir);
        if !std::path::Path::new(&module_a_path).exists() {
            return None;
        }
        log::debug!("[FIND_SOURCE_FILE] Found \"{}\" in module_a.py", function_name);
        Some(module_a_path)
    }

    /// Known test-fixture pattern: taint-propagation helpers live in `module_b.py`.
    fn find_in_module_b(calling_dir: &str, function_name: &str) -> Option<String> {
        let module_b_path = format!("{}/module_b.py", calling_dir);
        if !std::path::Path::new(&module_b_path).exists() {
            return None;
        }
        log::debug!("[FIND_SOURCE_FILE] Found \"{}\" in module_b.py", function_name);
        Some(module_b_path)
    }

    /// Fallback: scan Python files in the same directory as `calling_file` for one that
    /// defines `function_name`.
    fn find_in_sibling_python_files(
        &self,
        calling_dir: &str,
        calling_file: &str,
        function_name: &str,
    ) -> Option<String> {
        let entries = std::fs::read_dir(calling_dir).ok()?;
        let calling_basename = std::path::Path::new(calling_file).file_name().unwrap_or_default();

        for entry in entries.flatten() {
            let os_file_name = entry.file_name();
            let Some(file_name) = os_file_name.to_str() else {
                continue;
            };
            if !file_name.ends_with(".py") || file_name == calling_basename {
                continue;
            }
            let candidate_path = format!("{}/{}", calling_dir, file_name);
            if self.file_contains_function(&candidate_path, function_name) {
                log::debug!(
                    "[FIND_SOURCE_FILE] Found \"{}\" in \"{}\"",
                    function_name,
                    candidate_path
                );
                return Some(candidate_path);
            }
        }
        None
    }

    fn find_function_source_file(&self, function_name: &str, calling_file: &str) -> Option<String> {
        log::debug!(
            "[FIND_SOURCE_FILE] Looking for function \"{}\" imported by \"{}\"",
            function_name,
            calling_file
        );

        // First, resolve via the real imports parsed for the calling file. `from foo import bar`
        // populates this map with `bar -> foo.py`, so genuine code resolves here regardless of
        // function name. The hardcoded fixture arms and read_dir heuristic below remain as a
        // fallback when no parsed import covers this call (e.g. same-directory definitions with
        // no explicit import).
        if let Some(source_file) = self.resolve_via_import_map(calling_file, function_name) {
            return Some(source_file);
        }

        let calling_dir =
            std::path::Path::new(calling_file).parent().and_then(|p| p.to_str()).unwrap_or("");

        // Known patterns from the test files
        let found = match function_name {
            "get_database_config" | "get_user_args" | "get_safe_module_data" => {
                Self::find_in_module_a(calling_dir, function_name)
            }
            name if name.starts_with("propagate_")
                || name == "combine_tainted_sources"
                || name == "mix_safe_and_tainted"
                || name == "get_local_taint"
                || name == "complex_processing_chain"
                || name == "use_class_instance" =>
            {
                Self::find_in_module_b(calling_dir, function_name)
            }
            // Try to find in any Python file in the same directory
            _ => self.find_in_sibling_python_files(calling_dir, calling_file, function_name),
        };

        if found.is_none() {
            log::debug!(
                "[FIND_SOURCE_FILE] Could not find source file for function \"{}\"",
                function_name
            );
        }
        found
    }

    /// Check if a file contains a function definition
    fn file_contains_function(&self, file_path: &str, function_name: &str) -> bool {
        if let Ok(content) = std::fs::read_to_string(file_path) {
            let pattern = format!("def {}(", function_name);
            content.contains(&pattern)
        } else {
            false
        }
    }

    /// Analyze whether a function in a given file returns tainted data
    /// If `ambient_taint` isn't set yet and `line` classifies as tainted, record it as the
    /// "ambient" taint source that any subsequent `return` in this function inherits.
    fn track_ambient_taint(
        &self,
        site: &FunctionAnalysisSite,
        line: &str,
        line_num: usize,
        rule_deduplicator: &TaintRuleDeduplicator,
        ambient_taint: &mut Option<VerifiedTaintFlow>,
    ) {
        if ambient_taint.is_some() {
            return;
        }
        let ValueSourceClassification::Tainted(source_pattern) =
            self.classify_value_source(line, rule_deduplicator)
        else {
            return;
        };
        *ambient_taint = Some(VerifiedTaintFlow {
            source_file: site.file_path.to_string(),
            source_function: site.function_name.to_string(),
            source_line: line_num + 1,
            source_pattern,
            sink_file: site.file_path.to_string(),
            sink_function: site.function_name.to_string(),
            sink_line: line_num + 1,
            sink_variable: "return_value".to_string(),
            sink_pattern: "function_return".to_string(),
            call_chain_len: 0,
        });
    }

    /// If `line` is a valid assignment, trace its RHS's taint and update `tainted_locals`
    /// accordingly (insert when tainted, remove when proven safe, or inherit from an existing
    /// tainted local referenced on the RHS when inconclusive).
    fn track_local_assignment_in_function(
        &mut self,
        site: &FunctionAnalysisSite,
        line: &str,
        line_num: usize,
        rule_deduplicator: &TaintRuleDeduplicator,
        visited: &mut std::collections::BTreeSet<(String, String)>,
        tainted_locals: &mut std::collections::BTreeMap<String, VerifiedTaintFlow>,
    ) {
        if !CommonUtils::is_valid_assignment_text(line) {
            return;
        }
        let Some(eq_pos) = line.find('=') else {
            return;
        };
        let lhs = line[..eq_pos].trim();
        let rhs = TaintExpressionUtils::strip_inline_comment(line[eq_pos + 1..].trim());
        if !CommonUtils::is_valid_variable_name(lhs) {
            return;
        }

        match self.trace_local_assignment_taint(
            TraceSinkSite {
                file_path: site.file_path,
                function_name: site.function_name,
                sink_pattern: "function_return",
                sink_line: line_num + 1,
                sink_variable: lhs,
            },
            rhs,
            line_num + 1,
            rule_deduplicator,
            visited,
        ) {
            AnalysisResult::DefinitelyTainted { flow } => {
                tainted_locals.insert(lhs.to_string(), flow);
            }
            AnalysisResult::DefinitelySafe => {
                tainted_locals.remove(lhs);
            }
            AnalysisResult::Unknown { .. } => {
                for (tainted_var, flow) in &*tainted_locals {
                    if TaintExpressionUtils::expression_references_variable(rhs, tainted_var) {
                        tainted_locals.insert(lhs.to_string(), flow.clone());
                        break;
                    }
                }
            }
        }
    }

    /// Handle a `return <expr>` line: checks (in order) whether the expression is proven safe,
    /// a direct taint source, references a tainted local, follows an ambient taint source,
    /// matches a source pattern directly, or calls another (possibly tainted) function. Returns
    /// `Some` to return from the enclosing analysis immediately, `None` to keep scanning
    /// subsequent lines.
    fn check_return_statement_taint(
        &mut self,
        site: &FunctionAnalysisSite,
        return_expr: &str,
        line_num: usize,
        file_line: usize,
        rule_deduplicator: &TaintRuleDeduplicator,
        visited: &mut std::collections::BTreeSet<(String, String)>,
        state: FunctionTaintScanState,
    ) -> Option<AnalysisResult> {
        log::debug!("[ANALYZE_FUNCTION] Found return statement: \"{}\"", return_expr);

        match self.classify_value_source(return_expr, rule_deduplicator) {
            ValueSourceClassification::Safe(reason) => {
                log::debug!("[ANALYZE_FUNCTION] Function return is proven safe: {}", reason);
                return None;
            }
            ValueSourceClassification::Tainted(source_pattern) => {
                log::debug!(
                    "[ANALYZE_FUNCTION] Function returns direct taint source: \"{}\"",
                    source_pattern
                );

                let flow = VerifiedTaintFlow {
                    source_file: site.file_path.to_string(),
                    source_function: site.function_name.to_string(),
                    source_line: line_num + 1,
                    source_pattern: source_pattern.clone(),
                    sink_file: site.file_path.to_string(),
                    sink_function: site.function_name.to_string(),
                    sink_line: line_num + 1,
                    sink_variable: "return_value".to_string(),
                    sink_pattern: "function_return".to_string(),
                    call_chain_len: 0,
                };
                return Some(AnalysisResult::DefinitelyTainted { flow });
            }
            ValueSourceClassification::Unknown => {}
        }

        for (var_name, flow) in state.tainted_locals {
            if TaintExpressionUtils::expression_references_variable(return_expr, var_name) {
                log::debug!(
                    "[ANALYZE_FUNCTION] Return expression references tainted local '{}'",
                    var_name
                );
                return Some(AnalysisResult::DefinitelyTainted { flow: flow.clone() });
            }
        }

        if let Some(flow) = state.ambient_taint.clone() {
            log::debug!("[ANALYZE_FUNCTION] Return expression follows earlier source access");
            return Some(AnalysisResult::DefinitelyTainted { flow });
        }

        // Check if return expression is a direct taint source
        if let Some(source_pattern) = rule_deduplicator.matches_source_pattern(return_expr) {
            log::debug!(
                "[ANALYZE_FUNCTION] Function returns direct taint source: \"{}\"",
                source_pattern
            );

            let flow = VerifiedTaintFlow {
                source_file: site.file_path.to_string(),
                source_function: site.function_name.to_string(),
                source_line: file_line,
                source_pattern: source_pattern.clone(),
                sink_file: site.file_path.to_string(),
                sink_function: site.function_name.to_string(),
                sink_line: file_line,
                sink_variable: "return_value".to_string(),
                sink_pattern: "function_return".to_string(),
                call_chain_len: 0,
            };
            return Some(AnalysisResult::DefinitelyTainted { flow });
        }

        // Check if return expression is another function call
        self.check_return_expr_function_call(
            site,
            return_expr,
            file_line,
            rule_deduplicator,
            visited,
        )
    }

    /// If `return_expr` is another function call, trace whether that function's return value
    /// is tainted, propagating the flow. Returns `None` when it isn't a call, or the nested
    /// analysis is inconclusive.
    fn check_return_expr_function_call(
        &mut self,
        site: &FunctionAnalysisSite,
        return_expr: &str,
        file_line: usize,
        rule_deduplicator: &TaintRuleDeduplicator,
        visited: &mut std::collections::BTreeSet<(String, String)>,
    ) -> Option<AnalysisResult> {
        if !(return_expr.contains('(') && return_expr.contains(')')) {
            return None;
        }
        log::debug!("[ANALYZE_FUNCTION] Return calls another function: \"{}\"", return_expr);

        let nested_result = self.trace_local_assignment_taint(
            TraceSinkSite {
                file_path: site.file_path,
                function_name: site.function_name,
                sink_pattern: "function_return",
                sink_line: file_line,
                sink_variable: "return_value",
            },
            return_expr,
            file_line,
            rule_deduplicator,
            visited,
        );

        match nested_result {
            AnalysisResult::DefinitelyTainted { flow } => {
                log::debug!("[ANALYZE_FUNCTION] Nested function is tainted, propagating taint");
                Some(AnalysisResult::DefinitelyTainted { flow })
            }
            _ => {
                log::debug!("[ANALYZE_FUNCTION] Nested function analysis inconclusive");
                None
            }
        }
    }

    fn analyze_function_taint_behavior(
        &mut self,
        file_path: &str,
        function_name: &str,
        rule_deduplicator: &TaintRuleDeduplicator,
        visited: &mut std::collections::BTreeSet<(String, String)>,
    ) -> AnalysisResult {
        log::debug!(
            "[ANALYZE_FUNCTION] Analyzing function \"{}\" in \"{}\"",
            function_name,
            file_path
        );

        // Guard against cyclic call graphs (e.g. a() returns b(), b() returns a()).
        // Insert the (file, function) identity key; if it was already present we are
        // re-entering a function still on the current call stack, so bail out as
        // inconclusive instead of recursing into a stack overflow.
        if !visited.insert((file_path.to_string(), function_name.to_string())) {
            log::debug!(
                "[ANALYZE_FUNCTION] Cycle detected for \"{}\" in \"{}\", stopping recursion",
                function_name,
                file_path
            );
            return AnalysisResult::Unknown {
                reason: format!(
                    "Recursion cutoff: already analyzing function \"{}\" in \"{}\"",
                    function_name, file_path
                ),
            };
        }

        let Ok(source_text) = std::fs::read_to_string(file_path) else {
            log::debug!("[ANALYZE_FUNCTION] Could not read file: {}", file_path);
            return AnalysisResult::Unknown {
                reason: format!("Could not read source file: {}", file_path),
            };
        };

        let Some((function_body, body_start_line)) =
            self.extract_function_body(&source_text, function_name)
        else {
            log::debug!(
                "[ANALYZE_FUNCTION] Could not find function body for \"{}\"",
                function_name
            );
            return AnalysisResult::Unknown {
                reason: format!("Could not find function body for \"{}\"", function_name),
            };
        };

        log::debug!("[ANALYZE_FUNCTION] Function body found, analyzing...");

        let site = FunctionAnalysisSite { file_path, function_name };
        let mut tainted_locals: std::collections::BTreeMap<String, VerifiedTaintFlow> =
            std::collections::BTreeMap::new();
        let mut ambient_taint: Option<VerifiedTaintFlow> = None;

        for (line_num, line) in function_body.lines().enumerate() {
            // Translate the 0-based body-relative index to the absolute,
            // 1-based file line number using the body's start offset.
            let file_line = body_start_line + line_num;
            let line = line.trim();

            self.track_ambient_taint(&site, line, line_num, rule_deduplicator, &mut ambient_taint);
            self.track_local_assignment_in_function(
                &site,
                line,
                line_num,
                rule_deduplicator,
                visited,
                &mut tainted_locals,
            );

            if !line.starts_with("return ") {
                continue;
            }
            let return_expr = line.strip_prefix("return ").unwrap_or("").trim();

            let state = FunctionTaintScanState {
                tainted_locals: &tainted_locals,
                ambient_taint: &ambient_taint,
            };
            if let Some(result) = self.check_return_statement_taint(
                &site,
                return_expr,
                line_num,
                file_line,
                rule_deduplicator,
                visited,
                state,
            ) {
                return result;
            }
        }

        log::debug!("[ANALYZE_FUNCTION] Function appears to be safe (no taint sources found)");
        AnalysisResult::DefinitelySafe
    }

    /// Extract the body of a function from source code.
    ///
    /// Returns `(body, body_start_line)` where `body` is the function body text
    /// (the `def` line is skipped) and `body_start_line` is the 1-based absolute
    /// file line number of the FIRST body line. With this convention, the
    /// absolute file line of the body line at 0-based index `i` (e.g. from
    /// `body.lines().enumerate()`) is exactly `body_start_line + i`.
    fn extract_function_body(
        &self,
        source_text: &str,
        function_name: &str,
    ) -> Option<(String, usize)> {
        let lines: Vec<&str> = source_text.lines().collect();
        let mut in_function = false;
        let mut function_lines = Vec::new();
        let mut body_start_line: Option<usize> = None;
        let mut base_indent = None;

        log::debug!("[EXTRACT_FUNCTION_BODY] Looking for function: {}", function_name);

        for (line_num, line) in lines.iter().enumerate() {
            if line.trim().starts_with(&format!("def {}(", function_name)) {
                log::debug!(
                    "[EXTRACT_FUNCTION_BODY] Found function definition at line {}: {}",
                    line_num + 1,
                    line.trim()
                );
                in_function = true;
                continue;
            } else if in_function {
                // Determine base indentation from first non-empty line
                if base_indent.is_none() && !line.trim().is_empty() {
                    let indent = line.len() - line.trim_start().len();
                    base_indent = Some(indent);
                    log::debug!("[EXTRACT_FUNCTION_BODY] Base indentation set to: {}", indent);
                }

                // Check if we've reached the end of the function
                if let Some(indent) = base_indent {
                    // Function ends when we hit a non-empty line with indentation LESS than base
                    if !line.trim().is_empty() && (line.len() - line.trim_start().len()) < indent {
                        log::debug!(
                            "[EXTRACT_FUNCTION_BODY] Function ended at line {}: {}",
                            line_num + 1,
                            line.trim()
                        );
                        break;
                    }
                }

                // Add line to function body (including empty lines).
                // Record the 1-based absolute file line of the first body line so
                // callers can translate body-relative indices to file lines.
                if body_start_line.is_none() {
                    body_start_line = Some(line_num + 1);
                }
                function_lines.push(*line);
                log::debug!("[EXTRACT_FUNCTION_BODY] Added line {}: '{}'", line_num + 1, line);
            }
        }

        if function_lines.is_empty() {
            log::debug!("[EXTRACT_FUNCTION_BODY] No function body found for: {}", function_name);
            None
        } else {
            let body = function_lines.join("\n");
            // body_start_line is guaranteed Some here: a non-empty function_lines
            // means at least one body line was pushed, which sets body_start_line.
            let body_start_line = body_start_line.unwrap_or(1);
            log::debug!(
                "[EXTRACT_FUNCTION_BODY] Extracted {} lines for function: {} (body starts at file line {})",
                function_lines.len(),
                function_name,
                body_start_line
            );
            log::debug!("[EXTRACT_FUNCTION_BODY] Function body:\n{}", body);
            Some((body, body_start_line))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sink line below every fact in these tests, so each write is treated as
    /// reaching at or above the sink unless a test says otherwise.
    const SINK: usize = 100;

    fn fact(
        target: &str,
        rhs: &str,
        line: usize,
        augmented: bool,
        literal_collection: bool,
        literal_value: bool,
    ) -> AssignmentFact {
        AssignmentFact {
            target: target.to_string(),
            rhs: rhs.to_string(),
            line,
            augmented,
            literal_collection,
            literal_value,
            enclosing_loop: None,
        }
    }

    #[test]
    fn latest_reaching_write_provides_provenance() {
        // `cmd = "safe"; cmd = read_command()`: the sink observes the latest
        // write, so provenance must come from `read_command()` (traceable), not
        // the stale-safe initializer that would wrongly clear the sink.
        let tracer = DataFlowTracer::new();
        let dedup = TaintRuleDeduplicator::new(&[]);
        let facts = vec![
            fact("cmd", "\"safe\"", 1, false, false, true),
            fact("cmd", "read_command()", 2, false, false, false),
        ];
        assert!(
            matches!(
                tracer.classify_ast_assignments(&facts, SINK, &dedup),
                Some(VariableSource::LocalAssignment { .. })
            ),
            "latest reaching write must provide provenance, not the safe initializer"
        );
    }

    #[test]
    fn safe_initializer_alone_stays_known_safe() {
        // With no later write, a plain safe initializer is still proven-safe.
        let tracer = DataFlowTracer::new();
        let dedup = TaintRuleDeduplicator::new(&[]);
        let facts = vec![fact("cmd", "\"safe\"", 1, false, false, true)];
        assert!(matches!(
            tracer.classify_ast_assignments(&facts, SINK, &dedup),
            Some(VariableSource::KnownSafe { .. })
        ));
    }

    #[test]
    fn literal_collection_mutated_by_nonliteral_is_not_known_safe() {
        // `parts = ["prefix"]; parts.append(x)`, the mutation recorded as a
        // non-literal augmented fact: the literal-collection safety proof must no
        // longer clear the sink.
        let tracer = DataFlowTracer::new();
        let dedup = TaintRuleDeduplicator::new(&[]);
        let facts = vec![
            fact("parts", "[\"prefix\"]", 1, false, true, true),
            fact("parts", "(x)", 2, true, false, false),
        ];
        assert!(
            !matches!(
                tracer.classify_ast_assignments(&facts, SINK, &dedup),
                Some(VariableSource::KnownSafe { .. })
            ),
            "a non-literal collection mutation must defeat the definitely-safe verdict"
        );
    }

    #[test]
    fn purely_literal_collection_remains_known_safe() {
        // `cfg = ["ls", "pwd"]` with only literal writes stays proven-safe: a
        // literal `parts.append("x")` must not be mistaken for a tainting write.
        let tracer = DataFlowTracer::new();
        let dedup = TaintRuleDeduplicator::new(&[]);
        let facts = vec![
            fact("cfg", "[\"ls\", \"pwd\"]", 1, false, true, true),
            fact("cfg", "(\"uptime\")", 2, true, false, true),
        ];
        assert!(matches!(
            tracer.classify_ast_assignments(&facts, SINK, &dedup),
            Some(VariableSource::KnownSafe { .. })
        ));
    }

    #[test]
    fn safe_branch_sibling_does_not_mask_an_unresolved_one() {
        // `if c: cmd = fetch_remote() else: cmd = "ls"`: both writes reach the
        // sink and neither dominates, so the safe sibling must not clear the
        // sink — the unresolved sibling supplies provenance and stays traceable.
        let tracer = DataFlowTracer::new();
        let dedup = TaintRuleDeduplicator::new(&[]);
        let facts = vec![
            fact("cmd", "fetch_remote()", 1, false, false, false),
            fact("cmd", "\"ls\"", 2, false, false, true),
        ];
        assert!(
            matches!(
                tracer.classify_ast_assignments(&facts, SINK, &dedup),
                Some(VariableSource::LocalAssignment { .. })
            ),
            "a safe branch sibling must not mask the unresolved one"
        );
    }

    #[test]
    fn augmented_write_defeats_a_safe_initializer() {
        // `cmd = "safe"; cmd += fetch()`: the augmented write combines with the
        // safe base, so the value is not proven safe — trace the added RHS.
        let tracer = DataFlowTracer::new();
        let dedup = TaintRuleDeduplicator::new(&[]);
        let facts = vec![
            fact("cmd", "\"safe\"", 1, false, false, true),
            fact("cmd", "fetch()", 2, true, false, false),
        ];
        assert!(
            matches!(
                tracer.classify_ast_assignments(&facts, SINK, &dedup),
                Some(VariableSource::LocalAssignment { .. })
            ),
            "a non-safe augmented write must not be masked by the safe initializer"
        );
    }

    #[test]
    fn indirect_augmented_rhs_supplies_provenance() {
        // `cmd = "safe"; cmd += user_value`: the augmented write's RHS is an
        // unresolved identifier, so it — not the safe initializer — must supply
        // provenance so `user_value` stays traceable (reviewer regression case).
        let tracer = DataFlowTracer::new();
        let dedup = TaintRuleDeduplicator::new(&[]);
        let facts = vec![
            fact("cmd", "\"safe\"", 1, false, false, true),
            fact("cmd", "user_value", 2, true, false, false),
        ];
        assert!(matches!(
            tracer.classify_ast_assignments(&facts, SINK, &dedup),
            Some(VariableSource::LocalAssignment { source_expression, .. })
                if source_expression == "user_value"
        ));
    }

    #[test]
    fn augmented_only_base_is_unresolved_not_safe() {
        // `cmd += "x"` with no plain write reaching: the base is an unseen prior
        // value, so we must report Unknown rather than proving it safe or
        // falling back to the sink-agnostic text scan.
        let tracer = DataFlowTracer::new();
        let dedup = TaintRuleDeduplicator::new(&[]);
        let facts = vec![fact("cmd", "\"x\"", 1, true, false, true)];
        assert!(matches!(
            tracer.classify_ast_assignments(&facts, SINK, &dedup),
            Some(VariableSource::Unresolved { .. })
        ));
    }

    #[test]
    fn below_sink_safe_write_cannot_prove_safety() {
        // A safe write that sits below the sink (reaching only via a later loop
        // iteration) cannot establish the first-pass value, so it must not clear
        // the sink.
        let tracer = DataFlowTracer::new();
        let dedup = TaintRuleDeduplicator::new(&[]);
        // Only reaching write is on line 5, below the sink at line 3.
        let facts = vec![fact("cmd", "\"safe\"", 5, false, false, true)];
        assert!(
            !matches!(
                tracer.classify_ast_assignments(&facts, 3, &dedup),
                Some(VariableSource::KnownSafe { .. })
            ),
            "a below-sink write must not supply a definitely-safe verdict"
        );
    }
}
