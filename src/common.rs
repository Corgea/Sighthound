use anyhow::Result;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;
use tree_sitter::Node;

pub use crate::models::LanguageInfo;
pub struct CommonUtils;

impl CommonUtils {
    /// Unified pattern matching supporting exact, wildcard, glob, and regex
    /// This is the single source of truth for all pattern matching in the codebase
    pub fn matches_unified_pattern(pattern: &str, text: &str) -> bool {
        // Fast exact match
        if pattern == text {
            return true;
        }

        // Handle regex patterns (prefix or escaped chars)
        if let Some(stripped) = pattern.strip_prefix("regex:") {
            return Self::matches_regex(stripped, text);
        }
        if pattern.contains("\\\\") || pattern.contains("\\.") {
            return Self::matches_regex(pattern, text);
        }

        // Handle escaped patterns (taint rules use escaped chars)
        if pattern.contains("\\") {
            return Self::matches_escaped_pattern(pattern, text);
        }

        // Handle glob/wildcard patterns
        if pattern.contains('*') {
            return Self::matches_glob_pattern(pattern, text);
        }

        // Default: substring matching
        text.contains(pattern)
    }

    /// Specialized pattern matching for file paths and names
    pub fn matches_file_pattern(pattern: &str, file_path: &str) -> bool {
        // Try full path match first
        if Self::matches_unified_pattern(pattern, file_path) {
            return true;
        }

        // Try filename only
        if let Some(filename) = std::path::Path::new(file_path).file_name() {
            if let Some(filename_str) = filename.to_str() {
                return Self::matches_unified_pattern(pattern, filename_str);
            }
        }

        false
    }

    /// Specialized pattern matching for taint analysis with context awareness
    pub fn matches_taint_pattern(pattern: &str, text: &str) -> bool {
        // Skip string literals and metadata
        if text.trim().starts_with('"')
            || text.trim().starts_with("'")
            || text.contains("__all__")
            || text.contains("__version__")
        {
            return false;
        }

        // Special handling for DOM property patterns like *.innerHTML
        if let Some(property) = pattern.strip_prefix("*.") {
            // Remove "*."

            // Handle TypeScript casting syntax: (element.innerHTML as Type) = value
            if text.contains(&format!(".{}", property)) {
                // Check for assignment context
                if text.contains('=') && !text.contains("==") && !text.contains("!=") {
                    return true;
                }
            }
        }

        Self::matches_unified_pattern(pattern, text)
    }

    /// Context-aware taint pattern matching with additional filtering
    pub fn matches_taint_pattern_in_context(
        pattern: &str,
        text: &str,
        _node_kind: &str,
        _context: &str,
    ) -> bool {
        // Skip string literals in any context
        if text.starts_with('"')
            || text.starts_with("'")
            || text.starts_with("b\"")
            || text.starts_with("b'")
        {
            return false;
        }

        // Skip __all__ lists and other metadata
        if text.contains("__all__") || text.contains("__version__") || text.contains("__author__") {
            return false;
        }

        Self::matches_unified_pattern(pattern, text)
    }

    /// General rule pattern matching (replaces old matches_pattern)
    pub fn matches_rule_pattern(pattern: &str, text: &str) -> bool {
        // Fast exact match
        if pattern == text {
            return true;
        }

        // Use unified pattern matching for consistency
        Self::matches_unified_pattern(pattern, text)
    }

    /// Enhanced glob pattern matching for file paths and function names
    /// (Used internally by unified pattern matching)
    fn matches_glob_pattern(pattern: &str, text: &str) -> bool {
        if !pattern.contains('*') {
            return pattern == text;
        }

        // Use glob library for complex patterns
        if let Ok(glob_pattern) = glob::Pattern::new(pattern) {
            if glob_pattern.matches(text) {
                return true;
            }

            // Also try matching against just the filename
            if let Some(filename) = std::path::Path::new(text).file_name() {
                if let Some(filename_str) = filename.to_str() {
                    if glob_pattern.matches(filename_str) {
                        return true;
                    }
                }
            }
        }

        // Fallback to simple wildcard matching
        Self::simple_glob_match(pattern, text)
    }

    /// Simple glob matching for basic wildcard patterns
    fn simple_glob_match(pattern: &str, text: &str) -> bool {
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.is_empty() {
            return true;
        }

        if parts.len() == 2 {
            let prefix = parts[0];
            let suffix = parts[1];

            if prefix.is_empty() && suffix.is_empty() {
                return true; // Pattern is just "*"
            } else if prefix.is_empty() {
                return text.ends_with(suffix);
            } else if suffix.is_empty() {
                return text.starts_with(prefix);
            } else {
                return text.starts_with(prefix)
                    && text.ends_with(suffix)
                    && text.len() >= prefix.len() + suffix.len();
            }
        }

        // For complex patterns, check that all non-empty parts exist in order
        let mut current_pos = 0;
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                continue;
            }

            if i == 0 {
                // First part must match at start
                if !text.starts_with(part) {
                    return false;
                }
                current_pos = part.len();
            } else if i == parts.len() - 1 {
                // Last part must match at end
                return text[current_pos..].ends_with(part);
            } else {
                // Middle parts must exist in order
                if let Some(pos) = text[current_pos..].find(part) {
                    current_pos += pos + part.len();
                } else {
                    return false;
                }
            }
        }

        true
    }

    /// Match regex patterns with caching for performance
    fn matches_regex(pattern: &str, text: &str) -> bool {
        static REGEX_CACHE: Lazy<Mutex<HashMap<String, regex::Regex>>> =
            Lazy::new(|| Mutex::new(HashMap::new()));

        // Fast path: try cache first
        if let Some(re) = REGEX_CACHE.lock().unwrap().get(pattern) {
            return re.is_match(text);
        }

        match regex::Regex::new(pattern) {
            Ok(re) => {
                let is_match = re.is_match(text);
                // Cache the compiled regex (keep cache small to avoid unbounded growth)
                let mut cache = REGEX_CACHE.lock().unwrap();
                if cache.len() < 256 {
                    cache.insert(pattern.to_string(), re);
                }
                is_match
            }
            Err(_) => false,
        }
    }

    /// Handle escaped patterns from taint rules (eval\(, os\.system, etc.)
    fn matches_escaped_pattern(pattern: &str, text: &str) -> bool {
        // Clean escaped characters for taint patterns
        let cleaned_pattern = pattern
            .replace("\\(", "(")
            .replace("\\)", ")")
            .replace("\\.", ".")
            .replace("\\\\", "\\");

        // For patterns like "os.listdir", ensure we match the exact module.function pattern
        // This prevents "listdir" from matching "list(" and other false positives
        if cleaned_pattern.contains('.') {
            // Module.function pattern - require exact match with proper word boundaries
            let parts: Vec<&str> = cleaned_pattern.split('.').collect();
            if parts.len() == 2 {
                let module_name = parts[0];
                let func_name = parts[1];

                // Look for exact "module.function" pattern in text
                let full_pattern = format!("{}.{}", module_name, func_name);
                return text.contains(&full_pattern);
            }
        }

        // For function call patterns ending with '(', ensure exact function name match
        if cleaned_pattern.ends_with('(') {
            let func_name = &cleaned_pattern[..cleaned_pattern.len() - 1];

            // Special handling for module.function( patterns
            if func_name.contains('.') {
                return text.contains(&cleaned_pattern);
            }

            // Look for the function name followed by '(' in the text
            if let Some(pos) = text.find(&format!("{}(", func_name)) {
                // Ensure it's a word boundary (not part of a larger identifier)
                let before_pos = if pos > 0 { pos - 1 } else { 0 };
                let char_before = text.chars().nth(before_pos);

                return char_before.is_none_or(|c| !c.is_alphanumeric() && c != '_');
            }
            return false;
        }

        text.contains(&cleaned_pattern)
    }

    /// Match any pattern from a list (common use case)
    pub fn matches_any_pattern(patterns: &[String], text: &str) -> bool {
        patterns
            .iter()
            .any(|pattern| Self::matches_unified_pattern(pattern, text))
    }

    /// Extract variable name from assignment expression with configurable behavior
    pub fn extract_variable_from_assignment(
        assignment_text: &str,
        return_empty_on_none: bool,
    ) -> Option<String> {
        let eq_pos = assignment_text.find('=')?;
        let left_side = assignment_text[..eq_pos].trim();

        // Handle multiple assignments: a = b = c (take first)
        let target = left_side.split('=').next()?.trim();

        let result = Self::extract_clean_variable_name(target);

        if return_empty_on_none && result.is_none() {
            Some(String::new())
        } else {
            result
        }
    }

    /// Extract clean variable name from complex expressions
    fn extract_clean_variable_name(expr: &str) -> Option<String> {
        // Handle patterns like: obj.attr, arr[index], simple_var
        if expr.contains('.') {
            // For obj.attr assignments, the object is modified, not a new variable
            return None;
        }
        if expr.contains('[') {
            // For arr[index], extract arr
            return expr.split('[').next().map(|s| s.trim().to_string());
        }

        // Handle JavaScript declarations: const/let/var variable_name
        let tokens: Vec<&str> = expr.split_whitespace().collect();
        if tokens.len() >= 2 && matches!(tokens[0], "const" | "let" | "var") {
            // Return the variable name after the declaration keyword
            if Self::is_valid_variable_name(tokens[1]) {
                return Some(tokens[1].to_string());
            }
        }

        // Extract final identifier from whitespace-separated expression
        expr.split_whitespace()
            .last()
            .filter(|s| Self::is_valid_variable_name(s))
            .map(|s| s.to_string())
    }

    /// Extract all variable identifiers from code expression
    /// Extract simple variable identifiers from code expression (separator-based)
    pub fn extract_simple_variables(expr: &str) -> Vec<String> {
        let separators = [
            ' ', '+', '-', '*', '/', '(', ')', '[', ']', '{', '}', ',', '.', '=',
        ];

        expr.split(&separators)
            .map(|s| s.trim())
            .filter(|s| Self::is_valid_variable_name(s))
            .filter(|s| !Self::is_keyword_or_builtin(s))
            .map(|s| s.to_string())
            .collect()
    }

    /// Extract all variables from an expression, including complex cases
    /// Extract all variables from an expression, including complex patterns (comprehensive)
    pub fn extract_all_variables(expr: &str) -> Vec<String> {
        let mut variables = Vec::new();

        // Direct variable usage
        if let Some(var) = Self::extract_direct_variable(expr) {
            variables.push(var);
        }

        // Assignment variables (both sides)
        if let Some(var) = Self::extract_variable_from_assignment(expr, false) {
            variables.push(var);
        }

        // Extract variables from the right side of assignments
        if let Some(eq_pos) = expr.find('=') {
            let right_side = &expr[eq_pos + 1..].trim();
            // Recursively extract from right side, but avoid infinite recursion
            if !right_side.contains('=') || right_side.contains("==") {
                variables.extend(Self::extract_simple_variables(right_side));
            }
        }

        // F-string variables: f"echo {user_input}"
        variables.extend(Self::extract_f_string_variables(expr));

        // JavaScript/TypeScript template literals: `hello ${user_input}`
        variables.extend(Self::extract_template_literal_variables(expr));

        // Format string variables: "echo {}".format(user_input)
        variables.extend(Self::extract_format_variables(expr));

        // String concatenation: "echo " + user_input
        variables.extend(Self::extract_concatenation_variables(expr));

        // Function call arguments: eval(user_input)
        variables.extend(Self::extract_function_arguments(expr).unwrap_or_default());

        // Remove duplicates and invalid names
        variables.sort();
        variables.dedup();
        variables
            .into_iter()
            .filter(|v| Self::is_valid_variable_name(v))
            .collect()
    }

    /// Extract direct variable from simple expressions
    fn extract_direct_variable(expr: &str) -> Option<String> {
        let trimmed = expr.trim();
        if Self::is_valid_variable_name(trimmed) {
            return Some(trimmed.to_string());
        }
        None
    }

    /// Extract variables from F-strings
    pub fn extract_f_string_variables(expr: &str) -> Vec<String> {
        log::debug!("[F_STRING_EXTRACT] Processing: '{}'", expr);

        let mut variables = Vec::new();
        let mut brace_depth = 0usize;
        let mut current_start: Option<usize> = None;
        let chars: Vec<char> = expr.chars().collect();

        let mut i = 0;
        while i < chars.len() {
            // Skip escaped braces `{{` or `}}`
            if i + 1 < chars.len()
                && ((chars[i] == '{' && chars[i + 1] == '{')
                    || (chars[i] == '}' && chars[i + 1] == '}'))
            {
                i += 2;
                continue;
            }

            match chars[i] {
                '{' => {
                    brace_depth += 1;
                    if brace_depth == 1 {
                        current_start = Some(i + 1);
                    }
                }
                '}' => {
                    if brace_depth > 0 {
                        brace_depth -= 1;
                        if brace_depth == 0 {
                            if let Some(start) = current_start.take() {
                                // Extract the variable using character indices, not byte indices
                                let raw_var: String = chars[start..i].iter().collect();
                                let raw_var = raw_var.trim();
                                // Strip format specifiers after ':' or '!'
                                let clean_var = raw_var
                                    .split([':', '!'].as_ref())
                                    .next()
                                    .unwrap_or("")
                                    .trim();
                                if Self::is_valid_variable_name(clean_var) {
                                    log::debug!("[F_STRING_EXTRACT] Found variable: {}", clean_var);
                                    variables.push(clean_var.to_string());
                                } else {
                                    // For complex expressions, try to extract simple variables
                                    variables.extend(Self::extract_simple_variables(clean_var));
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
            i += 1;
        }

        variables
    }

    /// Extract variables from JavaScript/TypeScript template literals
    pub fn extract_template_literal_variables(expr: &str) -> Vec<String> {
        log::debug!("[TEMPLATE_LITERAL_EXTRACT] Processing: '{}'", expr);

        let mut variables = Vec::new();
        let mut dollar_brace_depth = 0usize;
        let mut current_start: Option<usize> = None;
        let chars: Vec<char> = expr.chars().collect();

        let mut i = 0;
        while i < chars.len() {
            // Look for ${...} patterns
            if i + 1 < chars.len() && chars[i] == '$' && chars[i + 1] == '{' {
                dollar_brace_depth += 1;
                if dollar_brace_depth == 1 {
                    current_start = Some(i + 2); // Skip ${
                }
                i += 2;
                continue;
            }

            if chars[i] == '{' && dollar_brace_depth > 0 {
                dollar_brace_depth += 1;
            } else if chars[i] == '}' && dollar_brace_depth > 0 {
                dollar_brace_depth -= 1;
                if dollar_brace_depth == 0 {
                    if let Some(start) = current_start.take() {
                        // Extract the expression inside ${}
                        let raw_expr: String = chars[start..i].iter().collect();
                        let raw_expr = raw_expr.trim();

                        log::debug!(
                            "[TEMPLATE_LITERAL_EXTRACT] Found expression: '{}'",
                            raw_expr
                        );

                        // Extract variables from the expression
                        variables.extend(Self::extract_all_variables(raw_expr));
                    }
                }
            }

            i += 1;
        }

        // Also extract assignment target if this is an assignment with template literal
        if expr.contains('=') && expr.contains('`') {
            if let Some(var) = Self::extract_variable_from_assignment(expr, false) {
                variables.push(var);
            }
        }

        variables
    }

    /// Extract variables from format strings
    pub fn extract_format_variables(expr: &str) -> Vec<String> {
        // Handle .format() calls
        if let Some(format_start) = expr.find(".format(") {
            let args_part = &expr[format_start + 8..];
            if let Some(args_end) = args_part.rfind(')') {
                let args = &args_part[..args_end];
                return Self::extract_function_arguments(args).unwrap_or_default();
            }
        }

        Vec::new()
    }

    /// Extract variables from string concatenation
    fn extract_concatenation_variables(expr: &str) -> Vec<String> {
        let mut variables = Vec::new();

        // Handle + concatenation: "echo " + user_input
        let parts: Vec<&str> = expr.split('+').collect();
        for part in parts {
            let trimmed = part.trim();
            if Self::is_valid_variable_name(trimmed) {
                variables.push(trimmed.to_string());
            }
        }

        variables
    }

    /// Extract variable from various code patterns (function calls, assignments, etc.)
    /// Extract variable from various code patterns (assignments, function calls, etc.)
    pub fn extract_variable_from_pattern(code: &str) -> Option<String> {
        // Try assignment pattern first
        if let Some(var) = Self::extract_variable_from_assignment(code, false) {
            return Some(var);
        }

        // Try function call pattern
        if let Some(paren_pos) = code.find('(') {
            let before_paren = &code[..paren_pos];
            if let Some(func_name) = before_paren.split_whitespace().last() {
                if let Some(dot_pos) = func_name.rfind('.') {
                    return Some(func_name[..dot_pos].to_string());
                } else if Self::is_valid_variable_name(func_name) {
                    return Some(func_name.to_string());
                }
            }
        }

        None
    }

    /// Extract function arguments from call expression
    pub fn extract_function_arguments(call_expr: &str) -> Option<Vec<String>> {
        let start = call_expr.find('(')?;
        let end = call_expr.rfind(')')?;

        // Validate bounds before slicing to prevent panic
        if start + 1 >= end {
            return Some(Vec::new()); // Return empty args for malformed expressions
        }

        let args_str = &call_expr[start + 1..end];

        Some(
            args_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty() && !s.starts_with('"') && !s.starts_with('\''))
                .collect(),
        )
    }

    /// Check if assignment text is valid (not comparison)
    pub fn is_valid_assignment_text(text: &str) -> bool {
        text.contains('=')
            && !text.contains("==")
            && !text.contains("!=")
            && !text.contains("<=")
            && !text.contains(">=")
    }

    /// Check if string is a valid variable name
    pub fn is_valid_variable_name(s: &str) -> bool {
        !s.is_empty()
            && s.chars().all(|c| c.is_alphanumeric() || c == '_')
            && !s.chars().next().unwrap().is_ascii_digit()
    }

    /// Check if string is a keyword or builtin (consolidated from multiple implementations)
    pub fn is_keyword_or_builtin(s: &str) -> bool {
        matches!(
            s,
            // Python keywords
            "and" | "as" | "assert" | "break" | "class" | "continue" | "def" | "del" | "elif" |
            "else" | "except" | "exec" | "finally" | "for" | "from" | "global" | "if" | "import" |
            "in" | "is" | "lambda" | "not" | "or" | "pass" | "print" | "raise" | "return" |
            "try" | "while" | "with" | "yield" |

            // Python builtins
            "True" | "False" | "None" | "str" | "int" | "float" | "list" | "dict" | "set" |
            "tuple" | "bool" | "len" | "range" | "enumerate" | "zip" | "map" | "filter" |

            // SQL keywords
            "SELECT" | "FROM" | "WHERE" | "INSERT" | "UPDATE" | "DELETE" | "CREATE" | "DROP" |
            "ALTER" | "INDEX" | "TABLE" | "DATABASE" | "UNION" | "JOIN" | "AND" | "OR" |

            // JavaScript keywords (unique only)
            "var" | "let" | "const" | "function" | "do" |
            "switch" | "case" | "default" | "typeof" |
            "instanceof" | "new" | "this" | "super" | "extends" | "implements" |

            // Common database/web terms
            "cursor" | "execute" | "query" | "request" | "response" | "session" | "document" |
            "window" | "console" | "undefined" | "null"
        )
    }

    // =========================================================================
    // UNIFIED FILE OPERATIONS (consolidated from core_utils.rs)
    // =========================================================================

    /// Detect syntax for syntax highlighting (moved from core.rs)
    pub fn detect_syntax(file_path: &str) -> &'static str {
        match std::path::Path::new(file_path)
            .extension()
            .and_then(|e| e.to_str())
        {
            Some("py") => "Python",
            Some("js") | Some("mjs") => "JavaScript",
            Some("ts") | Some("tsx") => "TypeScript",
            Some("rs") => "Rust",
            Some("java") => "Java",
            Some("html") => "HTML",
            Some("css") => "CSS",
            Some("json") => "JSON",
            Some("md") => "Markdown",
            Some("sh") => "Shell",
            Some("go") => "Go",
            Some("php") => "PHP",
            Some("rb") => "Ruby",
            Some("swift") => "Swift",
            Some("kt") => "Kotlin",
            Some("scala") => "Scala",
            Some("c") => "C",
            Some("cpp") | Some("cc") | Some("cxx") | Some("hpp") => "C++",
            Some("cs") => "C#",
            Some("sql") => "SQL",
            _ => "Plain Text",
        }
    }

    /// Apply function to all children and collect results
    pub fn map_children<F, T>(node: &Node, mut mapper: F) -> Vec<T>
    where
        F: FnMut(&Node) -> Option<T>,
    {
        let mut results = Vec::new();
        let mut cursor = node.walk();

        if cursor.goto_first_child() {
            loop {
                if let Some(result) = mapper(&cursor.node()) {
                    results.push(result);
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        results
    }

    /// Apply function to all children (no return value)
    pub fn for_each_child<F>(node: &Node, mut visitor: F)
    where
        F: FnMut(&Node),
    {
        let mut cursor = node.walk();

        if cursor.goto_first_child() {
            loop {
                visitor(&cursor.node());
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    /// Find first child matching predicate
    pub fn find_child<'a, F>(node: &'a Node<'a>, mut predicate: F) -> Option<Node<'a>>
    where
        F: FnMut(&Node) -> bool,
    {
        let mut cursor = node.walk();

        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if predicate(&child) {
                    return Some(child);
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        None
    }

    /// Recursive tree traversal with depth limit
    pub fn traverse_recursive<F>(node: &Node, visitor: &mut F, max_depth: usize)
    where
        F: FnMut(&Node),
    {
        if max_depth == 0 {
            return;
        }

        visitor(node);

        Self::for_each_child(node, |child| {
            Self::traverse_recursive(child, visitor, max_depth - 1);
        });
    }

    /// Validate required CLI parameter combination
    pub fn validate_cli_params(
        language: &Option<String>,
        rules_path: &Option<String>,
        use_embedded_rules: bool,
        use_file_rules: bool,
    ) -> Result<()> {
        // Resolve the actual embedded rules setting (use_file_rules overrides use_embedded_rules)
        let should_use_embedded = use_embedded_rules && !use_file_rules;

        match (language, rules_path, should_use_embedded) {
            // Explicit mode with embedded rules
            (Some(_), None, true) => Ok(()),
            // Explicit mode with file rules
            (Some(_), Some(_), false) => Ok(()),
            // Auto-detection mode (embedded or file rules)
            (None, None, _) => Ok(()),
            // Invalid combinations
            (Some(_), Some(_), true) => Err(anyhow::anyhow!(
                "Cannot specify both --rules-path and embedded rules. Use --use-file-rules to disable embedded rules"
            )),
            (Some(_), None, false) => Err(anyhow::anyhow!(
                "Must specify --rules-path when using explicit mode with --use-file-rules"
            )),
            (None, Some(_), _) => Err(anyhow::anyhow!(
                "Cannot specify --rules-path without language in auto-detection mode"
            )),
        }
    }
}
