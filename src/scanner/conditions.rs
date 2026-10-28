use crate::language::LanguageSupport;
use crate::parser::get_node_text;
use crate::rules::Condition;
use crate::rules::{is_literal_node, match_any_pattern, match_pattern};

fn unwrap_keyword_argument(node: tree_sitter::Node) -> tree_sitter::Node {
    if node.kind() == "keyword_argument"
        && let Some(val_node) = node.child_by_field_name("value")
    {
        return val_node;
    }
    node
}

fn get_target_argument<'a>(
    args_node: tree_sitter::Node<'a>,
    position: usize,
    source: &[u8],
) -> Option<tree_sitter::Node<'a>> {
    for i in 0..args_node.named_child_count() {
        if let Some(arg) = args_node.named_child(i as u32)
            && arg.kind() == "keyword_argument"
            && let Some(name_node) = arg.child_by_field_name("name")
        {
            let name_text = get_node_text(&name_node, source);
            if name_text == "query" || name_text == "operation" || name_text == "sql" {
                return Some(arg);
            }
        }
    }
    args_node.named_child(position as u32)
}

/// Check if all AST conditions are satisfied for a node
pub fn check_ast_conditions(
    conditions: &[Condition],
    node: &tree_sitter::Node,
    source: &[u8],
    language_support: &dyn LanguageSupport,
) -> bool {
    conditions
        .iter()
        .all(|condition| check_single_condition(node, source, condition, language_support))
}

/// Check a single AST condition
pub fn check_single_condition(
    node: &tree_sitter::Node,
    source: &[u8],
    condition: &Condition,
    language_support: &dyn LanguageSupport,
) -> bool {
    match condition.condition_type.as_deref().unwrap_or("") {
        "has_argument" => check_has_argument_condition(node, source, condition, language_support),
        "in_context" => check_in_context_condition(node, condition),
        "has_parent" => check_has_parent_condition(node, condition),
        "not_literal" => check_not_literal_condition(node, source, condition, language_support),
        "has_ancestor" => check_has_ancestor_condition(node, condition),
        "argument_not_sanitized" => {
            check_argument_not_sanitized_condition(node, source, condition, language_support)
        }
        "has_sibling_pattern" => check_has_sibling_pattern_condition(node, source, condition),
        "ruby_unsafe_command_injection" => {
            check_ruby_unsafe_command_injection(node, source, language_support)
        }
        "node_kind" => {
            condition.node_type.as_deref().is_some_and(|expected| node.kind() == expected)
        }
        _ => false,
    }
}

/// Check if function has an argument matching the condition
pub fn check_has_argument_condition(
    node: &tree_sitter::Node,
    source: &[u8],
    condition: &Condition,
    language_support: &dyn LanguageSupport,
) -> bool {
    if let Some(args_node) = language_support.get_arguments_node(node) {
        // If specific position is specified, check only that argument
        if let Some(position) = condition.argument_position {
            if let Some(arg) = get_target_argument(args_node, position, source) {
                return check_argument_matches(arg, source, condition);
            }
            return false;
        }

        // Otherwise check all arguments
        for i in 0..args_node.named_child_count() {
            if let Some(arg) = args_node.named_child(i as u32)
                && check_argument_matches(arg, source, condition)
            {
                return true;
            }
        }
    }
    false
}

/// Check if an argument node matches the given condition
pub fn check_argument_matches(
    arg: tree_sitter::Node,
    source: &[u8],
    condition: &Condition,
) -> bool {
    let unwrapped = unwrap_keyword_argument(arg);
    let arg_text = get_node_text(&unwrapped, source);

    // Check node type if specified
    if let Some(expected_type) = &condition.node_type
        && unwrapped.kind() != expected_type
    {
        return false;
    }

    // Check pattern(s)
    if let Some(pattern) = &condition.pattern {
        return match_pattern(pattern, &arg_text);
    }

    if let Some(patterns) = &condition.patterns {
        return match_any_pattern(patterns, &arg_text);
    }

    true
}

/// Check if node is in a specific context (e.g., not in comments/strings)
pub fn check_in_context_condition(node: &tree_sitter::Node, condition: &Condition) -> bool {
    if let Some(not_in) = &condition.not_in
        && let Some(parent) = node.parent()
    {
        if not_in.contains(&"comment".to_string()) && parent.kind() == "comment" {
            return false;
        }
        if not_in.contains(&"string".to_string()) && parent.kind() == "string" {
            return false;
        }
    }
    true
}

/// Check if node has a specific parent type
pub fn check_has_parent_condition(node: &tree_sitter::Node, condition: &Condition) -> bool {
    if let Some(parent_type) = &condition.parent_type {
        if let Some(parent) = node.parent() {
            return parent.kind() == parent_type;
        }
        return false;
    }
    true
}

/// Check if arguments are not literal values
pub fn check_not_literal_condition(
    node: &tree_sitter::Node,
    source: &[u8],
    condition: &Condition,
    language_support: &dyn LanguageSupport,
) -> bool {
    if let Some(args_node) = language_support.get_arguments_node(node) {
        if let Some(position) = condition.argument_position {
            if let Some(arg) = get_target_argument(args_node, position, source) {
                let unwrapped = unwrap_keyword_argument(arg);
                return !is_literal_node(&unwrapped);
            }
        } else {
            // Check if any argument is not literal
            for i in 0..args_node.named_child_count() {
                if let Some(arg) = args_node.named_child(i as u32)
                    && !is_literal_node(&unwrap_keyword_argument(arg))
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Check if node has specific ancestor types
pub fn check_has_ancestor_condition(node: &tree_sitter::Node, condition: &Condition) -> bool {
    if let Some(ancestor_types) = &condition.ancestor_types {
        let mut current = node.parent();
        let mut depth = 0;

        while let Some(parent) = current {
            if depth > 20 {
                // Limit search depth
                break;
            }

            if ancestor_types.contains(&parent.kind().to_string()) {
                return true;
            }

            current = parent.parent();
            depth += 1;
        }
    }
    false
}

/// Check if arguments are not sanitized
pub fn check_argument_not_sanitized_condition(
    node: &tree_sitter::Node,
    source: &[u8],
    condition: &Condition,
    language_support: &dyn LanguageSupport,
) -> bool {
    if let Some(sanitizer_patterns) = &condition.patterns {
        if let Some(args_node) = language_support.get_arguments_node(node) {
            for i in 0..args_node.named_child_count() {
                if let Some(arg) = args_node.named_child(i as u32) {
                    let unwrapped = unwrap_keyword_argument(arg);
                    let arg_text = get_node_text(&unwrapped, source);

                    // Check if argument contains any sanitization patterns
                    for sanitizer in sanitizer_patterns {
                        if match_pattern(sanitizer, &arg_text) {
                            return false; // Found sanitization, so condition fails
                        }
                    }
                }
            }
        }
        return true; // No sanitization found
    }
    true
}

/// Check if node has siblings matching patterns
pub fn check_has_sibling_pattern_condition(
    node: &tree_sitter::Node,
    source: &[u8],
    condition: &Condition,
) -> bool {
    if let Some(patterns) = &condition.patterns
        && let Some(parent) = node.parent()
    {
        let mut cursor = parent.walk();
        if cursor.goto_first_child() {
            loop {
                let sibling = cursor.node();
                if sibling != *node {
                    let sibling_text = get_node_text(&sibling, source);
                    if match_any_pattern(patterns, &sibling_text) {
                        return true;
                    }
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }
    false
}

fn clean_ruby_string(s: String) -> String {
    let mut val = s.trim().to_string();
    if ((val.starts_with('"') && val.ends_with('"'))
        || (val.starts_with('\'') && val.ends_with('\'')))
        && val.len() >= 2
    {
        val = val[1..val.len() - 1].to_string();
    }
    if val.starts_with(':') {
        val = val[1..].to_string();
    }
    val.trim().to_string()
}

/// Extract shell name from a path or executable string, e.g. "/bin/sh" -> "sh", "C:\Windows\cmd.exe" -> "cmd"
fn extract_shell_name(text: &str) -> Option<String> {
    let cleaned = text.trim();
    if cleaned.is_empty() {
        return None;
    }
    let std_path = cleaned.replace('\\', "/");
    let filename = std_path.rsplit('/').next().unwrap_or(cleaned).to_ascii_lowercase();
    let name_without_ext = filename.strip_suffix(".exe").unwrap_or(&filename).to_string();

    if matches!(
        name_without_ext.as_str(),
        "sh" | "bash"
            | "cmd"
            | "powershell"
            | "pwsh"
            | "zsh"
            | "ksh"
            | "csh"
            | "tcsh"
            | "fish"
            | "dash"
            | "ash"
    ) {
        Some(name_without_ext)
    } else {
        None
    }
}

fn is_posix_shell(shell_name: &str) -> bool {
    matches!(shell_name, "sh" | "bash" | "zsh" | "ksh" | "csh" | "tcsh" | "dash" | "ash" | "fish")
}

fn is_posix_command_flag(arg: &str) -> bool {
    arg == "-c"
        || (arg.starts_with('-')
            && !arg.starts_with("--")
            && arg.ends_with('c')
            && arg.len() >= 2
            && arg[1..].chars().all(|ch| ch.is_ascii_alphabetic()))
}

fn is_powershell_command_flag(arg: &str) -> bool {
    matches!(arg, "-command" | "/command" | "-encodedcommand" | "/encodedcommand" | "-e" | "/e")
        || arg.starts_with("-enc")
        || arg.starts_with("/enc")
}

/// Check if an argument text represents a shell command execution flag (-c, /c, clustered -lc/-ec, -Command, etc.)
fn is_shell_command_flag(shell_name: &str, arg: &str) -> bool {
    let lower_arg = arg.trim().to_ascii_lowercase();
    let lower = lower_arg.as_str();

    if lower == "-c" || lower == "/c" {
        return true;
    }

    if is_posix_shell(shell_name) && is_posix_command_flag(lower) {
        return true;
    }

    if (shell_name == "powershell" || shell_name == "pwsh") && is_powershell_command_flag(lower) {
        return true;
    }

    if shell_name == "cmd" && matches!(lower, "/c" | "/k" | "-c" | "/r") {
        return true;
    }

    false
}

/// Extract normalized callee name, handling `::` and `.` namespace prefixes.
/// e.g. `::IO.popen` -> `IO.popen`, `Open3::pipeline` -> `Open3.pipeline`
fn get_ruby_callee_name(
    node: &tree_sitter::Node,
    source: &[u8],
    language_support: &dyn LanguageSupport,
) -> String {
    let raw_name = if let Some(method_name) = language_support.get_function_name(node, source) {
        if let Some(receiver_node) = node.child_by_field_name("receiver") {
            let receiver_text = get_node_text(&receiver_node, source);
            format!("{}.{}", receiver_text.trim(), method_name.trim())
        } else {
            method_name.trim().to_string()
        }
    } else {
        let node_text = get_node_text(node, source);
        let callee = node_text
            .split('(')
            .next()
            .unwrap_or(&node_text)
            .split_whitespace()
            .next()
            .unwrap_or("");
        callee.trim().to_string()
    };

    let stripped = raw_name.strip_prefix("::").unwrap_or(&raw_name);
    stripped.replace("::", ".")
}

/// Check if an array or splatted array argument represents a safe (non-shell) command execution array.
/// An array argument `["sh", "-c", "cmd"]` or `*["/bin/bash", "-c", "cmd"]` still invokes a shell
/// and is UNSAFE. Only arrays with non-shell executables or safe argument structures are SAFE.
fn is_safe_command_array(arg_node: &tree_sitter::Node, source: &[u8]) -> bool {
    let target_array = if arg_node.kind() == "array" {
        Some(*arg_node)
    } else if arg_node.kind() == "splat_argument" {
        let mut found = None;
        for i in 0..arg_node.named_child_count() {
            if let Some(child) = arg_node.named_child(i as u32)
                && child.kind() == "array"
            {
                found = Some(child);
                break;
            }
        }
        found
    } else {
        None
    };

    let Some(array_node) = target_array else {
        return false;
    };

    let mut elements = Vec::new();
    for i in 0..array_node.named_child_count() {
        if let Some(child) = array_node.named_child(i as u32) {
            elements.push(child);
        }
    }

    if elements.is_empty() {
        return false;
    }

    let first_text = clean_ruby_string(get_node_text(&elements[0], source));
    if let Some(shell_name) = extract_shell_name(&first_text) {
        for el in elements.iter().skip(1) {
            let el_text = clean_ruby_string(get_node_text(el, source));
            if is_shell_command_flag(&shell_name, &el_text) {
                return false;
            }
        }
    }

    let first_kind = elements[0].kind();
    matches!(first_kind, "string" | "string_literal" | "simple_symbol" | "symbol")
}

/// Check if a Ruby call's arguments structure represents an unsafe command execution.
/// Follows strict FAIL-CLOSED principle: unmodeled, dynamic, or shell-executing calls return `true` (UNSAFE).
/// Only calls with verified non-shell multi-argument or array structures return `false` (SAFE).
fn filter_ruby_env_and_options<'a>(cmd_args: &mut Vec<tree_sitter::Node<'a>>) {
    // 1. Filter out environment hash at index 0
    if !cmd_args.is_empty()
        && (cmd_args[0].kind() == "hash" || cmd_args[0].kind() == "hash_literal")
        && cmd_args.len() > 1
    {
        cmd_args.remove(0);
    }

    // 2. Filter out options/keyword arguments/hash splats at the end
    while !cmd_args.is_empty() {
        let last_kind = cmd_args[cmd_args.len() - 1].kind();
        if last_kind == "hash"
            || last_kind == "hash_literal"
            || last_kind == "pair"
            || last_kind == "keyword_argument"
            || last_kind == "hash_splat_argument"
        {
            cmd_args.pop();
        } else {
            break;
        }
    }
}

fn check_multi_arg_safety(cmd_args: &[tree_sitter::Node], source: &[u8]) -> bool {
    if cmd_args.len() <= 1 {
        return false;
    }

    let mut exec_idx = 0;
    let mut first_text = clean_ruby_string(get_node_text(&cmd_args[0], source));

    // Handle wrapper executables like /usr/bin/env
    if (first_text == "env" || first_text.ends_with("/env") || first_text == "/usr/bin/env")
        && cmd_args.len() > 2
    {
        exec_idx = 1;
        first_text = clean_ruby_string(get_node_text(&cmd_args[1], source));
    }

    let first_kind = cmd_args[exec_idx].kind();
    let is_static_exec =
        matches!(first_kind, "string" | "string_literal" | "simple_symbol" | "symbol");
    if !is_static_exec {
        return true; // Dynamic binary target -> UNSAFE
    }

    if let Some(shell_name) = extract_shell_name(&first_text) {
        for arg_node in cmd_args.iter().skip(exec_idx + 1) {
            let arg_text = clean_ruby_string(get_node_text(arg_node, source));
            if is_shell_command_flag(&shell_name, &arg_text) {
                return true; // Explicit shell execution flag -> UNSAFE
            }
        }
    }

    false // Safe multi-argument execution
}

/// Check if a Ruby call's arguments structure represents an unsafe command execution.
/// Follows strict FAIL-CLOSED principle: unmodeled, dynamic, or shell-executing calls return `true` (UNSAFE).
/// Only calls with verified non-shell multi-argument or array structures return `false` (SAFE).
pub fn check_ruby_unsafe_command_injection(
    node: &tree_sitter::Node,
    source: &[u8],
    language_support: &dyn LanguageSupport,
) -> bool {
    if language_support.name() != "ruby" {
        return true;
    }
    let Some(args_node) = language_support.get_arguments_node(node) else {
        return true;
    };

    let mut cmd_args = Vec::new();
    for i in 0..args_node.named_child_count() {
        if let Some(child) = args_node.named_child(i as u32) {
            cmd_args.push(child);
        }
    }

    filter_ruby_env_and_options(&mut cmd_args);

    if cmd_args.is_empty() {
        return true;
    }

    let callee = get_ruby_callee_name(node, source, language_support);

    if callee == "IO.popen" || callee == "popen" {
        return !is_safe_command_array(&cmd_args[0], source);
    }

    if callee.starts_with("Open3.pipeline") || callee.starts_with("pipeline") {
        let all_safe_arrays = cmd_args.iter().all(|arg| is_safe_command_array(arg, source));
        return !all_safe_arrays;
    }

    if cmd_args.len() > 1 {
        return check_multi_arg_safety(&cmd_args, source);
    }

    if cmd_args.len() == 1 && is_safe_command_array(&cmd_args[0], source) {
        return false;
    }

    true
}

/// Helper function to evaluate generic conditions based on field, operator, and value.
pub fn evaluate_field_condition(
    node: &tree_sitter::Node,
    source: &[u8],
    condition: &Condition,
) -> bool {
    let node_text = get_node_text(node, source);
    match condition.field.as_str() {
        "pattern" => match condition.operator.as_str() {
            "not_contains" => !node_text.contains(&condition.value),
            "contains" => node_text.contains(&condition.value),
            _ => false,
        },
        "context" => {
            let context_text = get_context_text(node, source);
            match condition.operator.as_str() {
                "not_contains" => !context_text.contains(&condition.value),
                "contains" => context_text.contains(&condition.value),
                _ => false,
            }
        }
        _ => false,
    }
}

/// Helper function to extract context text (surrounding function or method node) for a given AST node.
pub fn get_context_text(node: &tree_sitter::Node, source: &[u8]) -> String {
    let mut current = *node;
    while let Some(parent) = current.parent() {
        let kind = parent.kind();
        if kind.contains("function") || kind.contains("method") || kind.contains("arrow") {
            return get_node_text(&parent, source);
        }
        current = parent;
    }
    // Fallback to the parent node or the node itself
    if let Some(parent) = node.parent() {
        get_node_text(&parent, source)
    } else {
        get_node_text(node, source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_shell_name() {
        assert_eq!(extract_shell_name("sh"), Some("sh".to_string()));
        assert_eq!(extract_shell_name("/bin/bash"), Some("bash".to_string()));
        assert_eq!(extract_shell_name("C:\\Windows\\cmd.exe"), Some("cmd".to_string()));
        assert_eq!(extract_shell_name("powershell"), Some("powershell".to_string()));
        assert_eq!(extract_shell_name("pwsh.exe"), Some("pwsh".to_string()));
        assert_eq!(extract_shell_name("/usr/bin/ls"), None);
    }

    #[test]
    fn test_is_shell_command_flag() {
        assert!(is_shell_command_flag("sh", "-c"));
        assert!(is_shell_command_flag("cmd", "/c"));
        assert!(is_shell_command_flag("powershell", "-Command"));
        assert!(is_shell_command_flag("powershell", "-encodedcommand"));
        assert!(is_shell_command_flag("pwsh", "-enc"));
        assert!(is_shell_command_flag("pwsh", "-e"));
        assert!(!is_shell_command_flag("sh", "-la"));
    }

    #[test]
    fn test_clean_ruby_string() {
        assert_eq!(clean_ruby_string("\"hello\"".to_string()), "hello");
        assert_eq!(clean_ruby_string("'world'".to_string()), "world");
        assert_eq!(clean_ruby_string(":symbol".to_string()), "symbol");
    }
}
