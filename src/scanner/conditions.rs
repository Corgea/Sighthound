use crate::language::LanguageSupport;
use crate::parser::get_node_text;
use crate::rules::Condition;
use crate::rules::{is_literal_node, match_any_pattern, match_pattern};

fn unwrap_keyword_argument(node: tree_sitter::Node) -> tree_sitter::Node {
    if node.kind() == "keyword_argument" {
        if let Some(val_node) = node.child_by_field_name("value") {
            return val_node;
        }
    }
    node
}

fn get_target_argument<'a>(
    args_node: tree_sitter::Node<'a>,
    position: usize,
    source: &[u8],
) -> Option<tree_sitter::Node<'a>> {
    for i in 0..args_node.named_child_count() {
        if let Some(arg) = args_node.named_child(i as u32) {
            if arg.kind() == "keyword_argument" {
                if let Some(name_node) = arg.child_by_field_name("name") {
                    let name_text = get_node_text(&name_node, source);
                    if name_text == "query" || name_text == "operation" || name_text == "sql" {
                        return Some(arg);
                    }
                }
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
        "node_kind" => condition.node_type.as_deref() == Some(node.kind()),
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
            if let Some(arg) = args_node.named_child(i as u32) {
                if check_argument_matches(arg, source, condition) {
                    return true;
                }
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
    if let Some(expected_type) = &condition.node_type {
        if unwrapped.kind() != expected_type {
            return false;
        }
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
    if let Some(not_in) = &condition.not_in {
        if let Some(parent) = node.parent() {
            if not_in.contains(&"comment".to_string()) && parent.kind() == "comment" {
                return false;
            }
            if not_in.contains(&"string".to_string()) && parent.kind() == "string" {
                return false;
            }
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
                if let Some(arg) = args_node.named_child(i as u32) {
                    let unwrapped = unwrap_keyword_argument(arg);
                    if !is_literal_node(&unwrapped) {
                        return true;
                    }
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
    if let Some(patterns) = &condition.patterns {
        if let Some(parent) = node.parent() {
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
    }
    false
}
