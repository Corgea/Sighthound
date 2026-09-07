use sighthound::language::get_language_support;
use sighthound::models::Condition;
use sighthound::parser::LanguageParser;
use sighthound::scanner::conditions::{
    check_has_argument_condition, check_has_sibling_pattern_condition, check_in_context_condition,
};
use tree_sitter::Node;

#[cfg(test)]
mod ast_conditions_tests {
    use super::*;

    fn base_condition() -> Condition {
        Condition {
            field: "argument".to_string(),
            operator: "contains".to_string(),
            value: String::new(),
            condition_type: None,
            argument_position: None,
            node_type: None,
            pattern: None,
            patterns: None,
            not_in: None,
            parent_type: None,
            ancestor_types: None,
        }
    }

    fn find_node_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
        if node.kind() == kind {
            return Some(node);
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if let Some(found) = find_node_of_kind(child, kind) {
                return Some(found);
            }
        }
        None
    }

    fn parse_python(source: &str) -> (tree_sitter::Tree, Vec<u8>) {
        let mut parser = LanguageParser::new("python").expect("python support available");
        let bytes = source.as_bytes().to_vec();
        let tree = parser.parse(&bytes).expect("parse should succeed");
        (tree, bytes)
    }

    // ---- check_has_argument_condition ----

    #[test]
    fn has_argument_matches_specific_position() {
        let support = get_language_support("python").unwrap();
        let (tree, source) = parse_python("foo(bar, \"eval_pattern\")");
        let call = find_node_of_kind(tree.root_node(), "call").expect("expected a call node");

        let mut condition = base_condition();
        condition.argument_position = Some(1);
        condition.pattern = Some("eval_pattern".to_string());

        assert!(check_has_argument_condition(&call, &source, &condition, support.as_ref()));
    }

    #[test]
    fn has_argument_out_of_range_position_is_false() {
        let support = get_language_support("python").unwrap();
        let (tree, source) = parse_python("foo(bar, \"eval_pattern\")");
        let call = find_node_of_kind(tree.root_node(), "call").expect("expected a call node");

        let mut condition = base_condition();
        condition.argument_position = Some(9);
        condition.pattern = Some("eval_pattern".to_string());

        assert!(!check_has_argument_condition(&call, &source, &condition, support.as_ref()));
    }

    #[test]
    fn has_argument_scans_all_positions_when_unset() {
        let support = get_language_support("python").unwrap();
        let (tree, source) = parse_python("foo(bar, \"eval_pattern\")");
        let call = find_node_of_kind(tree.root_node(), "call").expect("expected a call node");

        let mut condition = base_condition();
        condition.patterns = Some(vec!["eval_pattern".to_string()]);

        assert!(check_has_argument_condition(&call, &source, &condition, support.as_ref()));
    }

    #[test]
    fn has_argument_no_matching_pattern_is_false() {
        let support = get_language_support("python").unwrap();
        let (tree, source) = parse_python("foo(bar, \"eval_pattern\")");
        let call = find_node_of_kind(tree.root_node(), "call").expect("expected a call node");

        let mut condition = base_condition();
        condition.patterns = Some(vec!["not_present_anywhere".to_string()]);

        assert!(!check_has_argument_condition(&call, &source, &condition, support.as_ref()));
    }

    #[test]
    fn has_argument_with_no_arguments_node_is_false() {
        let support = get_language_support("python").unwrap();
        let (tree, source) = parse_python("foo(bar, \"eval_pattern\")");
        // The module root has no `arguments` field, so `get_arguments_node` is None.
        let root = tree.root_node();

        let mut condition = base_condition();
        condition.patterns = Some(vec!["eval_pattern".to_string()]);

        assert!(!check_has_argument_condition(&root, &source, &condition, support.as_ref()));
    }

    // ---- check_in_context_condition ----

    #[test]
    fn in_context_with_no_not_in_is_true() {
        let (tree, _source) = parse_python("x = 1");
        let root = tree.root_node();
        let condition = base_condition();

        assert!(check_in_context_condition(&root, &condition));
    }

    #[test]
    fn in_context_excludes_string_literals() {
        let (tree, _source) = parse_python("x = \"hello\"");
        // Python's grammar splits string literals into start/content/end
        // children of a `string` node, so `string_content`'s parent is `string`.
        let content =
            find_node_of_kind(tree.root_node(), "string_content").expect("expected string_content");

        let mut condition = base_condition();
        condition.not_in = Some(vec!["string".to_string()]);

        assert!(!check_in_context_condition(&content, &condition));
    }

    #[test]
    fn in_context_allows_node_not_matching_excluded_context() {
        let (tree, _source) = parse_python("x = \"hello\"");
        let identifier =
            find_node_of_kind(tree.root_node(), "identifier").expect("expected identifier");

        let mut condition = base_condition();
        condition.not_in = Some(vec!["comment".to_string()]);

        assert!(check_in_context_condition(&identifier, &condition));
    }

    #[test]
    fn in_context_root_node_has_no_parent_and_is_true() {
        let (tree, _source) = parse_python("x = 1");
        let root = tree.root_node();

        let mut condition = base_condition();
        condition.not_in = Some(vec!["comment".to_string(), "string".to_string()]);

        assert!(check_in_context_condition(&root, &condition));
    }

    // ---- check_has_sibling_pattern_condition ----

    #[test]
    fn has_sibling_pattern_none_configured_is_false() {
        let support = get_language_support("python").unwrap();
        let (tree, source) = parse_python("foo(bar, \"eval_pattern\")");
        let call = find_node_of_kind(tree.root_node(), "call").expect("expected call node");
        let args = support.get_arguments_node(&call).expect("call has arguments");
        let first_arg = args.named_child(0).expect("expected first argument");

        let condition = base_condition();

        assert!(!check_has_sibling_pattern_condition(&first_arg, &source, &condition));
    }

    #[test]
    fn has_sibling_pattern_matches_sibling_text() {
        let support = get_language_support("python").unwrap();
        let (tree, source) = parse_python("foo(bar, \"eval_pattern\")");
        let call = find_node_of_kind(tree.root_node(), "call").expect("expected call node");
        let args = support.get_arguments_node(&call).expect("call has arguments");
        let first_arg = args.named_child(0).expect("expected first argument (bar)");

        let mut condition = base_condition();
        condition.patterns = Some(vec!["eval_pattern".to_string()]);

        assert!(check_has_sibling_pattern_condition(&first_arg, &source, &condition));
    }

    #[test]
    fn has_sibling_pattern_no_match_is_false() {
        let support = get_language_support("python").unwrap();
        let (tree, source) = parse_python("foo(bar, \"eval_pattern\")");
        let call = find_node_of_kind(tree.root_node(), "call").expect("expected call node");
        let args = support.get_arguments_node(&call).expect("call has arguments");
        let first_arg = args.named_child(0).expect("expected first argument (bar)");

        let mut condition = base_condition();
        condition.patterns = Some(vec!["not_present_anywhere".to_string()]);

        assert!(!check_has_sibling_pattern_condition(&first_arg, &source, &condition));
    }

    #[test]
    fn has_sibling_pattern_root_node_has_no_parent_and_is_false() {
        let (tree, source) = parse_python("foo(bar, \"eval_pattern\")");
        let root = tree.root_node();

        let mut condition = base_condition();
        condition.patterns = Some(vec!["eval_pattern".to_string()]);

        assert!(!check_has_sibling_pattern_condition(&root, &source, &condition));
    }

    #[cfg(feature = "ruby")]
    fn parse_ruby(source: &str) -> (tree_sitter::Tree, Vec<u8>) {
        let mut parser = LanguageParser::new("ruby").expect("ruby support available");
        let bytes = source.as_bytes().to_vec();
        let tree = parser.parse(&bytes).expect("parse should succeed");
        (tree, bytes)
    }

    #[cfg(feature = "ruby")]
    #[test]
    fn ruby_unsafe_command_injection_detects_clustered_posix_flags() {
        use sighthound::scanner::conditions::check_ruby_unsafe_command_injection;

        let support = get_language_support("ruby").unwrap();

        for unsafe_call in [
            "system(\"bash\", \"-lc\", cmd)",
            "system(\"sh\", \"-ec\", cmd)",
            "system(\"/bin/sh\", \"-elc\", cmd)",
            "system([\"bash\", \"-lc\", cmd])",
            "exec(\"zsh\", \"-ic\", cmd)",
            "spawn(\"bash\", \"-c\", cmd)",
        ] {
            let (tree, source) = parse_ruby(unsafe_call);
            let call = find_node_of_kind(tree.root_node(), "call").expect("expected call node");
            assert!(
                check_ruby_unsafe_command_injection(&call, &source, support.as_ref()),
                "expected {unsafe_call} to be classified as unsafe",
            );
        }

        for safe_call in [
            "system(\"ls\", \"-l\", cmd)",
            "system(\"ls\", \"-la\", cmd)",
            "system(\"bash\", \"--version\")",
            "system(\"bash\", \"-l\")",
            "system([\"ls\", \"-l\", cmd])",
        ] {
            let (tree, source) = parse_ruby(safe_call);
            let call = find_node_of_kind(tree.root_node(), "call").expect("expected call node");
            assert!(
                !check_ruby_unsafe_command_injection(&call, &source, support.as_ref()),
                "expected {safe_call} to be classified as safe",
            );
        }
    }
}
