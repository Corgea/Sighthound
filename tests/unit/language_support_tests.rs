use sighthound::language::{get_language_support, SearchSemantics};
use sighthound::parser::{get_node_text, LanguageParser};
use tree_sitter::Node;

#[cfg(test)]
mod language_support_tests {
    use super::*;

    /// Depth-first search for the first descendant of `node` (including `node`
    /// itself) whose text contains `needle` and whose kind is `kind`.
    fn find_node_containing<'a>(
        node: Node<'a>,
        kind: &str,
        source: &[u8],
        needle: &str,
    ) -> Option<Node<'a>> {
        if node.kind() == kind && get_node_text(&node, source).contains(needle) {
            return Some(node);
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if let Some(found) = find_node_containing(child, kind, source, needle) {
                return Some(found);
            }
        }
        None
    }

    /// Depth-first search for the first descendant of `node` (including `node`
    /// itself) with the given `kind`, regardless of content.
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

    fn parse(language: &str, source: &str) -> (tree_sitter::Tree, Vec<u8>) {
        let mut parser = LanguageParser::new(language).expect("language support available");
        let bytes = source.as_bytes().to_vec();
        let tree = parser.parse(&bytes).expect("parse should succeed");
        (tree, bytes)
    }

    // ---- Django `get_function_name` (text node pattern matching) ----

    #[test]
    fn django_text_node_detects_safe_filter() {
        let support = get_language_support("django").unwrap();
        let (tree, source) = parse("django", "<p>{{ note|safe }}</p>");
        let node = find_node_containing(tree.root_node(), "text", &source, "|safe")
            .expect("expected a text node containing |safe");
        assert_eq!(support.get_function_name(&node, &source), Some("|safe"));
    }

    #[test]
    fn django_text_node_detects_mark_safe_filter() {
        let support = get_language_support("django").unwrap();
        let (tree, source) = parse("django", "<p>{{ note|mark_safe }}</p>");
        let node = find_node_containing(tree.root_node(), "text", &source, "|mark_safe")
            .expect("expected a text node containing |mark_safe");
        assert_eq!(support.get_function_name(&node, &source), Some("|mark_safe"));
    }

    #[test]
    fn django_text_node_detects_autoescape_off() {
        let support = get_language_support("django").unwrap();
        let (tree, source) =
            parse("django", "<p>{% autoescape off %}{{ note }}{% endautoescape %}</p>");
        let node = find_node_containing(tree.root_node(), "text", &source, "autoescape off")
            .expect("expected a text node containing the autoescape tag");
        assert_eq!(support.get_function_name(&node, &source), Some("{% autoescape off %}"));
    }

    #[test]
    fn django_text_node_detects_variable_interpolation() {
        let support = get_language_support("django").unwrap();
        let (tree, source) = parse("django", "<p>{{ username }}</p>");
        let node = find_node_containing(tree.root_node(), "text", &source, "{{")
            .expect("expected a text node containing {{");
        assert_eq!(support.get_function_name(&node, &source), Some("{{"));
    }

    #[test]
    fn django_text_node_detects_include_tag() {
        let support = get_language_support("django").unwrap();
        let (tree, source) = parse("django", "<div>{% include \"partial.html\" %}</div>");
        let node = find_node_containing(tree.root_node(), "text", &source, "{% include")
            .expect("expected a text node containing {% include");
        assert_eq!(support.get_function_name(&node, &source), Some("{% include"));
    }

    #[test]
    fn django_text_node_detects_generic_tag() {
        let support = get_language_support("django").unwrap();
        let (tree, source) =
            parse("django", "<div>{% if user.is_authenticated %}hi{% endif %}</div>");
        let node = find_node_containing(tree.root_node(), "text", &source, "{% if")
            .expect("expected a text node containing {% if");
        assert_eq!(support.get_function_name(&node, &source), Some("django_template"));
    }

    #[test]
    fn django_text_node_with_no_template_syntax_is_none() {
        let support = get_language_support("django").unwrap();
        let (tree, source) = parse("django", "<p>plain text with no template syntax</p>");
        let node = find_node_containing(tree.root_node(), "text", &source, "plain text")
            .expect("expected a plain text node");
        assert_eq!(support.get_function_name(&node, &source), None);
    }

    #[test]
    fn django_attribute_node_has_no_name_field_in_current_grammar() {
        // Unlike `HTMLLanguage::get_function_name`, the Django "attribute" arm
        // looks up `child_by_field_name("name")` with no `attribute_name`
        // fallback. The tree-sitter HTML grammar (v0.23) does not label
        // attribute children with fields at all, so this lookup is always
        // `None` today; this test documents that real, current behavior.
        let support = get_language_support("django").unwrap();
        let (tree, source) = parse("django", "<div data-role=\"panel\"></div>");
        let node =
            find_node_of_kind(tree.root_node(), "attribute").expect("expected an attribute node");
        assert_eq!(support.get_function_name(&node, &source), None);
    }

    #[test]
    fn django_script_element_returns_script() {
        let support = get_language_support("django").unwrap();
        let (tree, source) = parse("django", "<script>alert(1)</script>");
        let node = find_node_of_kind(tree.root_node(), "script_element")
            .expect("expected a script_element node");
        assert_eq!(support.get_function_name(&node, &source), Some("script"));
    }

    #[test]
    fn django_unmatched_node_kind_returns_none() {
        let support = get_language_support("django").unwrap();
        let (tree, source) = parse("django", "<div><span>x</span></div>");
        // `element` is not one of the matched kinds (text/attribute/script_element).
        let node =
            find_node_of_kind(tree.root_node(), "element").expect("expected an element node");
        assert_eq!(support.get_function_name(&node, &source), None);
    }

    // ---- Django `get_arguments_node` ----

    #[test]
    fn django_arguments_node_for_text_is_itself() {
        let support = get_language_support("django").unwrap();
        let (tree, source) = parse("django", "<p>{{ note|safe }}</p>");
        let node = find_node_containing(tree.root_node(), "text", &source, "note")
            .expect("expected a text node");
        let args = support.get_arguments_node(&node).expect("text node yields itself");
        assert_eq!(args.kind(), "text");
        assert_eq!(get_node_text(&args, &source), get_node_text(&node, &source));
    }

    #[test]
    fn django_arguments_node_for_quoted_attribute_value() {
        let support = get_language_support("django").unwrap();
        let (tree, source) = parse("django", "<div data-role=\"panel\"></div>");
        let node =
            find_node_of_kind(tree.root_node(), "attribute").expect("expected an attribute node");
        let args = support.get_arguments_node(&node).expect("attribute has a value");
        assert!(matches!(args.kind(), "quoted_attribute_value" | "attribute_value"));
        assert!(get_node_text(&args, &source).contains("panel"));
    }

    #[test]
    fn django_arguments_node_for_valueless_attribute_is_none() {
        let support = get_language_support("django").unwrap();
        let (tree, _source) = parse("django", "<input disabled>");
        let node =
            find_node_of_kind(tree.root_node(), "attribute").expect("expected an attribute node");
        assert_eq!(support.get_arguments_node(&node), None);
    }

    #[test]
    fn django_arguments_node_for_other_kind_falls_back_to_value_field() {
        let support = get_language_support("django").unwrap();
        let (tree, _source) = parse("django", "<div><span>x</span></div>");
        let node =
            find_node_of_kind(tree.root_node(), "element").expect("expected an element node");
        // `element` has no `value` field in the HTML grammar.
        assert_eq!(support.get_arguments_node(&node), None);
    }

    // ---- HTML `get_arguments_node` ----

    #[test]
    fn html_arguments_node_for_quoted_attribute_value() {
        let support = get_language_support("html").unwrap();
        let (tree, source) = parse("html", "<div class=\"container\"></div>");
        let node =
            find_node_of_kind(tree.root_node(), "attribute").expect("expected an attribute node");
        let args = support.get_arguments_node(&node).expect("attribute has a value");
        assert!(get_node_text(&args, &source).contains("container"));
    }

    #[test]
    fn html_arguments_node_for_valueless_attribute_is_none() {
        let support = get_language_support("html").unwrap();
        let (tree, _source) = parse("html", "<input disabled>");
        let node =
            find_node_of_kind(tree.root_node(), "attribute").expect("expected an attribute node");
        assert_eq!(support.get_arguments_node(&node), None);
    }

    #[test]
    fn html_arguments_node_for_non_attribute_is_none() {
        let support = get_language_support("html").unwrap();
        let (tree, _source) = parse("html", "<div><span>x</span></div>");
        let node =
            find_node_of_kind(tree.root_node(), "element").expect("expected an element node");
        assert_eq!(support.get_arguments_node(&node), None);
    }

    #[test]
    fn text_languages_do_not_require_tree_sitter_parsers() {
        for language in ["sql", "xml", "properties", "config"] {
            let support = get_language_support(language).unwrap();
            assert_eq!(support.search_semantics(), SearchSemantics::Text);
            assert!(support.tree_sitter_language().is_none());
        }
    }
}
