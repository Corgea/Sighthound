use sighthound::language::{get_language_support, LanguageSupport};
use sighthound::rules::{check_for_injection_pattern, is_literal_node};
use sighthound::scanner::core::ScanningLogic;
use sighthound::parser::{LanguageParser, get_node_text};

/// Return true if any call node in the tree has an injectable (non-literal,
/// separator-bearing) argument according to the scanner heuristic.
#[cfg(any(feature = "python", feature = "java", feature = "javascript"))]
fn any_call_has_injection(language: &str, code: &str) -> bool {
    let language_support = get_language_support(language).expect("language support");
    let mut parser = LanguageParser::new(language).expect("parser");
    let source = code.as_bytes();
    let tree = parser.parse(source).expect("parse");

    fn visit(
        node: &tree_sitter::Node,
        source: &[u8],
        ls: &dyn LanguageSupport,
        found: &mut bool,
    ) {
        for call_type in ls.call_node_types() {
            if node.kind() == *call_type
                && ScanningLogic::has_injection_pattern(node, source, ls)
            {
                *found = true;
                return;
            }
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                visit(&child, source, ls, found);
            }
        }
    }

    let mut found = false;
    visit(&tree.root_node(), source, language_support.as_ref(), &mut found);
    found
}

#[cfg(test)]
mod injection_pattern_tests {
    use super::*;

    #[test]
    #[cfg(feature = "python")]
    fn test_check_for_injection_pattern_positive() {
        let ls = get_language_support("python").expect("python support");

        // Command separators / chaining.
        assert!(check_for_injection_pattern("cmd; rm -rf /", ls.as_ref()));
        assert!(check_for_injection_pattern("ls -la && malware", ls.as_ref()));
        assert!(check_for_injection_pattern("echo 'safe' || dangerous_cmd", ls.as_ref()));
        assert!(check_for_injection_pattern("result = $(whoami)", ls.as_ref()));
        assert!(check_for_injection_pattern("`cat /etc/passwd`", ls.as_ref()));

        // Dangerous function calls.
        assert!(check_for_injection_pattern("eval(userCode)", ls.as_ref()));
        assert!(check_for_injection_pattern("exec(code)", ls.as_ref()));
        assert!(check_for_injection_pattern("system(cmd)", ls.as_ref()));

        // Template / URL-scheme indicators.
        assert!(check_for_injection_pattern("Hello {{ user }}", ls.as_ref()));
        assert!(check_for_injection_pattern("{% if admin %}", ls.as_ref()));
        assert!(check_for_injection_pattern("javascript:alert(1)", ls.as_ref()));
        assert!(check_for_injection_pattern("data:text/html,<script>", ls.as_ref()));
    }

    #[test]
    #[cfg(feature = "python")]
    fn test_check_for_injection_pattern_negative() {
        let ls = get_language_support("python").expect("python support");

        // Plain queries / format strings without separators are not flagged by
        // this language-agnostic indicator check.
        assert!(!check_for_injection_pattern("SELECT * FROM users", ls.as_ref()));
        assert!(!check_for_injection_pattern("'SELECT * FROM users WHERE id = %s'", ls.as_ref()));
        assert!(!check_for_injection_pattern("${userInput}", ls.as_ref()));
        assert!(!check_for_injection_pattern("query.format(user_id)", ls.as_ref()));
        assert!(!check_for_injection_pattern("variable_name", ls.as_ref()));
        assert!(!check_for_injection_pattern("123456", ls.as_ref()));
        assert!(!check_for_injection_pattern("", ls.as_ref()));
        assert!(!check_for_injection_pattern("   ", ls.as_ref()));
    }

    #[test]
    fn test_edge_cases_unsupported_language() {
        let unsupported_result = get_language_support("unsupported");
        assert!(unsupported_result.is_err(), "Should fail for unsupported language");
    }

    #[test]
    #[cfg(feature = "python")]
    fn test_python_call_with_injectable_argument() {
        // A non-literal argument that contains a command separator is injectable.
        let vulnerable = r#"
def run(cmd):
    subprocess.call("ping " + cmd + "; rm -rf /")
"#;
        assert!(any_call_has_injection("python", vulnerable),
            "Should detect injectable argument in command-building concatenation");

        // A literal argument is not injectable.
        let safe = r#"
def get_all_users():
    cursor.execute("SELECT * FROM users")
"#;
        assert!(!any_call_has_injection("python", safe),
            "Literal query argument should not be flagged");
    }

    #[test]
    #[cfg(feature = "java")]
    fn test_java_call_with_injectable_argument() {
        let vulnerable = r#"
public class T {
    void f(String c) {
        Runtime.getRuntime().exec("ping " + c + "; rm -rf /");
    }
}
"#;
        assert!(any_call_has_injection("java", vulnerable),
            "Should detect injectable argument in Java command concatenation");

        let safe = r#"
public class T {
    void f(Statement stmt) throws SQLException {
        stmt.execute("SELECT COUNT(*) FROM users");
    }
}
"#;
        assert!(!any_call_has_injection("java", safe),
            "Literal Java query argument should not be flagged");
    }

    #[test]
    #[cfg(feature = "javascript")]
    fn test_javascript_call_with_injectable_argument() {
        let vulnerable = r#"
function getUser(userId) {
    db.execute("SELECT * FROM users WHERE id = " + userId + "; DROP TABLE users");
}
"#;
        assert!(any_call_has_injection("javascript", vulnerable),
            "Should detect injectable argument in JS query concatenation");

        let safe = r#"
function safe() {
    db.execute("SELECT COUNT(*) FROM users");
}
"#;
        assert!(!any_call_has_injection("javascript", safe),
            "Literal JS query argument should not be flagged");
    }

    #[test]
    #[cfg(feature = "python")]
    fn test_is_literal_node_python() {
        let mut parser = LanguageParser::new("python").expect("parser");

        // String literals are treated as literal nodes.
        let code = "def f():\n    return \"a literal string\"\n";
        let source = code.as_bytes();
        let tree = parser.parse(source).expect("parse");

        let mut saw_string = false;
        let mut saw_integer = false;
        visit_all(&tree.root_node(), &mut |node| {
            if node.kind() == "string" {
                saw_string = true;
                assert!(is_literal_node(node), "string node should be a literal");
            }
        });
        assert!(saw_string, "expected a string node");

        let code = "def f():\n    return 42\n";
        let source = code.as_bytes();
        let tree = parser.parse(source).expect("parse");
        visit_all(&tree.root_node(), &mut |node| {
            if node.kind() == "integer" {
                saw_integer = true;
                assert!(is_literal_node(node), "integer node should be a literal");
            }
        });
        assert!(saw_integer, "expected an integer node");
    }

    #[test]
    #[cfg(feature = "javascript")]
    fn test_template_string_is_not_literal() {
        let mut parser = LanguageParser::new("javascript").expect("parser");
        let code = "function greet(name) { return `Hello, ${name}`; }\n";
        let source = code.as_bytes();
        let tree = parser.parse(source).expect("parse");

        let mut saw_template = false;
        visit_all(&tree.root_node(), &mut |node| {
            if node.kind() == "template_string" {
                saw_template = true;
                // Template strings interpolate values, so they are NOT literals.
                assert!(!is_literal_node(node), "template string should not be a literal");
            }
            let _ = get_node_text(node, source);
        });
        assert!(saw_template, "expected a template_string node");
    }
}

#[cfg(any(feature = "python", feature = "javascript"))]
fn visit_all<F: FnMut(&tree_sitter::Node)>(node: &tree_sitter::Node, f: &mut F) {
    f(node);
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            visit_all(&child, f);
        }
    }
}
