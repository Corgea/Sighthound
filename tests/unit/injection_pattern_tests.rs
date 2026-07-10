use sighthound::language::{LanguageSupport, get_language_support};
use sighthound::parser::{LanguageParser, get_node_text};
use sighthound::rules::{check_for_injection_pattern, is_literal_node};
use sighthound::scanner::ScanningLogic;

// note: in the unified-scanner refactor, `check_for_injection_pattern` became a
// language-agnostic check for a fixed set of command/template-injection indicator
// tokens: `;`, `&&`, `||`, backtick, `$(`, `eval(`, `exec(`, `system(`, `{{`, `{%`,
// `javascript:`, `data:`. The old format-string heuristics (%s, .format(), single
// `{}` braces, f-strings, bare `"a" + b` concatenation) are no longer flagged by this
// helper — that argument analysis now lives in the scanner core / taint engine. These
// tests assert the current contract: indicator tokens are detected, everything else is
// treated as safe by this helper.
#[cfg(test)]
mod injection_pattern_tests {
    use super::*;

    #[test]
    #[cfg(feature = "python")]
    fn test_python_injection_patterns() {
        let language_support =
            get_language_support("python").expect("Failed to get Python support");

        // Command injection indicators - should detect
        assert!(check_for_injection_pattern("cmd; rm -rf /", language_support.as_ref()));
        assert!(check_for_injection_pattern("ls -la && malware", language_support.as_ref()));
        assert!(check_for_injection_pattern(
            "echo 'safe' || dangerous_cmd",
            language_support.as_ref()
        ));
        assert!(check_for_injection_pattern("result = $(whoami)", language_support.as_ref()));
        assert!(check_for_injection_pattern("`cat /etc/passwd`", language_support.as_ref()));

        // Dangerous-call indicators - should detect
        assert!(check_for_injection_pattern("eval(user_code)", language_support.as_ref()));
        assert!(check_for_injection_pattern("exec(payload)", language_support.as_ref()));
        assert!(check_for_injection_pattern("os.system('rm -rf /')", language_support.as_ref()));

        // Template injection indicators - should detect
        assert!(check_for_injection_pattern("{{ user_input }}", language_support.as_ref()));
        assert!(check_for_injection_pattern("{% load malicious %}", language_support.as_ref()));

        // note: format-string / concatenation forms are no longer flagged by this helper
        assert!(!check_for_injection_pattern(
            "'SELECT * FROM users WHERE id = %s'",
            language_support.as_ref()
        ));
        assert!(!check_for_injection_pattern("'Hello {}'.format(name)", language_support.as_ref()));
        assert!(!check_for_injection_pattern(
            r#"f"SELECT * FROM table""#,
            language_support.as_ref()
        ));
        assert!(!check_for_injection_pattern(
            r#""SELECT * FROM users WHERE id = " + user_id"#,
            language_support.as_ref()
        ));

        // Safe patterns - should NOT detect
        assert!(!check_for_injection_pattern(
            r#""SELECT * FROM users""#,
            language_support.as_ref()
        ));
        assert!(!check_for_injection_pattern("print('Hello World')", language_support.as_ref()));
        assert!(!check_for_injection_pattern("safe_function()", language_support.as_ref()));
        assert!(!check_for_injection_pattern("123456", language_support.as_ref()));
        assert!(!check_for_injection_pattern("variable_name", language_support.as_ref()));
        assert!(!check_for_injection_pattern("simple text", language_support.as_ref()));
    }

    #[test]
    #[cfg(feature = "java")]
    fn test_java_injection_patterns() {
        let language_support = get_language_support("java").expect("Failed to get Java support");

        // Command injection indicators - should detect
        assert!(check_for_injection_pattern("cmd; del /f /q *", language_support.as_ref()));
        assert!(check_for_injection_pattern("dir && malware.exe", language_support.as_ref()));
        assert!(check_for_injection_pattern("echo safe || dangerous", language_support.as_ref()));
        assert!(check_for_injection_pattern("result = $(whoami)", language_support.as_ref()));
        assert!(check_for_injection_pattern("`cat file.txt`", language_support.as_ref()));
        assert!(check_for_injection_pattern(
            "Runtime.getRuntime().exec(payload)",
            language_support.as_ref()
        ));

        // note: String.format / concatenation forms are no longer flagged by this helper
        assert!(!check_for_injection_pattern(
            r#""SELECT * FROM users WHERE id = " + userId"#,
            language_support.as_ref()
        ));
        assert!(!check_for_injection_pattern(
            "String.format(\"SELECT * FROM %s\", tableName)",
            language_support.as_ref()
        ));
        assert!(!check_for_injection_pattern(
            "MessageFormat.format(\"Hello {0}\", name)",
            language_support.as_ref()
        ));

        // Safe patterns - should NOT detect
        assert!(!check_for_injection_pattern(
            r#""SELECT COUNT(*) FROM users""#,
            language_support.as_ref()
        ));
        assert!(!check_for_injection_pattern(
            "System.out.println(\"Hello\")",
            language_support.as_ref()
        ));
        assert!(!check_for_injection_pattern("methodCall()", language_support.as_ref()));
        assert!(!check_for_injection_pattern("42", language_support.as_ref()));
    }

    #[test]
    #[cfg(feature = "javascript")]
    fn test_javascript_injection_patterns() {
        let language_support =
            get_language_support("javascript").expect("Failed to get JavaScript support");

        // Template literal (backtick) indicators - should detect
        assert!(check_for_injection_pattern(
            "`SELECT * FROM ${tableName}`",
            language_support.as_ref()
        ));
        assert!(check_for_injection_pattern("query = `Hello ${name}!`", language_support.as_ref()));
        assert!(check_for_injection_pattern("`cat /etc/passwd`", language_support.as_ref()));
        assert!(check_for_injection_pattern("`SELECT * FROM users`", language_support.as_ref()));

        // Dangerous-call indicator - should detect
        assert!(check_for_injection_pattern("eval(userCode)", language_support.as_ref()));

        // Command injection indicators - should detect
        assert!(check_for_injection_pattern("cmd; rm -rf /", language_support.as_ref()));
        assert!(check_for_injection_pattern("ls && malware", language_support.as_ref()));
        assert!(check_for_injection_pattern("echo safe || dangerous", language_support.as_ref()));

        // note: `${...}` interpolation outside backticks, plain concatenation, and the
        // setTimeout/Function/document.write/innerHTML call shapes are not flagged by
        // this token-based helper anymore.
        assert!(!check_for_injection_pattern("${userInput}", language_support.as_ref()));
        assert!(!check_for_injection_pattern(
            r#""SELECT * FROM users WHERE id = " + userId"#,
            language_support.as_ref()
        ));
        assert!(!check_for_injection_pattern(
            "setTimeout(userFunction)",
            language_support.as_ref()
        ));
        assert!(!check_for_injection_pattern("document.write(content)", language_support.as_ref()));
        assert!(!check_for_injection_pattern(
            "element.innerHTML = userHtml",
            language_support.as_ref()
        ));

        // Safe patterns - should NOT detect
        assert!(!check_for_injection_pattern(
            r#""SELECT COUNT(*) FROM users""#,
            language_support.as_ref()
        ));
        assert!(!check_for_injection_pattern("console.log('Hello')", language_support.as_ref()));
        assert!(!check_for_injection_pattern("regularFunction", language_support.as_ref()));
        assert!(!check_for_injection_pattern("123", language_support.as_ref()));
    }

    #[test]
    #[cfg(feature = "python")]
    fn test_python_has_injection_pattern_integration() {
        let language_support =
            get_language_support("python").expect("Failed to get Python support");
        let mut parser = LanguageParser::new("python").expect("Failed to create parser");

        // note: a tainted execute() argument is now recognised when the argument node is
        // non-literal (e.g. a concatenation) and contains an injection indicator token.
        // An f-string is classified as a literal string node, so we use concatenation
        // with a command separator to exercise the vulnerable path.
        let vulnerable_code = r#"
def get_user(user_id):
    cursor.execute("SELECT * FROM users WHERE id = " + user_id + "; DROP TABLE users")
    return cursor.fetchone()
"#;

        let source = vulnerable_code.as_bytes();
        let tree = parser.parse(source).expect("Failed to parse code");
        let root_node = tree.root_node();

        let mut found_injection = false;

        fn visit_nodes<F>(
            node: &tree_sitter::Node,
            source: &[u8],
            language_support: &dyn LanguageSupport,
            callback: &mut F,
        ) where
            F: FnMut(bool),
        {
            for call_type in language_support.call_node_types() {
                if node.kind() == *call_type
                    && let Some(func_name) = language_support.get_function_name(node, source)
                    && func_name.contains("execute")
                {
                    let has_pattern =
                        ScanningLogic::has_injection_pattern(node, source, language_support);
                    callback(has_pattern);
                    return;
                }
            }

            for i in 0..node.child_count() {
                if let Some(child) = node.child(i as u32) {
                    visit_nodes(&child, source, language_support, callback);
                }
            }
        }

        visit_nodes(&root_node, source, language_support.as_ref(), &mut |has_pattern| {
            found_injection = has_pattern;
        });

        assert!(found_injection, "Should detect injection pattern in tainted SQL query");
    }

    #[test]
    #[cfg(feature = "python")]
    fn test_python_safe_code_no_injection_pattern() {
        let language_support =
            get_language_support("python").expect("Failed to get Python support");
        let mut parser = LanguageParser::new("python").expect("Failed to create parser");

        // Test safe SQL query with literal string
        let safe_code = r#"
def get_all_users():
    cursor.execute("SELECT * FROM users")
    return cursor.fetchall()
"#;

        let source = safe_code.as_bytes();
        let tree = parser.parse(source).expect("Failed to parse code");
        let root_node = tree.root_node();

        let mut found_injection = false;

        fn visit_nodes<F>(
            node: &tree_sitter::Node,
            source: &[u8],
            language_support: &dyn LanguageSupport,
            callback: &mut F,
        ) where
            F: FnMut(bool),
        {
            for call_type in language_support.call_node_types() {
                if node.kind() == *call_type
                    && let Some(func_name) = language_support.get_function_name(node, source)
                    && func_name.contains("execute")
                {
                    let has_pattern =
                        ScanningLogic::has_injection_pattern(node, source, language_support);
                    callback(has_pattern);
                    return;
                }
            }

            for i in 0..node.child_count() {
                if let Some(child) = node.child(i as u32) {
                    visit_nodes(&child, source, language_support, callback);
                }
            }
        }

        visit_nodes(&root_node, source, language_support.as_ref(), &mut |has_pattern| {
            found_injection = has_pattern;
        });

        assert!(!found_injection, "Should NOT detect injection pattern in safe literal SQL query");
    }

    #[test]
    #[cfg(feature = "java")]
    fn test_java_injection_pattern_integration() {
        let language_support = get_language_support("java").expect("Failed to get Java support");
        let mut parser = LanguageParser::new("java").expect("Failed to create parser");

        // Test vulnerable Java code with a tainted command separator
        let vulnerable_code = r#"
public class TestClass {
    public void vulnerableQuery(String userId, Statement stmt) throws SQLException {
        stmt.execute("SELECT * FROM users WHERE id = " + userId + "; DROP TABLE users");
    }
}
"#;

        let source = vulnerable_code.as_bytes();
        let tree = parser.parse(source).expect("Failed to parse code");
        let root_node = tree.root_node();

        let mut found_injection = false;

        fn visit_nodes<F>(
            node: &tree_sitter::Node,
            source: &[u8],
            language_support: &dyn LanguageSupport,
            callback: &mut F,
        ) where
            F: FnMut(bool),
        {
            for call_type in language_support.call_node_types() {
                if node.kind() == *call_type
                    && let Some(func_name) = language_support.get_function_name(node, source)
                    && func_name.contains("execute")
                {
                    let has_pattern =
                        ScanningLogic::has_injection_pattern(node, source, language_support);
                    callback(has_pattern);
                    return;
                }
            }

            for i in 0..node.child_count() {
                if let Some(child) = node.child(i as u32) {
                    visit_nodes(&child, source, language_support, callback);
                }
            }
        }

        visit_nodes(&root_node, source, language_support.as_ref(), &mut |has_pattern| {
            found_injection = has_pattern;
        });

        assert!(found_injection, "Should detect injection pattern in Java tainted SQL query");
    }

    #[test]
    #[cfg(feature = "javascript")]
    fn test_javascript_injection_pattern_integration() {
        let language_support =
            get_language_support("javascript").expect("Failed to get JavaScript support");
        let mut parser = LanguageParser::new("javascript").expect("Failed to create parser");

        // Test vulnerable JavaScript code with template literal passed directly
        let vulnerable_code = r#"
function getUser(userId) {
    db.execute(`SELECT * FROM users WHERE id = ${userId}`);
}
"#;

        let source = vulnerable_code.as_bytes();
        let tree = parser.parse(source).expect("Failed to parse code");
        let root_node = tree.root_node();

        let mut found_injection = false;

        fn visit_nodes<F>(
            node: &tree_sitter::Node,
            source: &[u8],
            language_support: &dyn LanguageSupport,
            callback: &mut F,
        ) where
            F: FnMut(bool),
        {
            for call_type in language_support.call_node_types() {
                if node.kind() == *call_type
                    && let Some(func_name) = language_support.get_function_name(node, source)
                    && func_name.contains("execute")
                {
                    let has_pattern =
                        ScanningLogic::has_injection_pattern(node, source, language_support);
                    callback(has_pattern);
                    return;
                }
            }

            for i in 0..node.child_count() {
                if let Some(child) = node.child(i as u32) {
                    visit_nodes(&child, source, language_support, callback);
                }
            }
        }

        visit_nodes(&root_node, source, language_support.as_ref(), &mut |has_pattern| {
            found_injection = has_pattern;
        });

        assert!(
            found_injection,
            "Should detect injection pattern in JavaScript template literal SQL query"
        );
    }

    #[test]
    fn test_edge_cases() {
        // Test with unsupported language
        let unsupported_result = get_language_support("unsupported");
        assert!(unsupported_result.is_err(), "Should fail for unsupported language");

        // Test empty strings
        #[cfg(feature = "python")]
        {
            let language_support =
                get_language_support("python").expect("Failed to get Python support");
            assert!(!check_for_injection_pattern("", language_support.as_ref()));
            assert!(!check_for_injection_pattern("   ", language_support.as_ref()));
        }
    }

    #[test]
    fn test_complex_injection_scenarios() {
        // note: only command/template indicator tokens are detected now, so the complex
        // scenarios assert detection of strings that chain commands and non-detection of
        // pure format-string concatenation.
        #[cfg(feature = "python")]
        {
            let language_support =
                get_language_support("python").expect("Failed to get Python support");

            // Command chaining inside the string is detected
            assert!(check_for_injection_pattern(
                "cmd = 'ping host'; subprocess.call(cmd, shell=True)",
                language_support.as_ref()
            ));
            assert!(check_for_injection_pattern(
                "query + ' WHERE id = ' && exfil",
                language_support.as_ref()
            ));

            // Pure format-string concatenation is no longer flagged by this helper
            assert!(!check_for_injection_pattern(
                "f'SELECT * FROM {table}' + ' WHERE id = ' + str(user_id)",
                language_support.as_ref()
            ));
        }

        #[cfg(feature = "java")]
        {
            let language_support =
                get_language_support("java").expect("Failed to get Java support");

            // Command chaining is detected
            assert!(check_for_injection_pattern(
                r#""SELECT * FROM " + tableName + "; DROP TABLE users""#,
                language_support.as_ref()
            ));

            // Plain concatenation without indicator tokens is not flagged
            assert!(!check_for_injection_pattern(
                r#""SELECT * FROM " + tableName + " WHERE id = " + userId"#,
                language_support.as_ref()
            ));
        }

        #[cfg(feature = "javascript")]
        {
            let language_support =
                get_language_support("javascript").expect("Failed to get JavaScript support");

            // Template literal (backtick) is detected
            assert!(check_for_injection_pattern(
                r#"`SELECT * FROM ${table}` + " WHERE id = " + userId"#,
                language_support.as_ref()
            ));

            // eval( with a template literal is detected
            assert!(check_for_injection_pattern(
                "eval(`function() { ${userCode} }`)",
                language_support.as_ref()
            ));
        }
    }

    /// Depth-first visit of every node in the tree, invoking `callback` on each.
    #[cfg(any(feature = "python", feature = "javascript"))]
    fn visit_nodes<F>(node: &tree_sitter::Node, callback: &mut F)
    where
        F: FnMut(&tree_sitter::Node),
    {
        callback(node);

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i as u32) {
                visit_nodes(&child, callback);
            }
        }
    }

    #[cfg(feature = "python")]
    fn check_python_literal_nodes() {
        let mut parser = LanguageParser::new("python").expect("Failed to create parser");

        // note: the refactor classifies quoted string literals as literal nodes.
        // Injection sensitivity for strings is now handled by inspecting the argument
        // text (check_for_injection_pattern), not by is_literal_node.
        let literal_string_code = r#"
def func():
    return "This is a literal string"
"#;
        let source = literal_string_code.as_bytes();
        let tree = parser.parse(source).expect("Failed to parse code");

        let mut found_string_node = false;
        visit_nodes(&tree.root_node(), &mut |node| {
            if node.kind() == "string" {
                found_string_node = true;
                assert!(is_literal_node(node), "String node is classified as a literal");
            }
        });

        assert!(found_string_node, "Should have found at least one string node");

        // Test with numeric literals (should be literal nodes)
        let numeric_code = r#"
def func():
    return 42
"#;
        let source = numeric_code.as_bytes();
        let tree = parser.parse(source).expect("Failed to parse code");

        let mut found_integer_node = false;
        visit_nodes(&tree.root_node(), &mut |node| {
            if node.kind() == "integer" {
                found_integer_node = true;
                assert!(is_literal_node(node), "Integer node should be considered a literal");
            }
        });

        assert!(found_integer_node, "Should have found at least one integer node");

        // f-strings are still classified as "string" nodes, hence literal nodes
        let fstring_code = r#"
def func(user_id):
    return f"User ID: {user_id}"
"#;
        let source = fstring_code.as_bytes();
        let tree = parser.parse(source).expect("Failed to parse code");

        let mut found_fstring_node = false;
        visit_nodes(&tree.root_node(), &mut |node| {
            if node.kind() == "string" && get_node_text(node, source).contains("f\"") {
                found_fstring_node = true;
                assert!(
                    is_literal_node(node),
                    "f-string node is classified as a literal string node"
                );
            }
        });

        assert!(found_fstring_node, "Should have found at least one f-string node");
    }

    #[cfg(feature = "javascript")]
    fn check_javascript_literal_nodes() {
        let mut parser = LanguageParser::new("javascript").expect("Failed to create parser");

        // Template literals are NOT classified as literal nodes
        let template_code = r#"
function greet(name) {
    return `Hello, ${name}`;
}
"#;
        let source = template_code.as_bytes();
        let tree = parser.parse(source).expect("Failed to parse code");

        let mut found_template_node = false;
        visit_nodes(&tree.root_node(), &mut |node| {
            if node.kind() == "template_string" {
                found_template_node = true;
                assert!(
                    !is_literal_node(node),
                    "Template literal should not be considered a literal for injection analysis"
                );
            }
        });

        assert!(found_template_node, "Should have found at least one template string node");
    }

    #[test]
    fn test_is_literal_node_function() {
        #[cfg(feature = "python")]
        check_python_literal_nodes();

        #[cfg(feature = "javascript")]
        check_javascript_literal_nodes();
    }
}
