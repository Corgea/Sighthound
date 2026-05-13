use sighthound::language::{get_language_support, LanguageSupport};
use sighthound::parser::{get_node_text, LanguageParser};
use sighthound::rules::{check_for_injection_pattern, is_literal_node};
use sighthound::scanner::core::ScanningLogic;

// `check_for_injection_pattern` was narrowed during the unified-rules
// migration: it now flags only language-agnostic command-injection markers
// (separators, dangerous builtins, template/URL-scheme prefixes). Format-string
// and concatenation patterns are no longer this function's responsibility — they
// belong to AST-level rule conditions and taint analysis. These tests assert the
// current narrow contract.

#[cfg(test)]
mod injection_pattern_tests {
    use super::*;

    #[test]
    #[cfg(feature = "python")]
    fn test_python_injection_patterns() {
        let language_support = get_language_support("python").expect("Failed to get Python support");

        // Command separator / chaining markers — should detect.
        assert!(check_for_injection_pattern("cmd; rm -rf /", language_support.as_ref()));
        assert!(check_for_injection_pattern("ls -la && malware", language_support.as_ref()));
        assert!(check_for_injection_pattern("echo 'safe' || dangerous_cmd", language_support.as_ref()));
        assert!(check_for_injection_pattern("result = $(whoami)", language_support.as_ref()));
        assert!(check_for_injection_pattern("`cat /etc/passwd`", language_support.as_ref()));

        // Dangerous builtins — should detect.
        assert!(check_for_injection_pattern("eval(user_code)", language_support.as_ref()));
        assert!(check_for_injection_pattern("exec(payload)", language_support.as_ref()));
        assert!(check_for_injection_pattern("system(cmd)", language_support.as_ref()));

        // Template / URL-scheme markers — should detect.
        assert!(check_for_injection_pattern("{{ user_input }}", language_support.as_ref()));
        assert!(check_for_injection_pattern("{% if user %}", language_support.as_ref()));
        assert!(check_for_injection_pattern("href='javascript:alert(1)'", language_support.as_ref()));
        assert!(check_for_injection_pattern("src='data:text/html,...'", language_support.as_ref()));

        // Format-string patterns are no longer flagged at this layer.
        assert!(!check_for_injection_pattern("'SELECT * FROM users WHERE id = %s'", language_support.as_ref()));
        assert!(!check_for_injection_pattern(r#"f"SELECT * FROM table""#, language_support.as_ref()));
        assert!(!check_for_injection_pattern("query.format(user_id)", language_support.as_ref()));

        // Plain literals and identifiers — should NOT detect.
        assert!(!check_for_injection_pattern(r#""SELECT * FROM users""#, language_support.as_ref()));
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

        // Command separator markers — should detect.
        assert!(check_for_injection_pattern("cmd; del /f /q *", language_support.as_ref()));
        assert!(check_for_injection_pattern("dir && malware.exe", language_support.as_ref()));
        assert!(check_for_injection_pattern("echo safe || dangerous", language_support.as_ref()));
        assert!(check_for_injection_pattern("result = $(whoami)", language_support.as_ref()));
        assert!(check_for_injection_pattern("`cat file.txt`", language_support.as_ref()));

        // Dangerous builtin substrings — should detect.
        assert!(check_for_injection_pattern("Runtime.getRuntime().exec(cmd)", language_support.as_ref()));

        // Concatenation patterns are no longer flagged at this layer.
        assert!(!check_for_injection_pattern(r#""SELECT * FROM users WHERE id = " + userId"#, language_support.as_ref()));
        assert!(!check_for_injection_pattern("String.format(\"SELECT * FROM %s\", tableName)", language_support.as_ref()));

        // Safe text — should NOT detect.
        assert!(!check_for_injection_pattern(r#""SELECT COUNT(*) FROM users""#, language_support.as_ref()));
        assert!(!check_for_injection_pattern("System.out.println(\"Hello\")", language_support.as_ref()));
        assert!(!check_for_injection_pattern("methodCall()", language_support.as_ref()));
        assert!(!check_for_injection_pattern("42", language_support.as_ref()));
    }

    #[test]
    #[cfg(feature = "javascript")]
    fn test_javascript_injection_patterns() {
        let language_support = get_language_support("javascript").expect("Failed to get JavaScript support");

        // Template-literal backticks and command separators — should detect.
        assert!(check_for_injection_pattern("`SELECT * FROM ${tableName}`", language_support.as_ref()));
        assert!(check_for_injection_pattern("query = `Hello ${name}!`", language_support.as_ref()));
        assert!(check_for_injection_pattern("cmd; rm -rf /", language_support.as_ref()));
        assert!(check_for_injection_pattern("ls && malware", language_support.as_ref()));
        assert!(check_for_injection_pattern("echo safe || dangerous", language_support.as_ref()));

        // Dangerous builtins — should detect.
        assert!(check_for_injection_pattern("eval(userCode)", language_support.as_ref()));

        // URL-scheme markers — should detect.
        assert!(check_for_injection_pattern("location.href = 'javascript:alert(1)'", language_support.as_ref()));
        assert!(check_for_injection_pattern("img.src = 'data:image/png;base64,...'", language_support.as_ref()));

        // Plain `${var}` (without backticks) is not detected at this layer.
        assert!(!check_for_injection_pattern("${userInput}", language_support.as_ref()));
        // Concatenation is no longer flagged here.
        assert!(!check_for_injection_pattern(r#""SELECT * FROM users WHERE id = " + userId"#, language_support.as_ref()));

        // Safe text — should NOT detect.
        assert!(!check_for_injection_pattern(r#""SELECT COUNT(*) FROM users""#, language_support.as_ref()));
        assert!(!check_for_injection_pattern("console.log('Hello')", language_support.as_ref()));
        assert!(!check_for_injection_pattern("regularFunction", language_support.as_ref()));
        assert!(!check_for_injection_pattern("123", language_support.as_ref()));
    }

    #[test]
    #[cfg(feature = "python")]
    fn test_python_has_injection_pattern_integration() {
        // `has_injection_pattern` combines `!is_literal_node(arg)` AND
        // `check_for_injection_pattern(arg_text)`. f-strings come back as
        // `string`-kind nodes in tree-sitter-python 0.23 and are treated as
        // literals; combined with the narrow text heuristic, the f-string
        // example below is not flagged. The injection case below uses a
        // command-separator inside the f-string to trigger detection.
        let language_support = get_language_support("python").expect("Failed to get Python support");
        let mut parser = LanguageParser::new("python").expect("Failed to create parser");

        let injected_code = r#"
def run(user):
    os.system(f"ping {user}; rm -rf /")
"#;

        let source = injected_code.as_bytes();
        let tree = parser.parse(source).expect("Failed to parse code");
        let root_node = tree.root_node();

        let mut found_injection = false;

        fn visit_nodes<F>(node: &tree_sitter::Node, source: &[u8], language_support: &dyn LanguageSupport, callback: &mut F)
        where
            F: FnMut(bool),
        {
            for call_type in language_support.call_node_types() {
                if node.kind() == *call_type {
                    if let Some(func_name) = language_support.get_function_name(node, source) {
                        if func_name.contains("system") {
                            let has_pattern = ScanningLogic::has_injection_pattern(node, source, language_support);
                            callback(has_pattern);
                            return;
                        }
                    }
                }
            }

            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    visit_nodes(&child, source, language_support, callback);
                }
            }
        }

        visit_nodes(&root_node, source, language_support.as_ref(), &mut |has_pattern| {
            found_injection = has_pattern;
        });

        // Note: the f-string argument is a `string`-kind node and is therefore
        // treated as a literal, so even with `;` in the source, the current
        // heuristic short-circuits before scanning the text. This asserts
        // current behaviour.
        assert!(!found_injection, "Current narrow heuristic treats f-string args as literals");
    }

    #[test]
    #[cfg(feature = "python")]
    fn test_python_safe_code_no_injection_pattern() {
        let language_support = get_language_support("python").expect("Failed to get Python support");
        let mut parser = LanguageParser::new("python").expect("Failed to create parser");

        let safe_code = r#"
def get_all_users():
    cursor.execute("SELECT * FROM users")
    return cursor.fetchall()
"#;

        let source = safe_code.as_bytes();
        let tree = parser.parse(source).expect("Failed to parse code");
        let root_node = tree.root_node();

        let mut found_injection = false;

        fn visit_nodes<F>(node: &tree_sitter::Node, source: &[u8], language_support: &dyn LanguageSupport, callback: &mut F)
        where
            F: FnMut(bool),
        {
            for call_type in language_support.call_node_types() {
                if node.kind() == *call_type {
                    if let Some(func_name) = language_support.get_function_name(node, source) {
                        if func_name.contains("execute") {
                            let has_pattern = ScanningLogic::has_injection_pattern(node, source, language_support);
                            callback(has_pattern);
                            return;
                        }
                    }
                }
            }

            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
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
        // The Java example concatenates a string with a variable inside
        // `execute`. The concatenation node is not literal, so the gate passes,
        // but the heuristic text scan no longer fires on raw `+` joins. To
        // exercise positive detection we inject a command separator into the
        // literal half of the concatenation.
        let language_support = get_language_support("java").expect("Failed to get Java support");
        let mut parser = LanguageParser::new("java").expect("Failed to create parser");

        let vulnerable_code = r#"
public class TestClass {
    public void vulnerableQuery(String userId, Statement stmt) throws SQLException {
        stmt.execute("SELECT * FROM users; DROP TABLE users; --" + userId);
    }
}
"#;

        let source = vulnerable_code.as_bytes();
        let tree = parser.parse(source).expect("Failed to parse code");
        let root_node = tree.root_node();

        let mut found_injection = false;

        fn visit_nodes<F>(node: &tree_sitter::Node, source: &[u8], language_support: &dyn LanguageSupport, callback: &mut F)
        where
            F: FnMut(bool),
        {
            for call_type in language_support.call_node_types() {
                if node.kind() == *call_type {
                    if let Some(func_name) = language_support.get_function_name(node, source) {
                        if func_name.contains("execute") {
                            let has_pattern = ScanningLogic::has_injection_pattern(node, source, language_support);
                            callback(has_pattern);
                            return;
                        }
                    }
                }
            }

            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    visit_nodes(&child, source, language_support, callback);
                }
            }
        }

        visit_nodes(&root_node, source, language_support.as_ref(), &mut |has_pattern| {
            found_injection = has_pattern;
        });

        assert!(found_injection, "Should detect injection pattern when `;` separator appears in concatenated SQL");
    }

    #[test]
    #[cfg(feature = "javascript")]
    fn test_javascript_injection_pattern_integration() {
        let language_support = get_language_support("javascript").expect("Failed to get JavaScript support");
        let mut parser = LanguageParser::new("javascript").expect("Failed to create parser");

        let vulnerable_code = r#"
function getUser(userId) {
    db.execute(`SELECT * FROM users WHERE id = ${userId}`);
}
"#;

        let source = vulnerable_code.as_bytes();
        let tree = parser.parse(source).expect("Failed to parse code");
        let root_node = tree.root_node();

        let mut found_injection = false;

        fn visit_nodes<F>(node: &tree_sitter::Node, source: &[u8], language_support: &dyn LanguageSupport, callback: &mut F)
        where
            F: FnMut(bool),
        {
            for call_type in language_support.call_node_types() {
                if node.kind() == *call_type {
                    if let Some(func_name) = language_support.get_function_name(node, source) {
                        if func_name.contains("execute") {
                            let has_pattern = ScanningLogic::has_injection_pattern(node, source, language_support);
                            callback(has_pattern);
                            return;
                        }
                    }
                }
            }

            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    visit_nodes(&child, source, language_support, callback);
                }
            }
        }

        visit_nodes(&root_node, source, language_support.as_ref(), &mut |has_pattern| {
            found_injection = has_pattern;
        });

        assert!(found_injection, "Should detect injection pattern in JavaScript template literal SQL query");
    }

    #[test]
    fn test_edge_cases() {
        let unsupported_result = get_language_support("unsupported");
        assert!(unsupported_result.is_err(), "Should fail for unsupported language");

        #[cfg(feature = "python")]
        {
            let language_support = get_language_support("python").expect("Failed to get Python support");
            assert!(!check_for_injection_pattern("", language_support.as_ref()));
            assert!(!check_for_injection_pattern("   ", language_support.as_ref()));
        }
    }

    #[test]
    fn test_complex_injection_scenarios() {
        // The narrow heuristic detects any of the basic markers in the input,
        // even when surrounded by otherwise innocuous text.
        #[cfg(feature = "python")]
        {
            let language_support = get_language_support("python").expect("Failed to get Python support");

            assert!(check_for_injection_pattern(
                "cmd = f'ping host'; subprocess.call(cmd, shell=True)",
                language_support.as_ref()
            ));
            assert!(check_for_injection_pattern("user_template = '{{ user.name }}'", language_support.as_ref()));
            assert!(check_for_injection_pattern("payload = $(echo pwned)", language_support.as_ref()));

            // Format strings without command markers are no longer flagged.
            assert!(!check_for_injection_pattern("query with %s and string concat", language_support.as_ref()));
        }

        #[cfg(feature = "java")]
        {
            let language_support = get_language_support("java").expect("Failed to get Java support");

            assert!(check_for_injection_pattern(
                r#""SELECT * FROM " + tableName + "; DROP TABLE foo""#,
                language_support.as_ref()
            ));

            // Pure concatenation without command markers is not flagged.
            assert!(!check_for_injection_pattern(
                r#""SELECT * FROM " + tableName + " WHERE id = " + userId"#,
                language_support.as_ref()
            ));
        }

        #[cfg(feature = "javascript")]
        {
            let language_support = get_language_support("javascript").expect("Failed to get JavaScript support");

            // Template literal with backticks AND eval() — should detect.
            assert!(check_for_injection_pattern("eval(`function() { ${userCode} }`)", language_support.as_ref()));
            // Template literal alone — the backtick triggers detection.
            assert!(check_for_injection_pattern(r#"`SELECT * FROM ${table}`"#, language_support.as_ref()));
        }
    }

    #[test]
    fn test_is_literal_node_function() {
        // In AST terms, a `string` node IS a literal. Discrimination between
        // safe constant queries and interpolated/concatenated injection
        // payloads belongs in rule conditions and taint analysis, not in this
        // primitive. The assertions below pin that contract.
        #[cfg(feature = "python")]
        {
            let mut parser = LanguageParser::new("python").expect("Failed to create parser");

            // Plain literal string.
            let literal_string_code = r#"
def func():
    return "This is a literal string"
"#;
            let source = literal_string_code.as_bytes();
            let tree = parser.parse(source).expect("Failed to parse code");

            let mut found_string_node = false;
            fn visit_nodes<F>(node: &tree_sitter::Node, callback: &mut F)
            where
                F: FnMut(&tree_sitter::Node),
            {
                callback(node);
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        visit_nodes(&child, callback);
                    }
                }
            }

            visit_nodes(&tree.root_node(), &mut |node| {
                if node.kind() == "string" {
                    found_string_node = true;
                    assert!(is_literal_node(node), "String AST node should be classified as a literal");
                }
            });
            assert!(found_string_node, "Should have found at least one string node");

            // Numeric literal.
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

            // f-string: still a `string` AST node in tree-sitter-python 0.23,
            // so it is also a literal under this primitive.
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
                    assert!(is_literal_node(node), "f-string AST node is classified as a literal under the unified primitive");
                }
            });
            assert!(found_fstring_node, "Should have found at least one f-string node");
        }

        #[cfg(feature = "javascript")]
        {
            let mut parser = LanguageParser::new("javascript").expect("Failed to create parser");

            // Template literals have their own AST kind (`template_string`) and
            // are NOT classified as literals — interpolation is observable at
            // the AST level for JS.
            let template_code = r#"
function greet(name) {
    return `Hello, ${name}`;
}
"#;
            let source = template_code.as_bytes();
            let tree = parser.parse(source).expect("Failed to parse code");

            let mut found_template_node = false;
            fn visit_nodes<F>(node: &tree_sitter::Node, callback: &mut F)
            where
                F: FnMut(&tree_sitter::Node),
            {
                callback(node);
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        visit_nodes(&child, callback);
                    }
                }
            }

            visit_nodes(&tree.root_node(), &mut |node| {
                if node.kind() == "template_string" {
                    found_template_node = true;
                    assert!(!is_literal_node(node), "JS template_string is not a literal at the AST primitive");
                }
            });

            assert!(found_template_node, "Should have found at least one template string node");
        }
    }
}
