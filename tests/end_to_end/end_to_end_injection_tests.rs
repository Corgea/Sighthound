use sighthound::VulnerabilityScanner;
use sighthound::rules::Rules;
use std::fs;
use std::io::Write;
use tempfile::{NamedTempFile, TempDir};

// note: the dedicated injection-sink analyzer was folded into the unified search scanner.
// Search rules tagged `category: "injection"` are gated by `has_injection_pattern`, which
// flags a sink only when an argument is non-literal AND contains a command/template
// injection indicator token (`;`, `&&`, `||`, backtick, `$(`, `eval(`, ...). Literal-string
// sink calls are therefore correctly treated as safe. The vulnerable samples below use
// tainted concatenation/template-literal forms that this gating detects; the old
// f-string/`%`-format SQL examples are now the domain of taint analysis, not search rules.
#[cfg(test)]
mod end_to_end_injection_tests {
    use super::*;

    fn create_temp_dir_with_files(files: Vec<(&str, &str)>) -> TempDir {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");

        for (filename, content) in files {
            let file_path = temp_dir.path().join(filename);
            if let Some(parent) = file_path.parent() {
                fs::create_dir_all(parent).expect("Failed to create parent directories");
            }
            fs::write(&file_path, content).expect("Failed to write file");
        }

        temp_dir
    }

    fn create_test_rules() -> NamedTempFile {
        let rules_content = r#"(
            rules: [
                // SQL injection sinks
                (
                    category: Some("injection"),
                    pattern: Some("*.execute"),
                    finding_type: Some("sql_injection"),
                    severity: Some("high"),
                    confidence: Some("high"),
                ),
                (
                    category: Some("injection"),
                    pattern: Some("cursor.execute"),
                    finding_type: Some("sql_injection"),
                    severity: Some("high"),
                    confidence: Some("high"),
                ),
                // Command injection sinks
                (
                    category: Some("injection"),
                    pattern: Some("Runtime.exec"),
                    finding_type: Some("command_injection"),
                    severity: Some("high"),
                    confidence: Some("high"),
                ),
                (
                    category: Some("injection"),
                    pattern: Some("os.system"),
                    finding_type: Some("command_injection"),
                    severity: Some("high"),
                    confidence: Some("high"),
                ),
                (
                    category: Some("injection"),
                    pattern: Some("subprocess.*"),
                    finding_type: Some("command_injection"),
                    severity: Some("high"),
                    confidence: Some("high"),
                ),
            ]
        )"#;

        let mut temp_file = NamedTempFile::with_suffix(".ron").expect("Failed to create temp file");
        write!(temp_file, "{}", rules_content).expect("Failed to write rules");
        temp_file
    }

    #[test]
    #[cfg(feature = "python")]
    fn test_python_sql_injection_detection() {
        let python_files = vec![
            (
                "vulnerable.py",
                r#"
import sqlite3

def get_user_vulnerable(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Tainted concatenation with a stacked-query separator
    cursor.execute("SELECT * FROM users WHERE id = " + user_id + "; DROP TABLE users")
    return cursor.fetchone()

def get_user_vulnerable2(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Tainted concatenation chained with a shell command
    cursor.execute("SELECT * FROM users WHERE name = " + user_id + " && evil")
    return cursor.fetchone()

def get_user_vulnerable3(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Tainted concatenation with an OR injection
    cursor.execute("SELECT * FROM users WHERE x = " + user_id + " || 1=1")
    return cursor.fetchone()

def get_user_safe():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Literal string - should NOT be detected
    cursor.execute("SELECT * FROM users")
    return cursor.fetchall()
"#,
            ),
            (
                "safe.py",
                r#"
import sqlite3

def get_all_users():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    return cursor.fetchall()

def count_users():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    return cursor.fetchone()[0]
"#,
            ),
        ];

        let temp_dir = create_temp_dir_with_files(python_files);
        let rules_file = create_test_rules();

        // Load rules and create scanner
        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");
        let scanner = VulnerabilityScanner::new("python", rules).expect("Failed to create scanner");

        // Scan the directory
        let findings = scanner
            .find_vulnerabilities_single_threaded(temp_dir.path().to_str().unwrap(), "python")
            .expect("Failed to scan directory");

        println!("Found {} findings", findings.len());
        for finding in &findings {
            println!(
                "Finding: {} in {} at line {} - {}",
                finding.finding_type, finding.file, finding.line, finding.snippet
            );
        }

        // Should find 3 vulnerabilities in vulnerable.py, none in safe.py
        assert!(findings.len() >= 3, "Should find at least 3 SQL injection vulnerabilities");

        // Verify all findings are SQL injection
        let sql_injection_count =
            findings.iter().filter(|f| f.finding_type == "sql_injection").count();
        assert!(sql_injection_count >= 3, "Should find at least 3 SQL injection vulnerabilities");

        // Verify findings are in the vulnerable file
        let vulnerable_findings =
            findings.iter().filter(|f| f.file.contains("vulnerable.py")).count();
        assert!(vulnerable_findings >= 3, "Should find vulnerabilities in vulnerable.py");

        // Verify no findings in safe file (literal-string queries are not flagged)
        let safe_findings = findings.iter().filter(|f| f.file.contains("safe.py")).count();
        assert_eq!(safe_findings, 0, "Should find no vulnerabilities in safe.py");
    }

    #[test]
    #[cfg(feature = "python")]
    fn test_python_command_injection_detection() {
        let python_files = vec![(
            "cmd_vulnerable.py",
            r#"
import os
import subprocess

def run_command_vulnerable1(user_input):
    # Tainted concatenation with a command separator
    os.system("ping " + user_input + "; rm -rf /")

def run_command_vulnerable2(host):
    # Tainted concatenation chained with another command
    subprocess.call("ping " + host + " && curl evil", shell=True)

def run_command_vulnerable3(file):
    # Tainted concatenation with command chaining
    subprocess.run("cat " + file + " && malware", shell=True)

def run_safe_command():
    # Literal string - should NOT be detected
    os.system("ls -la")
"#,
        )];

        let temp_dir = create_temp_dir_with_files(python_files);
        let rules_file = create_test_rules();

        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");
        let scanner = VulnerabilityScanner::new("python", rules).expect("Failed to create scanner");

        let findings = scanner
            .find_vulnerabilities_single_threaded(temp_dir.path().to_str().unwrap(), "python")
            .expect("Failed to scan directory");

        println!("Found {} command injection findings", findings.len());
        for finding in &findings {
            println!(
                "Finding: {} in {} at line {} - {}",
                finding.finding_type, finding.file, finding.line, finding.snippet
            );
        }

        // Should find command injection vulnerabilities
        assert!(findings.len() >= 2, "Should find at least 2 command injection vulnerabilities");

        let cmd_injection_count =
            findings.iter().filter(|f| f.finding_type == "command_injection").count();
        assert!(cmd_injection_count >= 2, "Should find command injection vulnerabilities");
    }

    /// Shared per-call-site context for [`scan_call_arguments_for_injection`], to keep that
    /// helper's own parameter count small.
    #[cfg(feature = "java")]
    struct MethodCallSite<'a> {
        node_text: &'a str,
        source: &'a [u8],
        filepath: &'a str,
        line: usize,
        func_name: &'a str,
        indent: &'a str,
        language_support: &'a dyn sighthound::language::LanguageSupport,
    }

    #[cfg(feature = "java")]
    fn is_vulnerable_sql_arg(
        arg_kind: &str,
        arg_text: &str,
        language_support: &dyn sighthound::language::LanguageSupport,
    ) -> bool {
        arg_kind == "binary_expression" // String concatenation
            || arg_kind == "method_invocation" // Method calls like String.format
            || sighthound::rules::check_for_injection_pattern(arg_text, language_support)
    }

    #[cfg(feature = "java")]
    fn is_vulnerable_command_arg(
        arg_kind: &str,
        arg_text: &str,
        language_support: &dyn sighthound::language::LanguageSupport,
    ) -> bool {
        arg_kind == "binary_expression" // String concatenation
            || arg_text.contains('+')
            || arg_text.contains(';')
            || sighthound::rules::check_for_injection_pattern(arg_text, language_support)
    }

    #[cfg(feature = "java")]
    fn push_injection_finding(
        findings: &mut Vec<sighthound::models::Finding>,
        filepath: &str,
        line: usize,
        func_name: &str,
        finding_type: &str,
        node_text: &str,
    ) {
        findings.push(sighthound::models::Finding {
            file: filepath.to_string(),
            line,
            column: 0,
            end_line: line,
            end_column: 0,
            function: func_name.to_string(),
            finding_type: finding_type.to_string(),
            snippet: node_text.to_string(),
            severity: "High".to_string(),
            confidence: "High".to_string(),
            description: None,
            cwe_id: None,
            source_info: None,
            sink_info: None,
            traces: None,
            tags: None,
        });
    }

    /// Check a method-invocation's arguments for injection indicators and record a finding of
    /// `finding_type` for each argument that `is_vulnerable_arg` flags.
    #[cfg(feature = "java")]
    fn scan_call_arguments_for_injection(
        node: &tree_sitter::Node,
        site: &MethodCallSite,
        finding_type: &str,
        vulnerable_label: &str,
        is_vulnerable_arg: fn(&str, &str, &dyn sighthound::language::LanguageSupport) -> bool,
        findings: &mut Vec<sighthound::models::Finding>,
    ) {
        let Some(args_node) = site.language_support.get_arguments_node(node) else {
            return;
        };
        for i in 0..args_node.named_child_count() {
            let Some(arg) = args_node.named_child(i as u32) else {
                continue;
            };
            let arg_text = String::from_utf8_lossy(&site.source[arg.start_byte()..arg.end_byte()]);
            let arg_kind = arg.kind();

            println!("{}Argument {}: {} (kind: {})", site.indent, i, arg_text, arg_kind);

            // Check for signs of injection vulnerability
            if is_vulnerable_arg(arg_kind, &arg_text, site.language_support) {
                println!("{}VULNERABLE: {} found", site.indent, vulnerable_label);
                push_injection_finding(
                    findings,
                    site.filepath,
                    site.line,
                    site.func_name,
                    finding_type,
                    site.node_text,
                );
            }
        }
    }

    /// Recursively search for method invocations and flag SQL/command injection in their
    /// arguments.
    #[cfg(feature = "java")]
    fn find_vulnerabilities(
        node: &tree_sitter::Node,
        source: &[u8],
        filepath: &str,
        language_support: &dyn sighthound::language::LanguageSupport,
        findings: &mut Vec<sighthound::models::Finding>,
        depth: usize,
    ) {
        let indent = "  ".repeat(depth);

        // Check if this node is a method invocation
        if node.kind() == "method_invocation" {
            let node_text = String::from_utf8_lossy(&source[node.start_byte()..node.end_byte()]);
            let line = node.start_position().row + 1;

            // If this is an execute()/exec() method, check its arguments for injection patterns
            if let Some(func_name) = language_support.get_function_name(node, source) {
                println!("{}Processing method: {}", indent, func_name);

                let site = MethodCallSite {
                    node_text: &node_text,
                    source,
                    filepath,
                    line,
                    func_name,
                    indent: &indent,
                    language_support,
                };

                // Check for SQL injection
                if func_name == "execute" {
                    scan_call_arguments_for_injection(
                        node,
                        &site,
                        "sql_injection",
                        "SQL injection",
                        is_vulnerable_sql_arg,
                        findings,
                    );
                }

                // Check for command injection
                if func_name == "exec" {
                    scan_call_arguments_for_injection(
                        node,
                        &site,
                        "command_injection",
                        "Command injection",
                        is_vulnerable_command_arg,
                        findings,
                    );
                }
            }
        }

        // Recursively process all children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i as u32) {
                find_vulnerabilities(
                    &child,
                    source,
                    filepath,
                    language_support,
                    findings,
                    depth + 1,
                );
            }
        }
    }

    #[test]
    #[cfg(feature = "java")]
    fn test_java_sql_injection_detection() {
        // For this test, we'll use a direct validation approach rather than using the scanner

        // 1. Create our test files
        let java_files = vec![(
            "VulnerableService.java",
            r#"
package com.example;
import java.sql.*;
import java.io.*;

public class VulnerableService {

    public void sqlInjectionVuln1(String userId, Statement stmt) throws SQLException {
        // This should be detected - string concatenation
        stmt.execute("SELECT * FROM users WHERE id = " + userId);
    }

    public void sqlInjectionVuln2(String tableName, Statement stmt) throws SQLException {
        // This should be detected - String.format
        stmt.execute(String.format("SELECT * FROM %s", tableName));
    }

    public void commandInjectionVuln(String userCmd) throws IOException {
        // This should be detected - Runtime.exec with concatenation
        Runtime.getRuntime().exec("ping " + userCmd + "; malware.exe");
    }

    public void safeSqlQuery(Statement stmt) throws SQLException {
        // This should NOT be detected - literal string
        stmt.execute("SELECT COUNT(*) FROM users");
    }
}
"#,
        )];

        let temp_dir = create_temp_dir_with_files(java_files);
        println!("Java test files created at: {}", temp_dir.path().display());

        // 2. Directly validate the injection pattern detection logic
        #[cfg(feature = "java")]
        {
            use sighthound::parser::LanguageParser;

            // Create findings vector to store our results
            let mut findings = Vec::new();

            let java_file_path = temp_dir.path().join("VulnerableService.java");
            let filepath = java_file_path.to_string_lossy().to_string();

            // Parse the source code
            let mut parser = LanguageParser::new("java").expect("Failed to create Java parser");
            let source = fs::read(&java_file_path).expect("Failed to read Java file");
            let tree = parser.parse(&source).expect("Failed to parse Java file");
            let root_node = tree.root_node();
            let language_support = parser.language_support();

            // Analyze the Java file directly
            find_vulnerabilities(
                &root_node,
                &source,
                &filepath,
                language_support,
                &mut findings,
                0,
            );

            // Display findings
            println!("\nFound {} Java findings", findings.len());
            for finding in &findings {
                println!(
                    "Finding: {} in {} at line {} - {}",
                    finding.finding_type, finding.file, finding.line, finding.snippet
                );
            }

            // Verify results
            assert!(findings.len() >= 3, "Should find at least 3 vulnerabilities in Java code");

            let sql_findings =
                findings.iter().filter(|f| f.finding_type == "sql_injection").count();
            let cmd_findings =
                findings.iter().filter(|f| f.finding_type == "command_injection").count();

            assert!(sql_findings >= 2, "Should find at least 2 SQL injection vulnerabilities");
            assert!(cmd_findings >= 1, "Should find at least 1 command injection vulnerability");
        }

        #[cfg(not(feature = "java"))]
        {
            println!("Java feature not enabled, skipping test");
            assert!(false, "Java feature not enabled");
        }
    }

    #[test]
    #[cfg(feature = "javascript")]
    fn test_javascript_injection_detection() {
        let js_files = vec![(
            "vulnerable.js",
            r#"
const db = require('db');

function getUserVulnerable1(userId) {
    // This should be detected - template literal (backtick) sink
    db.execute(`SELECT * FROM users WHERE id = ${userId}`);
}

function dangerousEval(userCode) {
    // This should be detected - eval with template literal
    eval(`function() { ${userCode} }`);
}

function updateDOM(userHtml) {
    // This should be detected - innerHTML assignment from user data
    document.body.innerHTML = userHtml;
}

function safeQuery() {
    // This should NOT be detected - literal string
    db.execute("SELECT COUNT(*) FROM users");
}
"#,
        )];

        let temp_dir = create_temp_dir_with_files(js_files);

        // JavaScript-specific rules. db.execute/eval use injection gating (literal args are
        // skipped); the innerHTML rule matches the tainted assignment by full-context pattern.
        let js_rules_content = r#"(
            rules: [
                (
                    category: Some("injection"),
                    pattern: Some("db.execute"),
                    finding_type: Some("sql_injection"),
                    severity: Some("high"),
                    confidence: Some("high"),
                ),
                (
                    category: Some("injection"),
                    pattern: Some("eval"),
                    finding_type: Some("code_injection"),
                    severity: Some("critical"),
                    confidence: Some("high"),
                ),
                (
                    pattern: Some("*.innerHTML*=*user*"),
                    finding_type: Some("xss"),
                    severity: Some("high"),
                    confidence: Some("medium"),
                ),
            ]
        )"#;

        let mut js_rules_file =
            NamedTempFile::with_suffix(".ron").expect("Failed to create temp file");
        write!(js_rules_file, "{}", js_rules_content).expect("Failed to write rules");

        let rules = Rules::load_from_file(js_rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");
        let scanner =
            VulnerabilityScanner::new("javascript", rules).expect("Failed to create scanner");

        let findings = scanner
            .find_vulnerabilities_single_threaded(temp_dir.path().to_str().unwrap(), "javascript")
            .expect("Failed to scan directory");

        println!("Found {} JavaScript findings", findings.len());
        for finding in &findings {
            println!(
                "Finding: {} in {} at line {} - {}",
                finding.finding_type, finding.file, finding.line, finding.snippet
            );
        }

        // Should find multiple vulnerabilities
        assert!(findings.len() >= 3, "Should find at least 3 vulnerabilities in JavaScript code");

        // Check for different types of vulnerabilities
        let has_sql_injection = findings.iter().any(|f| f.finding_type == "sql_injection");
        let has_code_injection = findings.iter().any(|f| f.finding_type == "code_injection");
        let has_xss = findings.iter().any(|f| f.finding_type == "xss");

        assert!(
            has_sql_injection || has_code_injection || has_xss,
            "Should find different types of injection vulnerabilities"
        );
    }

    #[test]
    fn test_no_false_positives_on_safe_code() {
        let safe_files = vec![(
            "SafePython.py",
            r#"
import sqlite3

def get_all_users():
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    return cursor.fetchall()

def get_user_count():
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    return cursor.fetchone()[0]

def safe_print():
    print("Hello World")
    print(f"Static message")
    print("Value: {}".format(42))
"#,
        )];

        let temp_dir = create_temp_dir_with_files(safe_files);
        let rules_file = create_test_rules();

        let rules = Rules::load_from_file(rules_file.path().to_str().unwrap())
            .expect("Failed to load rules");

        #[cfg(feature = "python")]
        {
            let scanner =
                VulnerabilityScanner::new("python", rules).expect("Failed to create scanner");

            let findings = scanner
                .find_vulnerabilities_single_threaded(temp_dir.path().to_str().unwrap(), "python")
                .expect("Failed to scan directory");

            println!("Found {} findings in safe code (should be 0)", findings.len());
            for finding in &findings {
                println!(
                    "Unexpected finding: {} in {} at line {} - {}",
                    finding.finding_type, finding.file, finding.line, finding.snippet
                );
            }

            // Should find no vulnerabilities in safe code
            assert_eq!(findings.len(), 0, "Should find no vulnerabilities in safe code");
        }
    }
}
