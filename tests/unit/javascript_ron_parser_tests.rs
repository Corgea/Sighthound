use ron::error::SpannedError;
use ron::from_str;
use serde::Deserialize;
use sighthound::rules::Rules;

// Inline fixture exercising the full UnifiedRule shape: pattern/patterns,
// finding_type/severity/confidence, file_types, and AST conditions. Mirrors
// the schema in `src/models.rs::UnifiedRule`.
const DOM_XSS_FIXTURE: &str = r#"(
    rules: [
        (
            id: Some("js-dom-xss-innerhtml"),
            name: Some("DOM XSS via innerHTML"),
            category: Some("xss"),
            mode: "search",
            patterns: Some([
                "*.innerHTML*=*user*",
                "*.innerHTML*=*location*",
            ]),
            finding_type: Some("DOM XSS"),
            severity: Some("High"),
            confidence: Some("High"),
            cwe_id: Some("cwe-79"),
            file_types: Some((
                extensions: Some([".js", ".jsx", ".ts", ".tsx"]),
                exclude_patterns: Some(["*.min.js", "*.test.js"]),
            )),
            conditions: Some([
                (
                    field: "argument",
                    operator: "not_literal",
                    value: "",
                    condition_type: Some("not_literal"),
                    argument_position: Some(0),
                ),
            ]),
            tags: Some(["xss", "dom", "frontend"]),
        ),
        (
            id: Some("js-document-write"),
            name: Some("DOM XSS via document.write"),
            category: Some("xss"),
            mode: "search",
            pattern: Some("document.write"),
            finding_type: Some("DOM XSS"),
            severity: Some("High"),
            confidence: Some("High"),
            file_types: Some((
                extensions: Some([".js", ".jsx"]),
                exclude_patterns: Some(["*.min.js"]),
            )),
            conditions: Some([
                (
                    field: "argument",
                    operator: "not_literal",
                    value: "",
                    condition_type: Some("not_literal"),
                    argument_position: Some(0),
                ),
            ]),
        ),
    ],
)"#;

#[test]
fn test_basic_ron_structure() {
    let simple_ron = r#"(
        key: "value",
        number: 42,
        array: [1, 2, 3],
        nested: (
            field: "nested_value",
        ),
    )"#;

    #[derive(Debug, Deserialize)]
    struct SimpleStruct {
        #[allow(dead_code)] key: String,
        #[allow(dead_code)] number: i32,
        #[allow(dead_code)] array: Vec<i32>,
        #[allow(dead_code)] nested: NestedStruct,
    }

    #[derive(Debug, Deserialize)]
    struct NestedStruct {
        #[allow(dead_code)] field: String,
    }

    let result: Result<SimpleStruct, SpannedError> = from_str(simple_ron);
    assert!(result.is_ok(), "Failed to parse basic RON structure");
}

#[test]
fn test_dom_xss_ron_structure() {
    let rules: Rules = from_str(DOM_XSS_FIXTURE).expect("Failed to parse DOM XSS fixture");

    assert!(!rules.rules.is_empty(), "rules list should not be empty");
    let xss_rules = rules.get_rules_by_category("xss");
    assert!(!xss_rules.is_empty(), "should have at least one XSS rule");

    let first = &rules.rules[0];
    assert!(first.is_search_rule(), "first rule should be search mode");
    assert!(first.patterns.is_some(), "first rule should declare patterns");
    assert_eq!(first.get_finding_type(), "DOM XSS");
    assert_eq!(first.get_severity(), "High");
    assert!(first.file_types.is_some(), "file_types should be set");
}

#[test]
fn test_ron_syntax_validation() {
    let valid_ron = r#"(
        field: "value",
        array: [1, 2, 3],
        object: (
            nested: "value",
        ),
    )"#;

    #[derive(Debug, Deserialize)]
    struct TestStruct {
        #[allow(dead_code)] field: String,
        #[allow(dead_code)] array: Vec<i32>,
        #[allow(dead_code)] object: NestedStruct,
    }

    #[derive(Debug, Deserialize)]
    struct NestedStruct {
        #[allow(dead_code)] nested: String,
    }

    let result: Result<TestStruct, SpannedError> = from_str(valid_ron);
    assert!(result.is_ok(), "Failed to parse valid RON syntax");

    let invalid_ron = r#"(
        field: "value",
        array: [1, 2, 3,
        object: (
            nested: "value",
        ),
    )"#;

    let result: Result<TestStruct, SpannedError> = from_str(invalid_ron);
    assert!(result.is_err(), "Should fail to parse invalid RON syntax");
}

#[test]
fn test_rule_file_parsing() {
    // Each fixture represents a distinct rule category; parsing should succeed
    // for all of them under the unified schema.
    let fixtures: &[(&str, &str)] = &[
        ("dom_xss", DOM_XSS_FIXTURE),
        (
            "code_injection",
            r#"(
                rules: [
                    (
                        category: Some("code_injection"),
                        mode: "search",
                        pattern: Some("eval"),
                        finding_type: Some("Code Injection"),
                        severity: Some("Critical"),
                        confidence: Some("High"),
                        file_types: Some((extensions: Some([".js"]))),
                    ),
                ],
            )"#,
        ),
        (
            "unsafe_object_ops",
            r#"(
                rules: [
                    (
                        category: Some("unsafe_object"),
                        mode: "search",
                        patterns: Some(["JSON.parse", "Object.assign"]),
                        finding_type: Some("Unsafe Object Operation"),
                        severity: Some("Medium"),
                        confidence: Some("Medium"),
                        file_types: Some((extensions: Some([".js"]))),
                    ),
                ],
            )"#,
        ),
    ];

    for (name, content) in fixtures {
        let result: Result<Rules, SpannedError> = from_str(content);
        assert!(result.is_ok(), "Failed to parse {} fixture: {:?}", name, result.err());
    }
}

#[test]
fn test_ron_field_types() {
    let rules: Rules = from_str(DOM_XSS_FIXTURE).expect("Failed to parse DOM XSS fixture");

    let first = rules.rules.first().expect("at least one rule");
    let file_types = first.file_types.as_ref().expect("file_types set");
    assert!(file_types.extensions.is_some(), "extensions should be set");
    assert!(
        file_types
            .extensions
            .as_ref()
            .map(|exts| !exts.is_empty())
            .unwrap_or(false),
        "extensions should not be empty"
    );
    assert!(
        file_types
            .exclude_patterns
            .as_ref()
            .map(|p| !p.is_empty())
            .unwrap_or(false),
        "exclude_patterns should not be empty"
    );
}

#[test]
fn test_ron_condition_structure() {
    let rules: Rules = from_str(DOM_XSS_FIXTURE).expect("Failed to parse DOM XSS fixture");

    let first = rules.rules.first().expect("at least one rule");
    let conditions = first.conditions.as_ref().expect("conditions set");
    assert!(!conditions.is_empty(), "Rule should have conditions");

    let first_condition = &conditions[0];
    assert!(!first_condition.field.is_empty(), "Condition should have field");
    assert!(!first_condition.operator.is_empty(), "Condition should have operator");
    assert_eq!(
        first_condition.condition_type.as_deref(),
        Some("not_literal"),
        "Condition type should round-trip through deserialization"
    );
}
