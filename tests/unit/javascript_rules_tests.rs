use ron::error::SpannedError;
use ron::from_str;
use sighthound::rules::Rules;

const DOM_XSS_FIXTURE: &str = r#"(
    rules: [
        (
            category: Some("xss"),
            mode: "search",
            patterns: Some(["*.innerHTML*=*user*", "document.write"]),
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

const UNSAFE_OBJECT_FIXTURE: &str = r#"(
    rules: [
        (
            category: Some("unsafe_object"),
            mode: "search",
            patterns: Some(["JSON.parse", "eval"]),
            finding_type: Some("Unsafe Object Operation"),
            severity: Some("Medium"),
            confidence: Some("Medium"),
            file_types: Some((
                extensions: Some([".js", ".jsx"]),
                exclude_patterns: Some(["*.min.js"]),
            )),
        ),
    ],
)"#;

const CODE_INJECTION_FIXTURE: &str = r#"(
    rules: [
        (
            category: Some("code_injection"),
            mode: "search",
            patterns: Some(["new Function", "setTimeout", "setInterval", "eval"]),
            finding_type: Some("Code Injection"),
            severity: Some("Critical"),
            confidence: Some("High"),
            file_types: Some((
                extensions: Some([".js", ".jsx", ".ts", ".tsx"]),
                exclude_patterns: Some(["*.min.js", "*.test.js"]),
            )),
        ),
    ],
)"#;

#[test]
fn test_dom_xss_rules() {
    let rules: Rules = from_str(DOM_XSS_FIXTURE).expect("Failed to parse DOM XSS fixture");
    let xss = rules.get_rules_by_category("xss");
    assert!(!xss.is_empty(), "should have at least one XSS rule");

    let first = xss[0];
    let patterns = first.patterns.as_ref().expect("patterns set");
    assert!(patterns.iter().any(|p| p.contains("innerHTML")));
    assert!(patterns.iter().any(|p| p.contains("document.write")));

    let file_types = first.file_types.as_ref().expect("file_types set");
    assert!(
        file_types.extensions.as_ref().map(|e| !e.is_empty()).unwrap_or(false),
        "extensions should be populated"
    );
}

#[test]
fn test_unsafe_object_rules() {
    let rules: Rules = from_str(UNSAFE_OBJECT_FIXTURE).expect("Failed to parse unsafe object fixture");
    let unsafe_ops = rules.get_rules_by_category("unsafe_object");
    assert!(!unsafe_ops.is_empty(), "should have at least one unsafe-object rule");

    let first = unsafe_ops[0];
    let patterns = first.patterns.as_ref().expect("patterns set");
    assert!(patterns.iter().any(|p| p == "JSON.parse"));
    assert!(patterns.iter().any(|p| p == "eval"));
}

#[test]
fn test_code_injection_rules() {
    let rules: Rules = from_str(CODE_INJECTION_FIXTURE).expect("Failed to parse code injection fixture");
    let injection = rules.get_rules_by_category("code_injection");
    assert!(!injection.is_empty(), "should have at least one code-injection rule");

    let first = injection[0];
    let patterns = first.patterns.as_ref().expect("patterns set");
    assert!(patterns.iter().any(|p| p.contains("new Function")));
    assert!(patterns.iter().any(|p| p == "setTimeout"));
}

#[test]
fn test_rule_conditions() {
    let rules: Rules = from_str(DOM_XSS_FIXTURE).expect("Failed to parse DOM XSS fixture");
    let first = rules.rules.first().expect("at least one rule");
    let conditions = first.conditions.as_ref().expect("conditions set");
    assert!(!conditions.is_empty(), "Rule should have conditions");
    assert!(!conditions[0].field.is_empty(), "Condition should have field");
    assert!(!conditions[0].operator.is_empty(), "Condition should have operator");
}

#[test]
fn test_file_type_patterns() {
    let fixtures = [DOM_XSS_FIXTURE, UNSAFE_OBJECT_FIXTURE, CODE_INJECTION_FIXTURE];

    for fixture in fixtures.iter() {
        let result: Result<Rules, SpannedError> = from_str(fixture);
        assert!(result.is_ok(), "Failed to parse fixture: {:?}", result.err());

        let rules = result.unwrap();
        for rule in &rules.rules {
            let file_types = rule.file_types.as_ref().expect("file_types set");
            assert!(
                file_types.extensions.as_ref().map(|e| !e.is_empty()).unwrap_or(false),
                "extensions should be populated"
            );
            assert!(
                file_types.exclude_patterns.as_ref().map(|p| !p.is_empty()).unwrap_or(false),
                "exclude_patterns should be populated"
            );
        }
    }
}
