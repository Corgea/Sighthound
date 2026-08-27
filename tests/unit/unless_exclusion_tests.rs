use sighthound::models::UnifiedRule;
use sighthound::rules::{Rules, rule_matches_pattern_unified};

// UnifiedRule does not derive Default; this fills the fields these tests do not care about.
fn make_rule(patterns: Vec<&str>, unless: Option<Vec<&str>>) -> UnifiedRule {
    UnifiedRule {
        id: Some("test-rule".to_string()),
        name: None,
        description: None,
        category: None,
        mode: "search".to_string(),
        pattern: None,
        patterns: Some(patterns.into_iter().map(str::to_string).collect()),
        unless: unless.map(|entries| entries.into_iter().map(str::to_string).collect()),
        sources: None,
        sinks: None,
        propagators: None,
        sanitizers: None,
        finding_type: None,
        severity: None,
        confidence: None,
        file_types: None,
        conditions: None,
        tags: None,
        cwe_id: None,
        message: None,
    }
}

#[cfg(test)]
mod unless_exclusion_tests {
    use super::*;

    fn frontend_rules() -> Rules {
        Rules::load_from_file("rules/javascript/frontend_security.ron")
            .expect("Failed to load frontend_security.ron")
    }

    fn rule_by_id(rules: &Rules, id: &str) -> UnifiedRule {
        rules
            .rules
            .iter()
            .find(|rule| rule.id.as_deref() == Some(id))
            .unwrap_or_else(|| panic!("rule {id} missing from frontend_security.ron"))
            .clone()
    }

    // The bug this suite guards: `unless:` shipped in the rule files but had no field on
    // UnifiedRule, and serde has no deny_unknown_fields — so every exclusion parsed into
    // nothing and every scan ignored it.
    #[test]
    fn frontend_rules_parse_their_unless_lists() {
        let rules = frontend_rules();

        for (id, entries) in [
            ("js-dom-xss-001", 16),
            ("js-react-dangerously-set-inner-html-001", 5),
            ("js-dom-xss-003", 5),
        ] {
            let rule = rule_by_id(&rules, id);
            let unless = rule.unless.unwrap_or_else(|| panic!("{id} dropped its unless list"));
            assert_eq!(unless.len(), entries, "{id} unless entry count");
        }
    }

    #[test]
    fn innerhtml_rule_reports_unsanitized_assignment() {
        let rule = rule_by_id(&frontend_rules(), "js-dom-xss-001");
        assert!(rule_matches_pattern_unified(&rule, "div.innerHTML = userInput"));
    }

    #[test]
    fn innerhtml_rule_excludes_sanitized_assignment() {
        let rule = rule_by_id(&frontend_rules(), "js-dom-xss-001");
        assert!(!rule_matches_pattern_unified(
            &rule,
            "div.innerHTML = DOMPurify.sanitize(userInput)"
        ));
    }

    #[test]
    fn dangerously_set_inner_html_rule_reports_raw_html() {
        let rule = rule_by_id(&frontend_rules(), "js-react-dangerously-set-inner-html-001");
        assert!(rule_matches_pattern_unified(
            &rule,
            "dangerouslySetInnerHTML={{ __html: userProfile }}"
        ));
    }

    #[test]
    fn dangerously_set_inner_html_rule_excludes_sanitized_html() {
        let rule = rule_by_id(&frontend_rules(), "js-react-dangerously-set-inner-html-001");
        assert!(!rule_matches_pattern_unified(
            &rule,
            "dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userProfile) }}"
        ));
    }

    #[test]
    fn document_write_rule_reports_dynamic_content() {
        let rule = rule_by_id(&frontend_rules(), "js-dom-xss-003");
        assert!(rule_matches_pattern_unified(&rule, "document.write(userInput)"));
    }

    #[test]
    fn document_write_rule_excludes_static_string() {
        let rule = rule_by_id(&frontend_rules(), "js-dom-xss-003");
        assert!(!rule_matches_pattern_unified(&rule, "document.write(\"<p>data</p>\")"));
    }

    // Regression: exclusions are scoped to the matched span, not the line. An `unless`
    // string belonging to an unrelated statement must not swallow a real finding sharing
    // the line with it.
    #[test]
    fn unrelated_unless_text_on_the_same_line_does_not_suppress() {
        let rule = rule_by_id(&frontend_rules(), "js-dom-xss-001");
        assert!(rule_matches_pattern_unified(
            &rule,
            "el.addEventListener('click', h); div.innerHTML = userInput;"
        ));
    }

    #[test]
    fn safe_document_write_earlier_on_the_line_does_not_suppress() {
        let rule = rule_by_id(&frontend_rules(), "js-dom-xss-003");
        assert!(rule_matches_pattern_unified(
            &rule,
            "document.write(\"safe\"); document.write(userInput);"
        ));
    }

    #[test]
    fn sanitized_sibling_expression_does_not_suppress_a_raw_one() {
        let rule = rule_by_id(&frontend_rules(), "js-dom-xss-001");
        assert!(rule_matches_pattern_unified(
            &rule,
            "a.innerHTML = DOMPurify.sanitize(x); b.innerHTML = userInput;"
        ));
    }

    #[test]
    fn rule_without_unless_is_unaffected() {
        let rule = make_rule(vec!["*.innerHTML*=*user*"], None);

        assert!(rule.unless.is_none());
        assert!(rule_matches_pattern_unified(
            &rule,
            "div.innerHTML = DOMPurify.sanitize(userInput)"
        ));
        assert!(rule_matches_pattern_unified(&rule, "div.innerHTML = userInput"));
        assert!(!rule_matches_pattern_unified(&rule, "div.textContent = userInput"));
    }

    #[test]
    fn empty_unless_list_never_suppresses() {
        let rule = make_rule(vec!["*.innerHTML*=*user*"], Some(vec![]));

        assert!(rule_matches_pattern_unified(&rule, "div.innerHTML = userInput"));
    }
}
