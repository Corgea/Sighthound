use sighthound::models::UnifiedRule;
use sighthound::rules::Rules;

/// Collect every literal pattern string referenced by a rule set
/// (`pattern`, `patterns`, `sinks`).
fn collect_patterns(rules: &[UnifiedRule]) -> Vec<String> {
    let mut out = Vec::new();
    for rule in rules {
        if let Some(p) = &rule.pattern {
            out.push(p.clone());
        }
        if let Some(ps) = &rule.patterns {
            out.extend(ps.iter().cloned());
        }
        if let Some(sinks) = &rule.sinks {
            out.extend(sinks.iter().cloned());
        }
    }
    out
}

fn load_js_rules() -> Rules {
    Rules::load_from_directory("rules/javascript/")
        .expect("Failed to load JavaScript rules directory")
}

#[test]
fn test_javascript_rules_load() {
    let rules = load_js_rules();
    assert!(
        !rules.rules.is_empty(),
        "JavaScript rules should not be empty"
    );

    // Every search rule must carry a matchable pattern or patterns.
    for rule in rules.rules.iter().filter(|r| r.mode == "search") {
        assert!(
            rule.pattern.is_some() || rule.patterns.is_some(),
            "Each search rule should have a pattern or patterns: {:?}",
            rule.id
        );
    }
}

#[test]
fn test_dom_xss_sinks_present() {
    let rules = load_js_rules();
    let patterns = collect_patterns(&rules.rules);
    let joined = patterns.join("\n");

    assert!(
        joined.contains("innerHTML"),
        "JS rules should cover innerHTML"
    );
    assert!(
        joined.contains("document.write") || joined.contains("write"),
        "JS rules should cover document.write"
    );
}

#[test]
fn test_code_injection_sinks_present() {
    let rules = load_js_rules();
    let patterns = collect_patterns(&rules.rules);
    let joined = patterns.join("\n");

    assert!(joined.contains("eval"), "JS rules should cover eval");
}

#[test]
fn test_rules_carry_cwe_metadata() {
    let rules = load_js_rules();
    // At least some rules should carry a CWE id (directly or via tags) so that
    // findings can be matched to ground-truth labels.
    let with_cwe = rules.rules.iter().any(|r| {
        r.cwe_id.is_some()
            || r.tags
                .as_ref()
                .map(|t| t.iter().any(|tag| tag.to_lowercase().starts_with("cwe")))
                .unwrap_or(false)
    });
    assert!(
        with_cwe,
        "Expected at least one JavaScript rule to carry CWE metadata"
    );
}
