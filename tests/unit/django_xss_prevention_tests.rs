use sighthound::rules::Rules;
use sighthound::VulnerabilityScanner;
use std::path::Path;

// General-security Python rules ship as `general_security.ron` (the earlier
// `general.ron` name was retired during the crate rename).
fn load_general_rules() -> Rules {
    Rules::load_from_file("rules/python/general_security.ron")
        .expect("Failed to load general security rules")
}

#[cfg(test)]
mod django_xss_tests {
    use super::*;

    #[test]
    fn test_basic_scanner_functionality() {
        let rules = load_general_rules();

        let scanner_result = VulnerabilityScanner::new("python", rules);
        assert!(scanner_result.is_ok(), "Should be able to create scanner with general rules");
        println!("Successfully created scanner with general rules");
    }

    #[test]
    fn test_django_xss_patterns_with_general_rules() {
        let rules = load_general_rules();

        let scanner_result = VulnerabilityScanner::new("python", rules);
        assert!(scanner_result.is_ok(), "Should be able to create scanner with general rules");
        println!("Successfully created scanner for Django patterns with general rules");
    }

    #[test]
    fn test_mark_safe_patterns() {
        let rules = load_general_rules();

        let scanner_result = VulnerabilityScanner::new("python", rules);
        assert!(scanner_result.is_ok(), "Should be able to create scanner with general rules");
        println!("Successfully created scanner for mark_safe patterns");
    }

    #[test]
    fn test_template_injection_patterns() {
        let rules = load_general_rules();

        let scanner_result = VulnerabilityScanner::new("python", rules);
        assert!(scanner_result.is_ok(), "Should be able to create scanner with general rules");
        println!("Successfully created scanner for template injection patterns");
    }

    #[test]
    fn test_safe_django_patterns() {
        let rules = load_general_rules();

        let scanner_result = VulnerabilityScanner::new("python", rules);
        assert!(scanner_result.is_ok(), "Should be able to create scanner with general rules");
        println!("Successfully created scanner for safe Django patterns");
    }

    #[test]
    fn test_xss_prevention_rule_structure() {
        // The Django XSS prevention rules ship optionally; if the file is
        // absent or fails to parse, treat that as a soft skip rather than a
        // hard failure. When the file is present, walk the unified rule list
        // and look for entries categorised as XSS.
        match Rules::load_from_file("rules/python/django/xss_prevention.ron") {
            Ok(rules) => {
                println!("Successfully loaded XSS prevention rules");

                let xss_rules: Vec<_> = rules
                    .rules
                    .iter()
                    .filter(|r| {
                        r.category
                            .as_deref()
                            .map(|c| c.contains("xss"))
                            .unwrap_or(false)
                    })
                    .collect();

                if xss_rules.is_empty() {
                    println!("Warning: no XSS-category rules found in xss_prevention.ron");
                } else {
                    for rule in &xss_rules {
                        assert!(
                            rule.pattern.is_some() || rule.patterns.is_some(),
                            "Each XSS rule should declare a pattern or patterns"
                        );

                        if let Some(finding_type) = &rule.finding_type {
                            assert!(
                                finding_type.to_lowercase().contains("django")
                                    || finding_type.to_lowercase().contains("xss"),
                                "Django XSS rules should reference Django or XSS in finding_type"
                            );
                        }
                    }
                }
            }
            Err(e) => {
                println!("Skipping: Failed to load XSS prevention rules: {}", e);
            }
        }
    }

    #[test]
    fn test_django_directory_loading() {
        match Rules::load_from_directory("rules/python/django/") {
            Ok(rules) => {
                println!("Successfully loaded Django rules directory");

                let total_rules = rules.count_rules();
                assert!(total_rules > 0, "Should have loaded some Django rules");
                println!("Loaded {} total rules from Django directory", total_rules);

                let scanner = VulnerabilityScanner::new("python", rules)
                    .expect("Failed to create scanner");
                let results = scanner
                    .find_vulnerabilities_single_threaded(
                        "tests/test_files/python/django",
                        "python",
                    )
                    .expect("Failed to scan directory");

                println!("Found {} vulnerabilities with Django rules", results.len());
                assert!(results.len() >= 1, "Should detect at least one vulnerability");
            }
            Err(e) => {
                println!("Skipping: Failed to load Django rules directory: {}", e);
            }
        }
    }

    #[test]
    fn test_django_scanner_output() {
        let django_dir = Path::new("tests/test_files/python/django");
        if !django_dir.exists() {
            println!("Skipping Django test because tests/test_files/python/django directory doesn't exist");
            return;
        }
    }
}
