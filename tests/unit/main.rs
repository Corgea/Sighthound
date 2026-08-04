// Unit tests for the vulnerability scanner
#![allow(clippy::module_inception)]
mod ast_conditions_tests;
mod directory_loading_tests;
mod django_xss_prevention_tests;
mod embedded_js_dom_xss_tests;
mod exclusion_patterns_tests;
mod file_pattern_tests;
mod injection_pattern_tests;
mod javascript_ron_parser_tests;
mod javascript_rules_tests;
mod language_support_tests;
mod pattern_matching_tests;
mod prefilter_should_scan_tests;
mod rule_deserialization_tests;
mod semantic_variables_tests;
