use std::path::PathBuf;
use std::sync::OnceLock;

use sighthound::parser::LanguageParser;
use sighthound::rules::Rules;
use sighthound::VulnerabilityScanner;
use tree_sitter::{Node, Point, Range};

const URL_SOURCE_LINE: usize = 5;
const URL_SINK_LINE: usize = 9;
const REMOTE_SOURCE_LINE: usize = 17;
const REMOTE_SINK_LINE: usize = 25;
const OVERLAP_LINE: usize = 6;
const FALLBACK_LINE: usize = 11;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/test_files/html")
}

fn scan_html_fixtures() -> &'static [sighthound::Finding] {
    static FINDINGS: OnceLock<Vec<sighthound::Finding>> = OnceLock::new();
    FINDINGS.get_or_init(|| {
        let rules = Rules::load_embedded_rules("html", None).expect("HTML rules should load");
        let scanner = VulnerabilityScanner::new("html", rules).expect("scanner should initialize");
        scanner
            .find_vulnerabilities_unified_with_filters_and_options(
                fixture_dir().to_str().expect("UTF-8 fixture path"),
                "html",
                false,
                None,
                None,
                true,
            )
            .expect("fixture scan should succeed")
    })
}

fn collect_nodes_of_kind<'tree>(node: Node<'tree>, kind: &str, nodes: &mut Vec<Node<'tree>>) {
    if node.kind() == kind {
        nodes.push(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_nodes_of_kind(child, kind, nodes);
    }
}

#[test]
fn embedded_js_dom_xss_rules_load_once() {
    let html_rules = Rules::load_embedded_rules("html", None).expect("HTML rules should load");
    let taint_rules = html_rules.get_taint_rules();
    assert_eq!(taint_rules.len(), 1);
    assert_eq!(taint_rules[0].id.as_deref(), Some("js-dom-xss-taint-001"));

    let languages = vec!["html".to_string(), "javascript".to_string()];
    let mixed_rules =
        Rules::load_all_embedded_rules(&languages, None).expect("mixed rules should load");
    let canonical_count = mixed_rules
        .rules
        .iter()
        .filter(|rule| rule.id.as_deref() == Some("js-dom-xss-taint-001"))
        .count();
    assert_eq!(canonical_count, 1);
}

#[test]
fn embedded_js_dom_xss_reports_precise_url_and_remote_flows() {
    let findings = scan_html_fixtures();
    let precise = findings
        .iter()
        .filter(|finding| {
            finding.file.ends_with("embedded_dom_xss_vulnerable.html")
                && finding.cwe_id.as_deref() == Some("cwe-79")
                && finding.has_tag("taint_analysis")
        })
        .collect::<Vec<_>>();
    assert_eq!(precise.len(), 2, "expected URL and remote flows: {findings:#?}");

    let url_flow = precise
        .iter()
        .copied()
        .find(|finding| finding.line == URL_SINK_LINE)
        .expect("URL flow should use the literal sink line");
    let url_source = url_flow.source_info.as_ref().expect("URL source evidence");
    let url_sink = url_flow.sink_info.as_ref().expect("URL sink evidence");
    assert!(url_flow.file.ends_with("embedded_dom_xss_vulnerable.html"));
    assert!(url_source.location.ends_with(&format!(":{URL_SOURCE_LINE}")));
    assert!(url_sink.location.ends_with(&format!(":{URL_SINK_LINE}")));
    assert!(url_flow.has_tag("data_flow"));

    let remote_flow = precise
        .iter()
        .copied()
        .find(|finding| finding.line == REMOTE_SINK_LINE)
        .expect("remote flow should use the literal sink line");
    let remote_source = remote_flow.source_info.as_ref().expect("remote source evidence");
    let remote_sink = remote_flow.sink_info.as_ref().expect("remote sink evidence");
    assert_eq!(remote_source.source_type, "fetch(*).then");
    assert!(remote_source.location.ends_with(&format!(":{REMOTE_SOURCE_LINE}")));
    assert!(remote_source.context.contains("fetch("));
    assert!(remote_sink.location.ends_with(&format!(":{REMOTE_SINK_LINE}")));
    assert!(remote_source.location.contains("embedded_dom_xss_vulnerable.html"));
    assert!(remote_sink.location.contains("embedded_dom_xss_vulnerable.html"));
    assert!(remote_flow.has_tag("data_flow"));
}

#[test]
fn embedded_js_dom_xss_safe_boundaries_stay_clean() {
    let findings = scan_html_fixtures();
    let unsafe_findings = findings
        .iter()
        .filter(|finding| {
            finding.file.ends_with("embedded_dom_xss_safe.html")
                && (finding.has_tag("taint_analysis") || finding.has_tag("html-inline-dom-xss-001"))
        })
        .collect::<Vec<_>>();
    assert!(unsafe_findings.is_empty(), "safe boundaries produced findings: {unsafe_findings:#?}");
}

#[test]
fn embedded_js_dom_xss_search_only_filters_ineligible_scripts() {
    let rules = Rules::load_embedded_rules("html", None).expect("HTML rules should load");
    let scanner = VulnerabilityScanner::new("html", rules).expect("scanner should initialize");
    let findings = scanner
        .find_vulnerabilities_parallel_with_options(
            fixture_dir().to_str().expect("UTF-8 fixture path"),
            "html",
            false,
            true,
        )
        .expect("search-only scan should succeed");
    let unsafe_findings = findings
        .iter()
        .filter(|finding| {
            finding.file.ends_with("embedded_dom_xss_safe.html")
                && finding.has_tag("html-inline-dom-xss-001")
        })
        .collect::<Vec<_>>();
    assert!(
        unsafe_findings.is_empty(),
        "ineligible scripts produced fallbacks: {unsafe_findings:#?}"
    );
}

#[test]
fn embedded_js_dom_xss_prefers_taint_and_retains_unmatched_fallback() {
    let findings = scan_html_fixtures();
    let overlap = findings
        .iter()
        .filter(|finding| {
            finding.file.ends_with("embedded_dom_xss_fallback.html")
                && finding.line == OVERLAP_LINE
                && finding.cwe_id.as_deref() == Some("cwe-79")
        })
        .collect::<Vec<_>>();
    assert_eq!(overlap.len(), 1, "overlap should collapse to one finding: {findings:#?}");
    assert!(overlap[0].has_tag("taint_analysis"));
    assert!(overlap[0].source_info.is_some());
    assert!(overlap[0].sink_info.is_some());

    let fallback = findings
        .iter()
        .filter(|finding| {
            finding.file.ends_with("embedded_dom_xss_fallback.html")
                && finding.line == FALLBACK_LINE
                && finding.cwe_id.as_deref() == Some("cwe-79")
        })
        .collect::<Vec<_>>();
    assert_eq!(fallback.len(), 1, "unknown source should retain fallback: {findings:#?}");
    assert!(fallback[0].has_tag("html-inline-dom-xss-001"));
}

#[test]
fn embedded_js_dom_xss_ranged_parser_preserves_rows_and_resets() {
    let source = b"<html>\n<script>\nconst first = 1;\n</script>\n<script>\nconst second = 2;\n</script>\n</html>";
    let mut html_parser = LanguageParser::new("html").expect("HTML parser");
    let html_tree = html_parser.parse(source).expect("HTML parse");
    let mut raw_text_nodes = Vec::new();
    collect_nodes_of_kind(html_tree.root_node(), "raw_text", &mut raw_text_nodes);
    let ranges = raw_text_nodes.iter().map(Node::range).collect::<Vec<_>>();
    assert_eq!(ranges.len(), 2);

    let mut javascript_parser = LanguageParser::new("javascript").expect("JavaScript parser");
    let ranged_tree = javascript_parser
        .parse_with_included_ranges(source, &ranges)
        .expect("ranged JavaScript parse");
    let mut declarations = Vec::new();
    collect_nodes_of_kind(ranged_tree.root_node(), "lexical_declaration", &mut declarations);
    let rows = declarations.iter().map(|node| node.start_position().row).collect::<Vec<_>>();
    assert_eq!(rows, vec![2, 5]);

    let full_tree =
        javascript_parser.parse(b"const standalone = 1;").expect("full parse after range");
    assert_eq!(full_tree.root_node().start_position().row, 0);

    let invalid = Range {
        start_byte: 4,
        end_byte: 2,
        start_point: Point::new(0, 4),
        end_point: Point::new(0, 2),
    };
    assert!(javascript_parser.parse_with_included_ranges(b"const x = 1;", &[invalid]).is_err());
    let reset_tree = javascript_parser.parse(b"const reset = 1;").expect("full parse after error");
    assert_eq!(reset_tree.root_node().start_position().row, 0);
}
