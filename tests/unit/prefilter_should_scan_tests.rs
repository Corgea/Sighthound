use sighthound::UnifiedRule;
use sighthound::rules::Rules;
use sighthound::scanner::PreFilter;
use std::fs;
use tempfile::TempDir;

#[cfg(test)]
mod prefilter_should_scan_tests {
    use super::*;

    fn empty_rules() -> Rules {
        Rules { rules: Vec::new() }
    }

    fn malware_rules() -> Rules {
        Rules {
            rules: vec![UnifiedRule {
                id: None,
                name: Some("Malware Backdoor Detector".to_string()),
                description: None,
                category: None,
                mode: "search".to_string(),
                pattern: None,
                patterns: None,
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
            }],
        }
    }

    #[test]
    fn empty_file_is_skipped() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("empty.py");
        fs::write(&path, "").unwrap();

        let filter = PreFilter::new(&empty_rules(), "python");
        assert!(!filter.should_scan_file(path.to_str().unwrap()));
    }

    #[test]
    fn malicious_scan_mode_scans_everything_else() {
        let dir = TempDir::new().unwrap();
        // A doc file that would normally be skipped outside malicious-scan mode.
        let path = dir.path().join("README.md");
        fs::write(&path, "just some documentation text").unwrap();

        let filter = PreFilter::new(&malware_rules(), "python");
        assert!(filter.is_malicious_scan());
        assert!(filter.should_scan_file(path.to_str().unwrap()));
    }

    #[test]
    fn doc_file_is_skipped_outside_malicious_scan() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("README.md");
        fs::write(&path, "just some documentation text").unwrap();

        let filter = PreFilter::new(&empty_rules(), "python");
        assert!(!filter.should_scan_file(path.to_str().unwrap()));
    }

    #[test]
    fn minified_js_file_is_skipped_when_enabled() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("app.min.js");
        fs::write(&path, "console.log('hi');").unwrap();

        let filter = PreFilter::with_options(&empty_rules(), "javascript", true, Vec::new());
        assert!(!filter.should_scan_file(path.to_str().unwrap()));
    }

    #[test]
    fn test_file_with_test_imports_is_skipped() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test_something.py");
        fs::write(&path, "import pytest\n\ndef test_ok():\n    assert True\n").unwrap();

        let filter = PreFilter::new(&empty_rules(), "python");
        assert!(!filter.should_scan_file(path.to_str().unwrap()));
    }

    #[test]
    fn ordinary_source_file_is_scanned() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("app.py");
        fs::write(&path, "def handler(request):\n    return request.args.get('x')\n").unwrap();

        let filter = PreFilter::new(&empty_rules(), "python");
        assert!(filter.should_scan_file(path.to_str().unwrap()));
    }
}
