use sighthound::rules::Rules;
use sighthound::scanner::PreFilter;
use sighthound::UnifiedRule;
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
    fn file_with_nested_test_import_is_skipped() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("plugin.py");
        fs::write(&path, "def register_plugin():\n    import pytest\n    return pytest\n").unwrap();

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

    #[test]
    fn production_file_with_attestation_or_contest_import_is_scanned() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("auth_service.py");
        fs::write(
            &path,
            "from myapp.attestation import verify_attestation\nfrom contest_service import handle_contest\nfrom services.latest_events import get_latest\nfrom fastest_cache import cache\n\ndef login(req):\n    return verify_attestation(req)\n",
        )
        .unwrap();

        let filter = PreFilter::new(&empty_rules(), "python");
        assert!(filter.should_scan_file(path.to_str().unwrap()));
    }

    #[test]
    fn production_file_with_migrate_user_import_is_scanned() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("account_service.py");
        fs::write(
            &path,
            "from accounts.user_migration import user_migration_step\n\ndef run(user):\n    user_migration_step(user)\n",
        )
        .unwrap();

        let filter = PreFilter::new(&empty_rules(), "python");
        assert!(filter.should_scan_file(path.to_str().unwrap()));
    }

    #[test]
    fn file_with_testing_or_vitest_import_is_skipped() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("service.ts");
        fs::write(&path, "import { describe, it } from 'vitest';\n\ndescribe('test', () => {});\n")
            .unwrap();

        let filter = PreFilter::new(&empty_rules(), "typescript");
        assert!(!filter.should_scan_file(path.to_str().unwrap()));
    }

    #[test]
    fn django_migration_file_with_migrations_import_is_skipped() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("0001_initial.py");
        fs::write(
            &path,
            "from django.db import migrations, models\n\nclass Migration(migrations.Migration):\n    dependencies = []\n",
        )
        .unwrap();

        let filter = PreFilter::new(&empty_rules(), "python");
        assert!(!filter.should_scan_file(path.to_str().unwrap()));
    }
}
