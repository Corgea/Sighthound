//! Tier 1: cross-file taint strictness — phantom flows, config safety, valid chains.

use super::helpers::*;

const CMD_TAINT_RULES: &str = "tests/strictness/fixtures/command_injection_taint.ron";

#[test]
#[cfg(feature = "python")]
fn phantom_flow_without_import_is_rejected() {
    let staging = stage_dir();

    stage_file(
        staging.path(),
        "tests/test_files/multi_file_taint_tests/category2_invalid/test2_1_module_a.py",
        "module_a.py",
        &[],
    );
    stage_file(
        staging.path(),
        "tests/test_files/multi_file_taint_tests/category2_invalid/test2_1_module_b.py",
        "module_b.py",
        &[],
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_no_cross_file_findings(&findings, "phantom flow (no import between modules)");
}

#[test]
#[cfg(feature = "python")]
fn safe_configuration_patterns_are_not_taint_sources() {
    let staging = stage_dir();

    stage_file(
        staging.path(),
        "tests/test_files/multi_file_taint_tests/category4_config/test4_1_config_manager.py",
        "config_manager.py",
        &[("test4_1_config_manager", "config_manager")],
    );
    stage_file(
        staging.path(),
        "tests/test_files/multi_file_taint_tests/category4_config/test4_1_app_initializer.py",
        "app_initializer.py",
        &[("test4_1_config_manager", "config_manager")],
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert!(
        findings.is_empty(),
        "os.environ.setdefault configuration should not produce taint findings, got {}: {:?}",
        findings.len(),
        findings
            .iter()
            .map(|f| (f.file.as_str(), f.line, f.finding_type.as_str()))
            .collect::<Vec<_>>()
    );
}

#[test]
#[cfg(feature = "python")]
fn user_controlled_environment_variable_is_detected() {
    let staging = stage_dir();

    stage_file(
        staging.path(),
        "tests/test_files/multi_file_taint_tests/category4_config/test4_2_env_reader.py",
        "env_reader.py",
        &[],
    );
    stage_file(
        staging.path(),
        "tests/test_files/multi_file_taint_tests/category4_config/test4_2_command_executor.py",
        "command_executor.py",
        &[("test4_2_env_reader", "env_reader")],
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_has_cross_file_finding_near(
        &findings,
        "command_executor.py",
        23,
        3,
        "user-controlled os.environ.get flow",
    );
}

#[test]
#[cfg(feature = "python")]
fn direct_import_cross_file_flow_is_detected() {
    let staging = stage_dir();

    stage_file(
        staging.path(),
        "tests/test_files/multi_file_taint_tests/category1_valid/test1_1_source_module.py",
        "source_module.py",
        &[],
    );
    stage_file(
        staging.path(),
        "tests/test_files/multi_file_taint_tests/category1_valid/test1_1_sink_module.py",
        "sink_module.py",
        &[("test1_1_source_module", "source_module")],
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_has_cross_file_finding_near(
        &findings,
        "sink_module.py",
        13,
        3,
        "input() -> os.system() via import",
    );
}

#[test]
#[cfg(feature = "python")]
fn three_file_taint_chain_is_detected() {
    let staging = stage_dir();
    let rewrite = &[
        ("test5_1_user_input", "user_input"),
        ("test5_1_data_processor", "data_processor"),
    ];

    stage_file(
        staging.path(),
        "tests/test_files/multi_file_taint_tests/category5_complex/test5_1_user_input.py",
        "user_input.py",
        rewrite,
    );
    stage_file(
        staging.path(),
        "tests/test_files/multi_file_taint_tests/category5_complex/test5_1_data_processor.py",
        "data_processor.py",
        rewrite,
    );
    stage_file(
        staging.path(),
        "tests/test_files/multi_file_taint_tests/category5_complex/test5_1_command_runner.py",
        "command_runner.py",
        rewrite,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_has_cross_file_finding_near(
        &findings,
        "command_runner.py",
        15,
        3,
        "three-file input -> processor -> os.system chain",
    );
}
