#!/usr/bin/env python3
"""Multi-file taint benchmark for strictness regressions."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[3]
FIXTURE_ROOT = Path(__file__).resolve().parent
RULES_PATH = "tests/strictness/fixtures/command_injection_taint.ron"


@dataclass(frozen=True)
class TestCase:
    name: str
    category: str
    files: list[tuple[str, str]]
    replacements: list[tuple[str, str]]
    expected_result: str
    description: str


@dataclass(frozen=True)
class TestResult:
    test_case: TestCase
    actual_result: str
    execution_time: float
    findings: list[dict[str, Any]]
    is_correct: bool


def test_cases() -> list[TestCase]:
    return [
        TestCase(
            name="test1_1_direct_import_flow",
            category="valid_flows",
            files=[
                ("category1_valid/test1_1_source_module.py", "source_module.py"),
                ("category1_valid/test1_1_sink_module.py", "sink_module.py"),
            ],
            replacements=[("test1_1_source_module", "source_module")],
            expected_result="DETECT",
            description="Direct function import flow: input() -> os.system()",
        ),
        TestCase(
            name="test2_1_phantom_no_import",
            category="phantom_flows",
            files=[
                ("category2_invalid/test2_1_module_a.py", "module_a.py"),
                ("category2_invalid/test2_1_module_b.py", "module_b.py"),
            ],
            replacements=[],
            expected_result="REJECT",
            description="No import relationship should not create a phantom flow",
        ),
        TestCase(
            name="test4_1_safe_config",
            category="configuration_safety",
            files=[
                ("category4_config/test4_1_config_manager.py", "config_manager.py"),
                ("category4_config/test4_1_app_initializer.py", "app_initializer.py"),
            ],
            replacements=[("test4_1_config_manager", "config_manager")],
            expected_result="REJECT",
            description="Configuration defaults should not be taint sources",
        ),
        TestCase(
            name="test4_2_real_env_vuln",
            category="real_environment_vulnerabilities",
            files=[
                ("category4_config/test4_2_env_reader.py", "env_reader.py"),
                ("category4_config/test4_2_command_executor.py", "command_executor.py"),
            ],
            replacements=[("test4_2_env_reader", "env_reader")],
            expected_result="DETECT",
            description="User-controlled environment variable reaches command sink",
        ),
        TestCase(
            name="test5_1_three_file_chain",
            category="complex_chains",
            files=[
                ("category5_complex/test5_1_user_input.py", "user_input.py"),
                ("category5_complex/test5_1_data_processor.py", "data_processor.py"),
                ("category5_complex/test5_1_command_runner.py", "command_runner.py"),
            ],
            replacements=[
                ("test5_1_user_input", "user_input"),
                ("test5_1_data_processor", "data_processor"),
            ],
            expected_result="DETECT",
            description="Three-file input -> processor -> os.system chain",
        ),
    ]


def stage_case(case: TestCase, temp_dir: Path) -> None:
    for source_rel, dest_name in case.files:
        content = (FIXTURE_ROOT / source_rel).read_text()
        for old, new in case.replacements:
            content = content.replace(old, new)
        (temp_dir / dest_name).write_text(content)


def parse_findings(output: str) -> list[dict[str, Any]]:
    output = output.strip()
    if not output:
        return []
    parsed = json.loads(output)
    if not isinstance(parsed, list):
        raise ValueError("expected scanner JSON output to be a list of findings")
    return parsed


def run_case(case: TestCase) -> TestResult:
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        stage_case(case, temp_path)

        cmd = [
            "cargo",
            "run",
            "--quiet",
            "--",
            str(temp_path),
            "python",
            RULES_PATH,
            "--use-file-rules",
            "--taint-analysis",
            "--output-format",
            "json",
        ]

        start = time.time()
        result = subprocess.run(
            cmd,
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        elapsed = time.time() - start

        if result.returncode != 0:
            raise RuntimeError(
                f"{case.name} scanner failed with {result.returncode}: {result.stderr}"
            )

        findings = parse_findings(result.stdout)
        taint_findings = [
            finding
            for finding in findings
            if "taint_analysis" in finding.get("tags", [])
        ]
        actual = "DETECT" if taint_findings else "REJECT"

        return TestResult(
            test_case=case,
            actual_result=actual,
            execution_time=elapsed,
            findings=taint_findings,
            is_correct=actual == case.expected_result,
        )


def main() -> int:
    results = [run_case(case) for case in test_cases()]

    passed = sum(1 for result in results if result.is_correct)
    failed = len(results) - passed
    total_time = sum(result.execution_time for result in results)

    print("Multi-file taint benchmark")
    print("=" * 40)
    for result in results:
        status = "PASS" if result.is_correct else "FAIL"
        print(
            f"{status} {result.test_case.name}: "
            f"expected={result.test_case.expected_result} "
            f"actual={result.actual_result} "
            f"findings={len(result.findings)} "
            f"time={result.execution_time:.3f}s"
        )
        if not result.is_correct:
            for finding in result.findings[:5]:
                print(
                    "  "
                    f"{Path(finding.get('file', '')).name}:"
                    f"{finding.get('line')} "
                    f"{finding.get('finding_type')}"
                )

    print("=" * 40)
    print(f"Passed: {passed}/{len(results)}")
    print(f"Average time: {round(total_time / len(results), 3)}s")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
