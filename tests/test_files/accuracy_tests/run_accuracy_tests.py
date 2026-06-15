#!/usr/bin/env python3
"""Accuracy benchmark for taint analysis strictness."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[3]
FIXTURE_ROOT = Path(__file__).resolve().parent
RULES_PATH = "tests/strictness/fixtures/accuracy_taint.ron"

REPLACEMENTS: dict[str, list[tuple[str, str]]] = {
    "edge_cases": [("get_comment_test", "get_comment_case")],
}


EXPECTED: dict[str, dict[str, dict[str, list[str]]]] = {
    "true_positives": {
        "should_detect": {
            "sink.py": [
                "vulnerable_eval",
                "vulnerable_exec",
                "vulnerable_system",
                "vulnerable_compile",
                "vulnerable_chain",
                "vulnerable_processed",
                "vulnerable_multiple",
                "vulnerable_assignment",
            ]
        },
        "should_not_detect": {},
    },
    "true_negatives": {
        "should_detect": {},
        "should_not_detect": {
            "safe_sink.py": [
                "safe_eval_constant",
                "safe_exec_computed",
                "safe_system_version",
                "safe_compile_version",
                "safe_eval_hash",
                "safe_template_usage",
                "safe_app_config",
                "safe_validated",
                "safe_literals",
                "safe_no_input",
            ]
        },
    },
    "edge_cases": {
        "should_detect": {
            "tricky_sink.py": [
                "test_variable_scope",
                "test_conditional",
                "test_nested",
                "test_multi_return",
                "test_reassignment",
                "test_mixed",
                "test_aliasing",
                "test_assignment_chain",
            ]
        },
        "should_not_detect": {
            "tricky_sink.py": [
                "test_comments",
                "test_false_positive",
                "test_string_literals",
                "test_name_confusion",
            ]
        },
    },
    "cross_file": {
        "should_detect": {
            "module_c.py": [
                "test_direct_a_to_c",
                "test_a_to_b_to_c",
                "test_combined_sources",
                "test_class_taint",
                "test_mixed_flow",
                "test_local_b_taint",
                "test_complex_chain",
                "test_class_instance",
                "test_multiple_hops",
                "test_subprocess_taint",
                "test_multi_import",
            ]
        },
        "should_not_detect": {
            "module_c.py": [
                "test_safe_flow",
                "test_safe_direct",
                "test_false_positive",
                "test_string_literals",
            ]
        },
    },
}


def parse_functions(file_path: Path) -> list[tuple[int, str]]:
    functions: list[tuple[int, str]] = []
    for line_number, line in enumerate(file_path.read_text().splitlines(), start=1):
        match = re.match(r"\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", line)
        if match:
            functions.append((line_number, match.group(1)))
    return functions


def function_for_line(functions: list[tuple[int, str]], line: int) -> str | None:
    current: str | None = None
    for function_line, name in functions:
        if function_line <= line:
            current = name
        else:
            break
    return current


def stage_category(category: str, temp_path: Path) -> dict[str, list[tuple[int, str]]]:
    function_maps: dict[str, list[tuple[int, str]]] = {}
    replacements = REPLACEMENTS.get(category, [])
    for source in (FIXTURE_ROOT / category).glob("*.py"):
        dest = temp_path / source.name
        content = source.read_text()
        for old, new in replacements:
            content = content.replace(old, new)
        dest.write_text(content)
        function_maps[source.name] = parse_functions(dest)
    return function_maps


def parse_findings(output: str) -> list[dict[str, Any]]:
    output = output.strip()
    if not output:
        return []
    parsed = json.loads(output)
    if not isinstance(parsed, list):
        raise ValueError("expected scanner JSON output to be a list of findings")
    return parsed


def run_category(category: str) -> tuple[set[str], float]:
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        function_maps = stage_category(category, temp_path)
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
            timeout=45,
        )
        elapsed = time.time() - start

        if result.returncode != 0:
            raise RuntimeError(
                f"{category} scanner failed with {result.returncode}: {result.stderr}"
            )

        detected: set[str] = set()
        for finding in parse_findings(result.stdout):
            if "taint_analysis" not in finding.get("tags", []):
                continue
            file_name = Path(finding.get("file", "")).name
            line = int(finding.get("line", 0))
            function = function_for_line(function_maps.get(file_name, []), line)
            if function:
                detected.add(f"{file_name}:{function}")
        return detected, elapsed


def analyze_category(category: str) -> dict[str, int | float]:
    expected = EXPECTED[category]
    detected, elapsed = run_category(category)

    tp = fp = tn = fn = 0
    print(f"\n{category}")
    print("-" * len(category))

    for file_name, functions in expected["should_detect"].items():
        for function in functions:
            key = f"{file_name}:{function}"
            if key in detected:
                tp += 1
                print(f"PASS detect {key}")
            else:
                fn += 1
                print(f"FAIL missed {key}")

    for file_name, functions in expected["should_not_detect"].items():
        for function in functions:
            key = f"{file_name}:{function}"
            if key in detected:
                fp += 1
                print(f"FAIL false-positive {key}")
            else:
                tn += 1
                print(f"PASS ignore {key}")

    expected_keys = {
        f"{file_name}:{function}"
        for bucket in ("should_detect", "should_not_detect")
        for file_name, functions in expected[bucket].items()
        for function in functions
    }
    extra = detected - expected_keys
    for key in sorted(extra):
        fp += 1
        print(f"FAIL unexpected {key}")

    return {
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "elapsed": elapsed,
        "detected": len(detected),
    }


def ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def main() -> int:
    totals = {
        "true_positives": 0,
        "false_positives": 0,
        "true_negatives": 0,
        "false_negatives": 0,
    }
    category_results: dict[str, dict[str, int | float]] = {}

    for category in EXPECTED:
        result = analyze_category(category)
        category_results[category] = result
        for key in totals:
            totals[key] += int(result[key])

    precision = ratio(
        totals["true_positives"],
        totals["true_positives"] + totals["false_positives"],
    )
    recall = ratio(
        totals["true_positives"],
        totals["true_positives"] + totals["false_negatives"],
    )
    f1 = ratio(2 * precision * recall, precision + recall)
    accuracy = ratio(
        totals["true_positives"] + totals["true_negatives"],
        sum(totals.values()),
    )

    print("\nAccuracy benchmark summary")
    print("=" * 40)
    print(f"True positives:  {totals['true_positives']}")
    print(f"False positives: {totals['false_positives']}")
    print(f"True negatives:  {totals['true_negatives']}")
    print(f"False negatives: {totals['false_negatives']}")
    print(f"Precision:       {precision:.2%}")
    print(f"Recall:          {recall:.2%}")
    print(f"F1:              {f1:.2%}")
    print(f"Accuracy:        {accuracy:.2%}")

    failed = totals["false_positives"] + totals["false_negatives"]
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
