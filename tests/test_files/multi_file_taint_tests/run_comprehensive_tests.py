#!/usr/bin/env python3
"""
Comprehensive Multi-File Taint Analysis Test Runner

This script executes the testing strategy defined in TAINT_TESTING_STRATEGY.md
and validates that our taint analysis fixes work correctly.
"""

import subprocess
import json
import time
import os
import tempfile
import shutil
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Any


@dataclass
class TestCase:
    name: str
    category: str
    files: List[str]
    expected_result: str  # "DETECT" or "REJECT"
    description: str


@dataclass
class TestResult:
    test_case: TestCase
    actual_result: str
    execution_time: float
    details: Dict[str, Any]
    is_correct: bool


class TaintTestSuite:
    def __init__(self):
        self.test_cases = self._define_test_cases()
        self.results = []

    def _define_test_cases(self) -> List[TestCase]:
        """Define all test cases according to the testing strategy"""
        return [
            # Category 1: Valid Cross-File Flows (Should DETECT)
            TestCase(
                name="test1_1_direct_import_flow",
                category="Category 1: Valid Flows",
                files=[
                    "category1_valid/test1_1_source_module.py",
                    "category1_valid/test1_1_sink_module.py",
                ],
                expected_result="DETECT",
                description="Direct function import flow: input() -> os.system()",
            ),
            # Category 2: Invalid Cross-File Flows (Should REJECT)
            TestCase(
                name="test2_1_phantom_no_import",
                category="Category 2: Phantom Flows",
                files=[
                    "category2_invalid/test2_1_module_a.py",
                    "category2_invalid/test2_1_module_b.py",
                ],
                expected_result="REJECT",
                description="No import relationship - should not create phantom flow",
            ),
            # Category 4: Configuration vs Vulnerability
            TestCase(
                name="test4_1_safe_config",
                category="Category 4: Configuration Safety",
                files=[
                    "category4_config/test4_1_config_manager.py",
                    "category4_config/test4_1_app_initializer.py",
                ],
                expected_result="REJECT",
                description="Configuration patterns should not be flagged",
            ),
            TestCase(
                name="test4_2_real_env_vuln",
                category="Category 4: Real Vulnerabilities",
                files=[
                    "category4_config/test4_2_env_reader.py",
                    "category4_config/test4_2_command_executor.py",
                ],
                expected_result="DETECT",
                description="Real environment variable vulnerability",
            ),
            # Category 5: Complex Multi-File Scenarios
            TestCase(
                name="test5_1_three_file_chain",
                category="Category 5: Complex Scenarios",
                files=[
                    "category5_complex/test5_1_user_input.py",
                    "category5_complex/test5_1_data_processor.py",
                    "category5_complex/test5_1_command_runner.py",
                ],
                expected_result="DETECT",
                description="Three-file chain: input() -> processor -> os.system()",
            ),
        ]

    def run_taint_analysis(self, test_files: List[str]) -> Dict[str, Any]:
        """Run taint analysis on test files and return results"""

        # Create a temporary directory for this specific test
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            test_dir = Path(__file__).parent

            # Copy only the specific test files to the temporary directory
            for test_file in test_files:
                source_file = test_dir / test_file

                # Create subdirectory structure in temp dir
                dest_file = temp_path / test_file
                dest_file.parent.mkdir(parents=True, exist_ok=True)

                # Copy the file
                shutil.copy2(source_file, dest_file)

            # Run taint analysis on the temporary directory
            cmd = [
                "cargo",
                "run",
                "--",
                str(
                    temp_path
                ),  # Root directory to scan (temp dir with only test files)
                "--taint-analysis",
            ]

            start_time = time.time()

            try:
                # Get the project root directory (where Cargo.toml is located)
                project_root = Path(__file__).parent.parent.parent

                result = subprocess.run(
                    cmd,
                    cwd=str(project_root),  # Run from project root
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

                execution_time = time.time() - start_time

                return {
                    "success": result.returncode == 0,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "execution_time": execution_time,
                    "return_code": result.returncode,
                }

            except subprocess.TimeoutExpired:
                return {
                    "success": False,
                    "stdout": "",
                    "stderr": "Timeout after 30 seconds",
                    "execution_time": 30.0,
                    "return_code": -1,
                }
            except Exception as e:
                return {
                    "success": False,
                    "stdout": "",
                    "stderr": f"Error: {str(e)}",
                    "execution_time": time.time() - start_time,
                    "return_code": -2,
                }

    def analyze_taint_result(self, output: str) -> str:
        """Analyze taint analysis output to determine DETECT or REJECT"""

        # Look for taint flow indicators in output
        taint_indicators = [
            "taint flow",
            "vulnerability found",
            "cross-file flow",
            "flows found:",
            "flows detected",
        ]

        output_lower = output.lower()

        # Check for explicit flow detection
        for indicator in taint_indicators:
            if indicator in output_lower:
                return "DETECT"

        # Check for flow count
        if "flows found: 0" in output_lower or "no flows" in output_lower:
            return "REJECT"

        # Look for specific vulnerability patterns
        if "command injection" in output_lower or "sql injection" in output_lower:
            return "DETECT"

        # Check for JSON output format
        try:
            if output.strip().startswith("{"):
                data = json.loads(output)
                if "flows" in data and len(data.get("flows", [])) > 0:
                    return "DETECT"
                else:
                    return "REJECT"
        except:
            pass

        # Default: if no clear indicators, assume REJECT
        return "REJECT"

    def run_single_test(self, test_case: TestCase) -> TestResult:
        """Run a single test case and return results"""

        print(f"\n🧪 Running {test_case.name}...")
        print(f"   📁 Files: {test_case.files}")
        print(f"   🎯 Expected: {test_case.expected_result}")

        # Run taint analysis
        analysis_result = self.run_taint_analysis(test_case.files)

        # Analyze results
        if analysis_result["success"] or analysis_result["return_code"] == 0:
            # Even if there are warnings in stderr, if return code is 0, analyze the output
            actual_result = self.analyze_taint_result(analysis_result["stdout"])
        else:
            actual_result = "ERROR"

        is_correct = actual_result == test_case.expected_result

        # Print immediate result
        status_emoji = "✅" if is_correct else "❌"
        print(f"   📊 Actual: {actual_result} {status_emoji}")

        if not is_correct and actual_result != "ERROR":
            print(
                f"   ⚠️  MISMATCH: Expected {test_case.expected_result}, got {actual_result}"
            )

        # Only show stderr if it's actually an error (not just warnings)
        if actual_result == "ERROR" and analysis_result.get("stderr"):
            print(f"   🚨 Error: {analysis_result['stderr'][:200]}...")

        return TestResult(
            test_case=test_case,
            actual_result=actual_result,
            execution_time=analysis_result["execution_time"],
            details=analysis_result,
            is_correct=is_correct,
        )

    def run_all_tests(self) -> List[TestResult]:
        """Run all test cases and return results"""

        print("🚀 Starting Comprehensive Multi-File Taint Analysis Test Suite")
        print("=" * 70)

        results = []

        for test_case in self.test_cases:
            result = self.run_single_test(test_case)
            results.append(result)
            self.results.append(result)

        return results

    def generate_report(self, results: List[TestResult]) -> Dict[str, Any]:
        """Generate comprehensive test report"""

        total_tests = len(results)
        passed_tests = sum(1 for r in results if r.is_correct)
        failed_tests = total_tests - passed_tests

        # Category breakdown
        category_stats = {}
        for result in results:
            category = result.test_case.category
            if category not in category_stats:
                category_stats[category] = {"total": 0, "passed": 0}
            category_stats[category]["total"] += 1
            if result.is_correct:
                category_stats[category]["passed"] += 1

        # Performance stats
        total_time = sum(r.execution_time for r in results)
        avg_time = total_time / total_tests if total_tests > 0 else 0

        # Critical failures
        critical_failures = []
        for result in results:
            if not result.is_correct:
                if "phantom" in result.test_case.name.lower():
                    critical_failures.append(
                        f"PHANTOM FLOW DETECTED: {result.test_case.name}"
                    )
                elif (
                    "config" in result.test_case.name.lower()
                    and result.test_case.expected_result == "REJECT"
                ):
                    critical_failures.append(
                        f"CONFIG FALSE POSITIVE: {result.test_case.name}"
                    )

        return {
            "summary": {
                "total_tests": total_tests,
                "passed_tests": passed_tests,
                "failed_tests": failed_tests,
                "success_rate": round((passed_tests / total_tests) * 100, 2)
                if total_tests > 0
                else 0,
            },
            "performance": {
                "total_time": round(total_time, 3),
                "average_time": round(avg_time, 3),
                "meets_performance_target": avg_time < 0.2,  # 200ms target
            },
            "category_breakdown": category_stats,
            "critical_failures": critical_failures,
            "detailed_results": [
                {
                    "name": r.test_case.name,
                    "category": r.test_case.category,
                    "expected": r.test_case.expected_result,
                    "actual": r.actual_result,
                    "correct": r.is_correct,
                    "time": round(r.execution_time, 3),
                    "description": r.test_case.description,
                }
                for r in results
            ],
        }

    def print_final_report(self, report: Dict[str, Any]):
        """Print comprehensive final report"""

        print("\n" + "=" * 70)
        print("📊 COMPREHENSIVE TAINT ANALYSIS TEST RESULTS")
        print("=" * 70)

        # Summary
        summary = report["summary"]
        print(f"\n🎯 OVERALL RESULTS:")
        print(f"   Total Tests: {summary['total_tests']}")
        print(f"   Passed: {summary['passed_tests']} ✅")
        print(f"   Failed: {summary['failed_tests']} ❌")
        print(f"   Success Rate: {summary['success_rate']}%")

        # Success criteria check
        meets_criteria = summary["success_rate"] >= 95
        criteria_emoji = "✅" if meets_criteria else "❌"
        print(f"   Meets Success Criteria (>95%): {criteria_emoji}")

        # Performance
        perf = report["performance"]
        print(f"\n⚡ PERFORMANCE:")
        print(f"   Total Time: {perf['total_time']}s")
        print(f"   Average Time: {perf['average_time']}s")
        perf_emoji = "✅" if perf["meets_performance_target"] else "❌"
        print(f"   Meets Performance Target (<200ms): {perf_emoji}")

        # Category breakdown
        print(f"\n📂 CATEGORY BREAKDOWN:")
        for category, stats in report["category_breakdown"].items():
            rate = round((stats["passed"] / stats["total"]) * 100, 2)
            print(f"   {category}: {stats['passed']}/{stats['total']} ({rate}%)")

        # Critical failures
        if report["critical_failures"]:
            print(f"\n🚨 CRITICAL FAILURES:")
            for failure in report["critical_failures"]:
                print(f"   ❌ {failure}")
        else:
            print(f"\n✅ NO CRITICAL FAILURES")

        # Detailed results
        print(f"\n📋 DETAILED RESULTS:")
        for result in report["detailed_results"]:
            status = "✅" if result["correct"] else "❌"
            print(
                f"   {status} {result['name']}: {result['expected']} -> {result['actual']} ({result['time']}s)"
            )

        # Final verdict
        print(f"\n" + "=" * 70)
        overall_success = (
            summary["success_rate"] >= 95
            and len(report["critical_failures"]) == 0
            and perf["meets_performance_target"]
        )

        if overall_success:
            print("🎉 COMPREHENSIVE TEST SUITE: ✅ PASSED")
            print("🚀 Taint analysis fixes are working correctly!")
        else:
            print("💥 COMPREHENSIVE TEST SUITE: ❌ FAILED")
            print("🔧 Taint analysis needs additional fixes.")

        print("=" * 70)


def main():
    """Main test execution"""
    suite = TaintTestSuite()
    results = suite.run_all_tests()
    report = suite.generate_report(results)
    suite.print_final_report(report)

    # Save detailed report
    report_file = Path(__file__).parent / "test_report.json"
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n📄 Detailed report saved to: {report_file}")


if __name__ == "__main__":
    main()
