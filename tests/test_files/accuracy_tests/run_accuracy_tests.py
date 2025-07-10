#!/usr/bin/env python3
"""
Accuracy Test Runner - Comprehensive analysis of taint analysis accuracy
"""

import subprocess
import json
import os
import sys
from typing import Dict, List, Set, Tuple


class AccuracyTestRunner:
    def __init__(self):
        self.test_results = {}
        self.expected_detections = {}
        self.setup_expected_results()

    def setup_expected_results(self):
        """Define expected detection results for each test case"""

        # TRUE POSITIVES: Should detect these vulnerabilities
        self.expected_detections["true_positives"] = {
            "should_detect": {
                "sink.py": [
                    "vulnerable_eval",  # TP1: Cross-file eval
                    "vulnerable_exec",  # TP2: Cross-file exec
                    "vulnerable_system",  # TP3: Cross-file system
                    "vulnerable_compile",  # TP4: Cross-file compile
                    "vulnerable_chain",  # TP5: Chained cross-file
                    "vulnerable_processed",  # TP6: Processed cross-file
                    "vulnerable_multiple",  # TP7: Multiple sources
                    "vulnerable_assignment",  # TP8: Local assignment with cross-file
                ]
            },
            "should_not_detect": {},
        }

        # TRUE NEGATIVES: Should NOT detect these (safe code)
        self.expected_detections["true_negatives"] = {
            "should_detect": {},
            "should_not_detect": {
                "safe_sink.py": [
                    "safe_eval_constant",  # TN1: Safe constant
                    "safe_exec_computed",  # TN2: Safe computed
                    "safe_system_version",  # TN3: Safe version
                    "safe_compile_version",  # TN4: Safe Python version
                    "safe_eval_hash",  # TN5: Safe hash
                    "safe_template_usage",  # TN6: Safe template
                    "safe_app_config",  # TN7: Safe app config
                    "safe_validated",  # TN8: Safe validated
                    "safe_literals",  # TN9: Safe literals
                    "safe_no_input",  # TN10: No user input
                ]
            },
        }

        # EDGE CASES: Complex scenarios
        self.expected_detections["edge_cases"] = {
            "should_detect": {
                "tricky_sink.py": [
                    "test_variable_scope",  # EC1: Tainted user_data
                    "test_conditional",  # EC2: Conditional taint
                    "test_nested",  # EC3: Nested taint
                    "test_multi_return",  # EC4: Multi return paths
                    "test_reassignment",  # EC5: Reassigned tainted
                    "test_mixed",  # EC6: Mixed data
                    "test_aliasing",  # EC8: Aliased taint
                    "test_assignment_chain",  # EC12: Assignment chain
                ]
            },
            "should_not_detect": {
                "tricky_sink.py": [
                    "test_comments",  # EC7: Comments shouldn't confuse
                    "test_false_positive",  # EC9: No actual connection
                    "test_string_literals",  # EC10: String literals
                    "test_name_confusion",  # EC11: Variable name confusion
                ]
            },
        }

        # CROSS-FILE: Complex multi-file scenarios
        self.expected_detections["cross_file"] = {
            "should_detect": {
                "module_c.py": [
                    "test_direct_a_to_c",  # CF-C1: Direct A->C
                    "test_a_to_b_to_c",  # CF-C2: A->B->C
                    "test_combined_sources",  # CF-C3: Combined sources
                    "test_class_taint",  # CF-C4: Class-based
                    "test_mixed_flow",  # CF-C6: Mixed safe/tainted
                    "test_local_b_taint",  # CF-C7: Local B taint
                    "test_complex_chain",  # CF-C8: Complex chain
                    "test_class_instance",  # CF-C9: Class instance
                    "test_multiple_hops",  # CF-C10: Multiple hops
                    "test_subprocess_taint",  # CF-C14: Subprocess
                    "test_multi_import",  # CF-C15: Multi-import
                ]
            },
            "should_not_detect": {
                "module_c.py": [
                    "test_safe_flow",  # CF-C5: Safe data flow
                    "test_safe_direct",  # CF-C11: Safe direct from A
                    "test_false_positive",  # CF-C12: No connection
                    "test_string_literals",  # CF-C13: String literals
                ]
            },
        }

    def run_test_suite(self, test_dir: str) -> Dict:
        """Run taint analysis on a test directory"""
        print(f"\n🧪 Running accuracy tests on: {test_dir}")

        cmd = [
            "cargo",
            "run",
            "--",
            "--taint-analysis",
            "--output-format",
            "json",
            f"tests/test_files/accuracy_tests/{test_dir}",
            "python",
            "rules/python/general_security.ron",
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, cwd="../..")
            if result.returncode != 0:
                print(f"❌ Error running test: {result.stderr}")
                return {"vulnerabilities": []}

            # Parse JSON output - find the JSON structure
            output = result.stdout.strip()

            # Look for the JSON structure (starts with { and contains flows)
            json_start = output.find("{")
            if json_start != -1:
                json_content = output[json_start:]
                # Clean up any trailing non-JSON content
                json_end = json_content.rfind("}")
                if json_end != -1:
                    json_line = json_content[: json_end + 1]
                else:
                    json_line = None
            else:
                json_line = None

            if json_line:
                return json.loads(json_line)
            else:
                print(f"❌ No JSON output found")
                return {"flows": []}

        except Exception as e:
            print(f"❌ Exception running test: {e}")
            return {"flows": []}

    def analyze_results(self, test_category: str, results: Dict) -> Dict:
        """Analyze test results for accuracy"""
        print(f"\n📊 Analyzing {test_category} results...")

        expected = self.expected_detections.get(test_category, {})
        should_detect = expected.get("should_detect", {})
        should_not_detect = expected.get("should_not_detect", {})

        # Extract detected vulnerabilities
        detected_vulns = set()
        flows = results.get("flows", [])

        for flow in flows:
            # Extract sink information from taint flow
            if "sink" in flow:
                sink = flow["sink"]
                sink_file = os.path.basename(sink.get("file", ""))
                sink_function = sink.get("function", "")
                detected_vulns.add(f"{sink_file}:{sink_function}")

        print(f"   Detected {len(detected_vulns)} total vulnerabilities")

        # Analyze true positives
        true_positives = 0
        false_negatives = 0

        for file, functions in should_detect.items():
            for func in functions:
                detection_key = f"{file}:{func}"
                if any(detection_key in str(vuln) for vuln in detected_vulns):
                    true_positives += 1
                    print(f"   ✅ Correctly detected: {func} in {file}")
                else:
                    false_negatives += 1
                    print(f"   ❌ MISSED (False Negative): {func} in {file}")

        # Analyze true negatives
        true_negatives = 0
        false_positives = 0

        for file, functions in should_not_detect.items():
            for func in functions:
                detection_key = f"{file}:{func}"
                if any(detection_key in str(vuln) for vuln in detected_vulns):
                    false_positives += 1
                    print(
                        f"   ❌ INCORRECTLY detected (False Positive): {func} in {file}"
                    )
                else:
                    true_negatives += 1
                    print(f"   ✅ Correctly ignored: {func} in {file}")

        return {
            "true_positives": true_positives,
            "false_negatives": false_negatives,
            "true_negatives": true_negatives,
            "false_positives": false_positives,
            "total_detected": len(detected_vulns),
        }

    def calculate_metrics(self, analysis: Dict) -> Dict:
        """Calculate accuracy metrics"""
        tp = analysis["true_positives"]
        fp = analysis["false_positives"]
        tn = analysis["true_negatives"]
        fn = analysis["false_negatives"]

        # Precision = TP / (TP + FP)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0

        # Recall = TP / (TP + FN)
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0

        # F1 Score = 2 * (precision * recall) / (precision + recall)
        f1_score = (
            2 * (precision * recall) / (precision + recall)
            if (precision + recall) > 0
            else 0
        )

        # Accuracy = (TP + TN) / (TP + TN + FP + FN)
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0

        return {
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "accuracy": accuracy,
        }

    def run_comprehensive_tests(self):
        """Run all accuracy tests and generate comprehensive report"""
        print("🚀 Starting Comprehensive Taint Analysis Accuracy Tests")
        print("=" * 60)

        test_categories = [
            ("true_positives", "True Positives (Real Vulnerabilities)"),
            ("true_negatives", "True Negatives (Safe Code)"),
            ("edge_cases", "Edge Cases (Complex Scenarios)"),
            ("cross_file", "Cross-File (Multi-Module Flows)"),
        ]

        overall_results = {
            "true_positives": 0,
            "false_negatives": 0,
            "true_negatives": 0,
            "false_positives": 0,
        }

        for test_dir, description in test_categories:
            print(f"\n{'=' * 20} {description} {'=' * 20}")

            # Run tests
            results = self.run_test_suite(test_dir)

            # Analyze results
            analysis = self.analyze_results(test_dir, results)

            # Calculate metrics
            metrics = self.calculate_metrics(analysis)

            # Print metrics
            print(f"\n📈 {test_dir.upper()} METRICS:")
            print(f"   Precision: {metrics['precision']:.2%}")
            print(f"   Recall:    {metrics['recall']:.2%}")
            print(f"   F1 Score:  {metrics['f1_score']:.2%}")
            print(f"   Accuracy:  {metrics['accuracy']:.2%}")

            # Add to overall results
            for key in overall_results:
                overall_results[key] += analysis[key]

        # Calculate overall metrics
        print(f"\n{'=' * 60}")
        print("🎯 OVERALL ACCURACY RESULTS")
        print(f"{'=' * 60}")

        overall_metrics = self.calculate_metrics(overall_results)

        print(f"True Positives:   {overall_results['true_positives']}")
        print(f"False Negatives:  {overall_results['false_negatives']}")
        print(f"True Negatives:   {overall_results['true_negatives']}")
        print(f"False Positives:  {overall_results['false_positives']}")
        print()
        print(f"Overall Precision: {overall_metrics['precision']:.2%}")
        print(f"Overall Recall:    {overall_metrics['recall']:.2%}")
        print(f"Overall F1 Score:  {overall_metrics['f1_score']:.2%}")
        print(f"Overall Accuracy:  {overall_metrics['accuracy']:.2%}")

        # Quality assessment
        print(f"\n🏆 QUALITY ASSESSMENT:")
        if overall_metrics["precision"] >= 0.9:
            print("✅ EXCELLENT precision - Very low false positive rate")
        elif overall_metrics["precision"] >= 0.8:
            print("✅ GOOD precision - Acceptable false positive rate")
        else:
            print("❌ POOR precision - High false positive rate")

        if overall_metrics["recall"] >= 0.9:
            print("✅ EXCELLENT recall - Very low false negative rate")
        elif overall_metrics["recall"] >= 0.8:
            print("✅ GOOD recall - Acceptable false negative rate")
        else:
            print("❌ POOR recall - High false negative rate")

        return overall_results, overall_metrics


if __name__ == "__main__":
    # Change to script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)

    runner = AccuracyTestRunner()
    results, metrics = runner.run_comprehensive_tests()

    print(f"\n🎉 Accuracy testing complete!")
    print(f"Overall Score: {metrics['f1_score']:.1%} F1")
