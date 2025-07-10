#!/usr/bin/env python3
"""
Comprehensive taint analysis test file to understand current behavior
"""

import os
import sys
import subprocess


def test_direct_variable_usage():
    """Test 1: Direct variable usage - should work"""
    user_input = os.environ.get("USER_DATA")
    eval(user_input)  # Direct usage


def test_f_string_formatting():
    """Test 2: F-string formatting - currently fails"""
    user_input = os.environ.get("USER_DATA")
    eval(f"print({user_input})")  # F-string


def test_string_format_method():
    """Test 3: String format method - currently fails"""
    user_input = os.environ.get("USER_DATA")
    eval("print({})".format(user_input))  # Format method


def test_string_concatenation():
    """Test 4: String concatenation - currently fails"""
    user_input = os.environ.get("USER_DATA")
    eval("print(" + user_input + ")")  # Concatenation


def test_percent_formatting():
    """Test 5: Percent formatting - currently fails"""
    user_input = os.environ.get("USER_DATA")
    eval("print(%s)" % user_input)  # Percent formatting


def test_multiple_variables():
    """Test 6: Multiple variables in one sink"""
    user_input = os.environ.get("USER_DATA")
    db_config = os.environ.get("DB_CONFIG")
    eval(user_input)  # Should work
    eval(db_config)  # Should work


def test_nested_function_calls():
    """Test 7: Nested function calls"""

    def get_tainted_data():
        return os.environ.get("USER_DATA")

    user_input = get_tainted_data()
    eval(user_input)  # Should work


def test_class_methods():
    """Test 8: Class methods"""

    class DataProvider:
        def get_data(self):
            return os.environ.get("USER_DATA")

    provider = DataProvider()
    user_input = provider.get_data()
    eval(user_input)  # Should work


def test_different_sink_types():
    """Test 9: Different sink types"""
    user_input = os.environ.get("USER_DATA")

    # Different sinks
    eval(user_input)  # eval
    exec(user_input)  # exec
    os.system(user_input)  # os.system
    subprocess.call(user_input, shell=True)  # subprocess.call


def test_command_line_args():
    """Test 10: Command line arguments"""
    if len(sys.argv) > 1:
        user_input = sys.argv[1]
        eval(user_input)  # Should work


def test_input_function():
    """Test 11: Input function"""
    # user_input = input("Enter data: ")  # Commented out to avoid blocking
    user_input = "test_input"  # Simulated input
    eval(user_input)  # Should work


def test_safe_vs_unsafe():
    """Test 12: Safe vs unsafe patterns"""
    # Unsafe - should be detected
    user_input = os.environ.get("USER_DATA")
    eval(user_input)

    # Safe - should NOT be detected
    safe_data = "print('hello')"
    eval(safe_data)


def test_complex_expressions():
    """Test 13: Complex expressions"""
    user_input = os.environ.get("USER_DATA")

    # Complex but direct usage
    result = eval(user_input + " + 1")  # Should work
    result = eval(user_input.strip())  # Should work

    # Complex with formatting
    result = eval(f"process({user_input})")  # Should fail


def test_import_statements():
    """Test 14: Import statements"""
    module_name = os.environ.get("MODULE_NAME")
    __import__(module_name)  # Should work


def test_file_operations():
    """Test 15: File operations"""
    filename = os.environ.get("FILENAME")
    with open(filename, "r") as f:  # Should work
        pass


def test_sql_operations():
    """Test 16: SQL operations"""
    import sqlite3

    user_input = os.environ.get("USER_DATA")

    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")  # Should fail


if __name__ == "__main__":
    # Run all tests
    test_direct_variable_usage()
    test_f_string_formatting()
    test_string_format_method()
    test_string_concatenation()
    test_percent_formatting()
    test_multiple_variables()
    test_nested_function_calls()
    test_class_methods()
    test_different_sink_types()
    test_command_line_args()
    test_input_function()
    test_safe_vs_unsafe()
    test_complex_expressions()
    test_import_statements()
    test_file_operations()
    test_sql_operations()
