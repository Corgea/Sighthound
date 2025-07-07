#!/usr/bin/env python3
"""
Comprehensive test file for unified rules - edge cases and combinations
"""

import os
import sqlite3
import hashlib
import subprocess
import shlex
from flask import Flask, request
from Crypto.Hash import MD5, SHA1
from Crypto.Cipher import DES, ARC4

app = Flask(__name__)

# ============================
# SEARCH MODE TESTS
# ============================


def test_all_weak_crypto_patterns():
    """Test all weak cryptography patterns that should be detected"""

    # Hashlib weak algorithms
    md5_1 = hashlib.md5(b"test")
    md5_2 = hashlib.md5("test".encode())
    sha1_1 = hashlib.sha1(b"test")
    sha1_2 = hashlib.sha1("test".encode())

    # Crypto library weak algorithms
    md5_crypto = MD5.new()
    sha1_crypto = SHA1.new()

    # Weak ciphers
    des_cipher = DES.new(b"12345678", DES.MODE_ECB)
    arc4_cipher = ARC4.new(b"secret")

    return "All weak crypto patterns tested"


def test_sql_execution_patterns():
    """Test SQL execution patterns that should be detected"""

    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()

    # Various execute patterns
    cursor.execute("SELECT 1")
    cursor.executemany("INSERT INTO test VALUES (?)", [(1,)])
    cursor.executescript("CREATE TABLE test (id INTEGER)")

    # Connection execute
    conn.execute("SELECT 2")
    conn.executemany("INSERT INTO test VALUES (?)", [(2,)])

    return "All SQL execution patterns tested"


# ============================
# TAINT ANALYSIS TESTS
# ============================


def test_all_source_patterns():
    """Test all taint source patterns"""

    # Request sources
    arg_data = request.args.get("data")
    form_data = request.form.get("data")
    json_data = request.json.get("data")

    # Input source
    user_input = input("Enter data: ")

    # Environment source
    env_data = os.environ.get("DATA")

    return [arg_data, form_data, json_data, user_input, env_data]


def test_all_sink_patterns():
    """Test all taint sink patterns"""
    data = "test_data"

    # Command execution sinks
    os.system(data)
    subprocess.call(data, shell=True)
    subprocess.run(data, shell=True)

    # Code execution sinks
    eval(data)
    exec(data)

    # File operation sinks
    filepath = os.path.join("/tmp", data)
    with open(filepath, "w") as f:
        f.write("test")

    return "All sink patterns tested"


def test_complex_taint_flows():
    """Test complex taint propagation scenarios"""

    # Multi-source flow
    source1 = request.args.get("cmd1")
    source2 = request.form.get("cmd2")

    # Complex propagation
    combined = source1 + " && " + source2
    processed = combined.strip().upper()
    final_cmd = f"bash -c '{processed}'"

    # Multiple sinks
    os.system(final_cmd)
    subprocess.run(final_cmd, shell=True)

    return "Complex taint flows tested"


def test_sanitization_scenarios():
    """Test various sanitization scenarios"""

    # Sanitized flow 1
    user_input1 = request.args.get("file")
    safe_file = shlex.quote(user_input1)
    os.system(f"cat {safe_file}")

    # Sanitized flow 2
    user_input2 = request.args.get("data")
    escaped_data = shlex.quote(user_input2)
    subprocess.call(f"echo {escaped_data}", shell=True)

    return "Sanitization scenarios tested"


# ============================
# MIXED VULNERABILITY TESTS
# ============================


def test_crypto_plus_injection():
    """Test weak crypto combined with injection vulnerabilities"""

    # Source: user password
    password = request.args.get("password")

    # Weak crypto (search pattern)
    weak_hash = hashlib.md5(password.encode())
    hash_string = weak_hash.hexdigest()

    # Injection (taint flow)
    os.system(f"echo 'Hash: {hash_string}'")

    return "Crypto + injection tested"


def test_sql_search_and_taint():
    """Test SQL vulnerabilities detected by both search and taint"""

    # User input (taint source)
    table_name = request.args.get("table")
    user_id = request.args.get("id")

    # Build query (taint propagation)
    query = f"SELECT * FROM {table_name} WHERE id = {user_id}"

    # Execute query (both search pattern AND taint sink)
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute(query)  # Should trigger both search and taint detection

    return "SQL search + taint tested"


def test_nested_function_calls():
    """Test nested function calls with taint"""

    def process_input(data):
        return data.upper().strip()

    def execute_command(cmd):
        return os.system(cmd)

    # Taint flow through nested calls
    user_data = request.args.get("command")
    processed = process_input(user_data)
    result = execute_command(processed)

    return result


def test_conditional_flows():
    """Test taint flows through conditional statements"""

    user_input = request.args.get("action")

    if user_input == "system":
        os.system(user_input)
    elif user_input == "eval":
        eval(user_input)
    else:
        subprocess.call(user_input, shell=True)

    return "Conditional flows tested"


def test_loop_propagation():
    """Test taint propagation through loops"""

    commands = request.args.getlist("commands")

    for cmd in commands:
        processed_cmd = cmd.strip()
        os.system(processed_cmd)

    return "Loop propagation tested"


# ============================
# EDGE CASES
# ============================


def test_multiple_assignments():
    """Test multiple assignments in taint flow"""

    source = request.args.get("data")
    var1 = source
    var2 = var1
    var3 = var2
    final = var3

    os.system(final)

    return "Multiple assignments tested"


def test_string_operations():
    """Test taint through string operations"""

    base_cmd = request.args.get("base")

    # Various string operations
    upper_cmd = base_cmd.upper()
    lower_cmd = base_cmd.lower()
    stripped_cmd = base_cmd.strip()
    replaced_cmd = base_cmd.replace(" ", "_")
    formatted_cmd = f"exec {base_cmd}"

    # All should be tainted
    os.system(upper_cmd)
    os.system(lower_cmd)
    os.system(stripped_cmd)
    os.system(replaced_cmd)
    os.system(formatted_cmd)

    return "String operations tested"


def test_mixed_sources_single_sink():
    """Test multiple sources flowing to single sink"""

    arg_data = request.args.get("arg")
    form_data = request.form.get("form")
    env_data = os.environ.get("ENV_VAR")

    # Combine multiple sources
    combined = f"{arg_data} {form_data} {env_data}"

    # Single sink
    os.system(combined)

    return "Mixed sources tested"


if __name__ == "__main__":
    print("Comprehensive unified rules test file")
    print("Run with Flask to test web-based patterns")

    # Test non-web patterns
    test_all_weak_crypto_patterns()
    test_sql_execution_patterns()
    test_all_sink_patterns()

    print("Non-web patterns tested successfully")
