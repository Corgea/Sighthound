#!/usr/bin/env python3
"""
Mixed vulnerability test file - should trigger both search and taint analysis
"""

import os
import sqlite3
import hashlib
import subprocess
from flask import Flask, request
from Crypto.Hash import MD5
from Crypto.Cipher import DES

app = Flask(__name__)


@app.route("/vulnerable_endpoint")
def vulnerable_endpoint():
    """Endpoint with multiple vulnerability types"""

    # TAINT FLOW: User input to command execution
    user_command = request.args.get("cmd")
    os.system(user_command)  # Should be detected by taint analysis

    # SEARCH PATTERN: Weak cryptography
    weak_hash = hashlib.md5(b"sensitive data")  # Should be detected by search

    # TAINT FLOW: SQL injection via taint
    user_id = request.args.get("id")
    query = f"SELECT * FROM users WHERE id = {user_id}"

    # SEARCH PATTERN: SQL execution
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(query)  # Should be detected by both search AND taint

    return "Endpoint processed"


def crypto_weakness_examples():
    """Examples of weak cryptography (search patterns)"""

    # Weak hashing algorithms
    md5_hash = hashlib.md5(b"password")
    sha1_hash = hashlib.sha1(b"secret")

    # Weak encryption
    crypto_md5 = MD5.new()
    weak_cipher = DES.new(b"12345678", DES.MODE_ECB)

    return "Crypto examples done"


def command_injection_variations():
    """Various command injection patterns (taint flows)"""

    # Direct user input to system
    cmd1 = request.args.get("command1")
    os.system(cmd1)

    # Through subprocess
    cmd2 = request.form.get("command2")
    subprocess.call(cmd2, shell=True)
    subprocess.run(cmd2, shell=True)

    # Through eval/exec
    code = request.args.get("code")
    eval(code)
    exec(code)

    return "Command injection examples done"


def path_operations():
    """File path operations (taint flows)"""

    # Path traversal
    filename = request.args.get("filename")
    full_path = os.path.join("/uploads", filename)

    # File operations
    with open(full_path, "r") as f:
        content = f.read()

    return content


def database_operations():
    """Database operations (both search and taint)"""

    # Raw SQL with user input (taint flow)
    table_name = request.args.get("table")
    user_filter = request.args.get("filter")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    # These should trigger search patterns
    cursor.execute(f"SELECT * FROM {table_name} WHERE {user_filter}")
    cursor.executemany("INSERT INTO logs VALUES (?, ?)", [(1, "test")])

    # Direct connection execute (search pattern)
    conn.execute("DELETE FROM temp_table")

    return "Database operations done"


def environment_based_attacks():
    """Environment variable based attacks"""

    # Environment variable as source (taint flow)
    malicious_cmd = os.environ.get("MALICIOUS_COMMAND")
    if malicious_cmd:
        os.system(malicious_cmd)
        subprocess.call(malicious_cmd, shell=True)

    return "Environment attacks done"


def mixed_crypto_and_injection():
    """Mix of crypto weaknesses and injection"""

    # Weak crypto (search pattern)
    user_password = request.args.get("password")
    weak_hash = hashlib.sha1(user_password.encode())  # Weak + taint

    # Use weak hash in command (double vulnerability)
    hash_str = weak_hash.hexdigest()
    os.system(f"echo {hash_str}")  # Command injection via taint

    return "Mixed vulnerabilities done"


if __name__ == "__main__":
    print("Mixed vulnerability test file")
    crypto_weakness_examples()
    print("Run with Flask to test web-based vulnerabilities")
