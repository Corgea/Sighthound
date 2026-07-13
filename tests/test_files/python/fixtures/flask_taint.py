#!/usr/bin/env python3
"""
Simple test file for taint analysis functionality
"""

import os
import subprocess
import sqlite3
from flask import request


def vulnerable_function():
    # Taint source: user input
    user_input = request.args.get("input")

    # Taint sink: SQL injection
    cursor = sqlite3.connect(":memory:").cursor()
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)

    # Taint sink: command injection
    os.system(f"echo {user_input}")

    return "Done"


def another_vulnerable_function():
    # Taint source: environment variable
    env_var = os.environ.get("USER_DATA")

    # Taint sink: code injection
    eval(env_var)

    # Taint propagator: string formatting
    formatted = env_var.format("test")

    # Taint sink: command execution
    subprocess.run(formatted, shell=True)


def safe_function():
    # This should not trigger taint analysis
    static_query = "SELECT * FROM users WHERE id = 1"
    cursor = sqlite3.connect(":memory:").cursor()
    cursor.execute(static_query)

    # Safe command execution
    subprocess.run(["echo", "hello world"])


if __name__ == "__main__":
    vulnerable_function()
    another_vulnerable_function()
    safe_function()
