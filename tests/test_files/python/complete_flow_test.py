#!/usr/bin/env python3
"""
Comprehensive test file for taint analysis demonstrating various data flows
"""

import os
import subprocess
import sqlite3
from flask import Flask, request, render_template_string
import pickle
import yaml

app = Flask(__name__)


# Command Injection Flow
@app.route("/command")
def command_injection():
    # Source: User input from request
    user_input = request.args.get("cmd", "")

    # Sink: Direct command execution (VULNERABLE)
    os.system(user_input)

    # Another flow with propagation
    command = f"echo {user_input}"
    subprocess.run(command, shell=True)

    return "Command executed"


# SQL Injection Flow
@app.route("/query")
def sql_injection():
    # Source: User input
    user_id = request.args.get("id", "")

    # Propagation through string formatting
    query = f"SELECT * FROM users WHERE id = {user_id}"

    # Sink: Database execution (VULNERABLE)
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute(query)

    return "Query executed"


# Sanitized Flow
@app.route("/safe_command")
def safe_command():
    # Source: User input
    user_input = request.args.get("cmd", "")

    # Sanitization
    import shlex

    safe_input = shlex.quote(user_input)

    # Sink: Command execution (SAFE due to sanitization)
    os.system(f"echo {safe_input}")

    return "Safe command executed"


# Path Traversal Flow
@app.route("/file")
def path_traversal():
    # Source: User input
    filename = request.args.get("file", "")

    # Propagation
    filepath = os.path.join("/uploads", filename)

    # Sink: File operation (VULNERABLE)
    with open(filepath, "r") as f:
        content = f.read()

    return content


# Template Injection Flow
@app.route("/template")
def template_injection():
    # Source: User input
    template_string = request.args.get("template", "")

    # Sink: Template rendering (VULNERABLE)
    return render_template_string(template_string)


# Deserialization Flow
@app.route("/deserialize")
def deserialization():
    # Source: User data
    data = request.get_data()

    # Sink: Unsafe deserialization (VULNERABLE)
    obj = pickle.loads(data)

    return str(obj)


# Multiple hops flow
@app.route("/multi_hop")
def multi_hop_flow():
    # Source
    user_input = request.args.get("data", "")

    # First hop: assignment
    temp_var = user_input

    # Second hop: string manipulation
    processed = temp_var.upper()

    # Third hop: formatting
    final_command = f"echo {processed}"

    # Sink: command execution
    os.system(final_command)

    return "Multi-hop flow executed"


# Environment variable flow
def env_flow():
    # Source: Environment variable
    config_value = os.environ.get("CONFIG_CMD", "")

    # Sink: Command execution
    subprocess.call(config_value, shell=True)


# File-based flow
def file_flow():
    # Source: File input
    with open("user_input.txt", "r") as f:
        user_data = f.read()

    # Sink: Code execution
    eval(user_data)


if __name__ == "__main__":
    app.run(debug=True)
