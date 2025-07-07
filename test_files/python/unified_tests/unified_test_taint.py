#!/usr/bin/env python3
"""
Test file for unified rule taint analysis patterns
"""

import os
import subprocess
import shlex
from flask import Flask, request

app = Flask(__name__)


def command_injection_flow():
    """Test command injection taint flow"""
    # Source: request.args.get
    user_cmd = request.args.get("command")

    # Sink: os.system
    os.system(user_cmd)

    return "Command executed"


def subprocess_flow():
    """Test subprocess taint flow"""
    # Source: request.form.get
    script_name = request.form.get("script")

    # Sink: subprocess.call
    subprocess.call(script_name, shell=True)

    # Another sink: subprocess.run
    subprocess.run(script_name, shell=True)

    return "Subprocess executed"


def input_to_eval_flow():
    """Test input to eval flow"""
    # Source: input(
    user_code = input("Enter Python code: ")

    # Sink: eval
    result = eval(user_code)

    # Another sink: exec
    exec(user_code)

    return result


def path_traversal_flow():
    """Test path traversal taint flow"""
    # Source: request.args.get
    filename = request.args.get("file")

    # Propagation through os.path.join
    full_path = os.path.join("/uploads", filename)

    # Sink: open(
    with open(full_path, "r") as f:
        content = f.read()

    return content


def sanitized_command_flow():
    """Test sanitized flow (should be marked as safe)"""
    # Source: request.args.get
    user_input = request.args.get("data")

    # Sanitization: shlex.quote
    safe_input = shlex.quote(user_input)

    # Sink: os.system (but sanitized)
    os.system(f"echo {safe_input}")

    return "Safe command executed"


def multi_hop_taint_flow():
    """Test multi-hop taint propagation"""
    # Source: request.form.get
    raw_data = request.form.get("data")

    # First hop: assignment
    processed_data = raw_data

    # Second hop: string manipulation
    formatted_data = processed_data.upper()

    # Third hop: format string
    command = f"echo {formatted_data}"

    # Sink: subprocess.run
    subprocess.run(command, shell=True)

    return "Multi-hop flow executed"


def environment_variable_flow():
    """Test environment variable source"""
    # Source: os.environ.get
    config_cmd = os.environ.get("USER_COMMAND")

    # Sink: os.system
    os.system(config_cmd)

    return "Environment command executed"


def complex_propagation_flow():
    """Test complex propagation patterns"""
    # Source: request.json
    json_data = request.json.get("payload")

    # Propagation through string operations
    step1 = json_data.strip()
    step2 = step1.replace('"', "")
    step3 = step2.lower()

    # Sink: eval
    eval(step3)

    return "Complex flow executed"


if __name__ == "__main__":
    print("Taint analysis test file - run with Flask to test properly")
