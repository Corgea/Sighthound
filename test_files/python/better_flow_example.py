#!/usr/bin/env python3
"""
Better example showing what taint flow output should capture
"""

import os
import subprocess
import shlex
from flask import request


def complex_flow_example():
    # SOURCE: User input enters here
    user_input = request.args.get("cmd")

    # TRACE: Data flows through string operations
    prefix = "echo "

    # TRACE: String concatenation propagates taint
    command = prefix + user_input

    # TRACE: Further manipulation
    final_command = command.upper()

    # SINK: Tainted data reaches dangerous function
    os.system(final_command)

    return "Done"


def sanitized_flow_example():
    # SOURCE: User input
    user_input = request.args.get("file")

    # TRACE: Data flows
    filename = user_input + ".txt"

    # SANITIZER: Proper sanitization breaks the flow
    safe_filename = shlex.quote(filename)

    # SINK: Now safe due to sanitization
    os.system(f"cat {safe_filename}")

    return "Safe"


if __name__ == "__main__":
    complex_flow_example()
    sanitized_flow_example()
