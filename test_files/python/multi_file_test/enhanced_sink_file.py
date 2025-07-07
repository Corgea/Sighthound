#!/usr/bin/env python3
"""
Enhanced sink file that uses tainted data from enhanced_source_file.py with rule-matching sinks
"""

import os
import subprocess
from enhanced_source_file import (
    get_user_input,
    get_environment_config,
    get_file_content,
    get_network_data,
    get_request_parameter,
    process_user_data,
    format_config,
)


def vulnerable_eval_cross_file():
    """CROSS-FILE TAINT FLOW: Uses tainted data from another file in eval() - SHOULD BE DETECTED"""
    config = (
        get_environment_config()
    )  # Tainted data from enhanced_source_file.py (os.environ)
    eval(config)  # Vulnerable sink - matches rule pattern eval()


def vulnerable_exec_cross_file():
    """CROSS-FILE TAINT FLOW: Uses tainted data from another file in exec() - SHOULD BE DETECTED"""
    user_data = get_user_input()  # Tainted data from enhanced_source_file.py (sys.argv)
    exec(user_data)  # Vulnerable sink - matches rule pattern exec()


def vulnerable_system_cross_file():
    """CROSS-FILE TAINT FLOW: Uses tainted data in os.system() - SHOULD BE DETECTED"""
    network_data = (
        get_network_data()
    )  # Tainted data from enhanced_source_file.py (os.getenv)
    os.system(network_data)  # Vulnerable sink - matches rule pattern os.system()


def complex_cross_file_flow():
    """COMPLEX CROSS-FILE TAINT FLOW: Multiple steps with taint propagation"""
    # Step 1: Get tainted data from another file
    raw_data = get_user_input()  # Tainted source from enhanced_source_file.py

    # Step 2: Process data (still tainted)
    processed = process_user_data(raw_data)  # Taint propagates through processing

    # Step 3: Use in vulnerable sink
    eval(processed)  # Vulnerable sink - should detect the flow


# Local vulnerable functions for comparison
def local_vulnerable_function():
    """LOCAL TAINT FLOW: For comparison with cross-file flows"""
    local_input = os.environ.get("LOCAL_VAR", "")  # Local tainted source
    eval(local_input)  # Local vulnerable sink


if __name__ == "__main__":
    print("This file contains cross-file taint vulnerabilities for testing")
