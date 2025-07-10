#!/usr/bin/env python3
"""
TRUE POSITIVES: Cross-file vulnerabilities that SHOULD be detected
"""

import os
from source import (
    get_database_url,
    get_user_command,
    read_user_file,
    get_request_data,
    get_config_chain,
    process_user_input,
)


# TP1: Cross-file eval vulnerability
def vulnerable_eval():
    """SHOULD BE DETECTED: Cross-file taint to eval()"""
    db_url = get_database_url()  # Tainted from source.py
    eval(db_url)  # Vulnerable sink


# TP2: Cross-file exec vulnerability
def vulnerable_exec():
    """SHOULD BE DETECTED: Cross-file taint to exec()"""
    cmd = get_user_command()  # Tainted from source.py
    exec(cmd)  # Vulnerable sink


# TP3: Cross-file system command vulnerability
def vulnerable_system():
    """SHOULD BE DETECTED: Cross-file taint to os.system()"""
    file_data = read_user_file()  # Tainted from source.py
    os.system(file_data)  # Vulnerable sink


# TP4: Cross-file compile vulnerability
def vulnerable_compile():
    """SHOULD BE DETECTED: Cross-file taint to compile()"""
    request_data = get_request_data()  # Tainted from source.py
    compile(request_data, "<string>", "exec")  # Vulnerable sink


# TP5: Chained cross-file vulnerability
def vulnerable_chain():
    """SHOULD BE DETECTED: Complex cross-file chain"""
    config = get_config_chain()  # Tainted from source.py (chain)
    eval(config)  # Vulnerable sink


# TP6: Processed cross-file vulnerability
def vulnerable_processed():
    """SHOULD BE DETECTED: Processed tainted data"""
    processed = process_user_input()  # Tainted from source.py
    exec(processed)  # Vulnerable sink


# TP7: Multiple sources to same sink
def vulnerable_multiple():
    """SHOULD BE DETECTED: Multiple tainted sources"""
    data1 = get_database_url()  # Tainted source 1
    data2 = get_user_command()  # Tainted source 2
    combined = f"{data1}_{data2}"
    eval(combined)  # Should detect both flows


# TP8: Local assignment with cross-file source
def vulnerable_assignment():
    """SHOULD BE DETECTED: Local variable with cross-file source"""
    local_var = get_request_data()  # Cross-file tainted assignment
    exec(local_var)  # Local vulnerable sink


if __name__ == "__main__":
    print("True positive vulnerabilities - should ALL be detected")
