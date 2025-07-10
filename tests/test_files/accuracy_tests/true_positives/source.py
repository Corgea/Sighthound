#!/usr/bin/env python3
"""
TRUE POSITIVES: Real taint sources that SHOULD be detected in cross-file analysis
"""

import os
import sys


# TP1: Environment variable source
def get_database_url():
    """Real vulnerability: environment variable"""
    return os.environ.get("DATABASE_URL", "default")


# TP2: Command line argument source
def get_user_command():
    """Real vulnerability: command line argument"""
    if len(sys.argv) > 1:
        return sys.argv[1]
    return ""


# TP3: File input source
def read_user_file():
    """Real vulnerability: file input"""
    try:
        with open("user_input.txt", "r") as f:
            return f.read()
    except:
        return ""


# TP4: Network-like input simulation
def get_request_data():
    """Real vulnerability: simulated request data"""
    return os.getenv("REQUEST_DATA", "")


# TP5: Multiple chained sources
def get_config_chain():
    """Real vulnerability: chained environment access"""
    base = os.environ.get("BASE_CONFIG", "")
    extended = os.environ.get("EXTENDED_CONFIG", base)
    return extended


# TP6: Return value that propagates taint
def process_user_input():
    """Real vulnerability: processes and returns tainted data"""
    raw = sys.argv[0] if len(sys.argv) > 0 else ""
    processed = f"processed_{raw}"
    return processed


# Export all vulnerable functions
__all__ = [
    "get_database_url",
    "get_user_command",
    "read_user_file",
    "get_request_data",
    "get_config_chain",
    "process_user_input",
]
