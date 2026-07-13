#!/usr/bin/env python3
"""
Enhanced source file with multiple taint sources matching rule patterns
"""

import os
import sys


def get_user_input():
    """Source: user input via command line args - TAINTED"""
    if len(sys.argv) > 1:
        return sys.argv[1]  # Tainted source: sys.argv
    return "default"


def get_environment_config():
    """Source: environment variables - TAINTED"""
    config = os.environ.get("DATABASE_URL", "default")  # Tainted source: os.environ
    return config


def get_file_content():
    """Source: file input - TAINTED"""
    try:
        with open("user_input.txt", "r") as f:
            return f.read()  # Tainted source: file input
    except FileNotFoundError:
        return "no file found"


def get_network_data():
    """Source: simulated network input - TAINTED"""
    # This simulates user-controlled data from network
    user_data = os.getenv("NETWORK_DATA", "default")  # Tainted source: os.getenv
    return user_data


def get_request_parameter():
    """Source: simulated HTTP request parameter - TAINTED"""
    # Simulates request.args.get() or similar
    param = os.environ.get("REQUEST_PARAM", "")  # Tainted source: os.environ.get
    return param


# Additional helper functions that propagate taint
def process_user_data(data):
    """Propagates tainted data"""
    processed = f"processed_{data}"
    return processed


def format_config(config):
    """Propagates tainted config data"""
    return f"config:{config}"


# Export all functions for import by other files
__all__ = [
    "get_user_input",
    "get_environment_config",
    "get_file_content",
    "get_network_data",
    "get_request_parameter",
    "process_user_data",
    "format_config",
]
