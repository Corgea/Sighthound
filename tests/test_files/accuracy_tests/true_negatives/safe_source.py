#!/usr/bin/env python3
"""
TRUE NEGATIVES: Safe sources that should NOT be flagged as vulnerabilities
"""

import os
import hashlib


# TN1: Hard-coded safe values
def get_safe_constant():
    """Safe: Hard-coded constant"""
    return "safe_constant_value"


# TN2: Computed safe values
def get_computed_safe():
    """Safe: Computed from safe inputs"""
    return "prefix_" + "suffix"


# TN3: Safe configuration (not user input)
def get_app_version():
    """Safe: Application version"""
    return "1.0.0"


# TN4: Safe system information (not user controlled)
def get_python_version():
    """Safe: Python version info"""
    import sys

    return f"{sys.version_info.major}.{sys.version_info.minor}"


# TN5: Hash/digest (safe transformation)
def get_safe_hash():
    """Safe: Hash of safe data"""
    safe_data = "application_name"
    return hashlib.sha256(safe_data.encode()).hexdigest()


# TN6: Safe file operations (config files)
def get_config_template():
    """Safe: Reading config template (not user input)"""
    try:
        with open("config_template.json", "r") as f:
            return f.read()
    except:
        return '{"default": true}'


# TN7: Safe environment (application config, not user input)
def get_app_config():
    """Safe: Application configuration"""
    return os.getenv("APP_MODE", "production")  # App config, not user input


# TN8: Validated/sanitized data
def get_validated_input():
    """Safe: Validated input (hypothetical validation)"""
    # In real scenario, this would be validated
    return "validated_safe_data"


__all__ = [
    "get_safe_constant",
    "get_computed_safe",
    "get_app_version",
    "get_python_version",
    "get_safe_hash",
    "get_config_template",
    "get_app_config",
    "get_validated_input",
]
