#!/usr/bin/env python3
"""
CROSS-FILE TEST MODULE A: Source module with various taint sources
"""

import os
import sys


class TaintedDataProvider:
    """Class with tainted methods"""

    def get_env_data(self):
        """Tainted: Environment data"""
        return os.environ.get("CLASS_ENV", "")

    def get_argv_data(self):
        """Tainted: Command line data"""
        return sys.argv[1] if len(sys.argv) > 1 else ""


# CF1: Direct function exports
def get_database_config():
    """Tainted: Database configuration from environment"""
    return os.environ.get("DATABASE_CONFIG", "")


def get_user_args():
    """Tainted: User arguments from command line"""
    return sys.argv[2] if len(sys.argv) > 2 else ""


# CF2: Wrapped/processed taint
def process_env_data():
    """Tainted: Processed environment data"""
    raw = os.getenv("RAW_DATA", "")
    processed = f"processed_{raw}"
    return processed


# CF3: Taint through class instantiation
provider = TaintedDataProvider()


def get_class_env():
    """Tainted: Environment data via class"""
    return provider.get_env_data()


def get_class_argv():
    """Tainted: Command line data via class"""
    return provider.get_argv_data()


# CF4: Constants and safe data (for comparison)
SAFE_CONSTANT = "safe_module_constant"


def get_safe_module_data():
    """Safe: Module constant"""
    return SAFE_CONSTANT


def get_version():
    """Safe: Version information"""
    return "1.0.0"


# CF5: Mixed functions with conditional taint
def get_mixed_data(use_env=True):
    """Mixed: Conditional taint"""
    if use_env:
        return os.environ.get("MIXED", "")  # Tainted path
    else:
        return "safe_default"  # Safe path


__all__ = [
    "TaintedDataProvider",
    "get_database_config",
    "get_user_args",
    "process_env_data",
    "get_class_env",
    "get_class_argv",
    "get_safe_module_data",
    "get_version",
    "get_mixed_data",
    "provider",
]
