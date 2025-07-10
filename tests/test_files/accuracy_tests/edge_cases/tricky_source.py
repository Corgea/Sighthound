#!/usr/bin/env python3
"""
EDGE CASES: Tricky patterns that test the accuracy of taint analysis
"""

import os
import sys


# EC1: Same variable name, different scope (should be separate)
def get_user_data():
    """Edge case: Variable name collision"""
    user_data = os.environ.get("USER_INPUT", "")  # Tainted
    return user_data


def get_safe_data():
    """Edge case: Same variable name but safe"""
    user_data = "safe_constant"  # Safe (same name, different data)
    return user_data


# EC2: Conditional taint (complex control flow)
def get_conditional_data(use_env=True):
    """Edge case: Conditional taint source"""
    if use_env:
        return os.environ.get("CONDITIONAL", "")  # Tainted path
    else:
        return "safe_default"  # Safe path


# EC3: Nested function calls
def get_nested_data():
    """Edge case: Nested function with taint"""

    def inner():
        return sys.argv[1] if len(sys.argv) > 1 else ""  # Tainted

    return inner()


# EC4: Multiple return paths
def get_multi_return(flag):
    """Edge case: Multiple return paths"""
    if flag == 1:
        return os.environ.get("PATH1", "")  # Tainted
    elif flag == 2:
        return "safe_path"  # Safe
    else:
        return sys.argv[0]  # Tainted


# EC5: Variable reassignment
def get_reassigned_data():
    """Edge case: Variable reassignment"""
    data = "safe_initial"  # Safe initially
    data = os.environ.get("REASSIGNED", data)  # Now tainted
    return data


# EC6: Mixed safe and tainted
def get_mixed_data():
    """Edge case: Mixing safe and tainted data"""
    safe_part = "prefix_"
    tainted_part = os.getenv("SUFFIX", "")  # Tainted
    return safe_part + tainted_part  # Should be considered tainted


# EC7: Comments and strings containing patterns (should NOT confuse parser)
def get_comment_test():
    """Edge case: Comments with os.environ patterns"""
    # This comment mentions os.environ but should not be flagged
    data = "safe_data_with_environ_in_name"
    # eval() in comment should not confuse parser
    return data


# EC8: Variable aliasing
def get_aliased_data():
    """Edge case: Variable aliasing"""
    environ_alias = os.environ  # Alias to tainted source
    return environ_alias.get("ALIASED", "")  # Should still be tainted


__all__ = [
    "get_user_data",
    "get_safe_data",
    "get_conditional_data",
    "get_nested_data",
    "get_multi_return",
    "get_reassigned_data",
    "get_mixed_data",
    "get_comment_test",
    "get_aliased_data",
]
