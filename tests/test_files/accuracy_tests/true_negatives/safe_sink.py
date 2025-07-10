#!/usr/bin/env python3
"""
TRUE NEGATIVES: Safe usage that should NOT be flagged as vulnerabilities
"""

import os
from safe_source import (
    get_safe_constant,
    get_computed_safe,
    get_app_version,
    get_python_version,
    get_safe_hash,
    get_config_template,
    get_app_config,
    get_validated_input,
)


# TN1: Safe constant in eval (should NOT be flagged)
def safe_eval_constant():
    """Should NOT be flagged: Safe constant in eval"""
    safe_val = get_safe_constant()  # Safe source
    eval(safe_val)  # Not vulnerable - safe input


# TN2: Safe computed value in exec (should NOT be flagged)
def safe_exec_computed():
    """Should NOT be flagged: Safe computed value in exec"""
    computed = get_computed_safe()  # Safe source
    exec(computed)  # Not vulnerable - safe input


# TN3: Safe version in system command (should NOT be flagged)
def safe_system_version():
    """Should NOT be flagged: Safe version info"""
    version = get_app_version()  # Safe source
    os.system(f"echo {version}")  # Not vulnerable - safe input


# TN4: Safe Python version in compile (should NOT be flagged)
def safe_compile_version():
    """Should NOT be flagged: Safe Python version"""
    py_version = get_python_version()  # Safe source
    compile(py_version, "<string>", "eval")  # Not vulnerable - safe input


# TN5: Safe hash in eval (should NOT be flagged)
def safe_eval_hash():
    """Should NOT be flagged: Safe hash value"""
    hash_val = get_safe_hash()  # Safe source
    eval(f"'{hash_val}'")  # Not vulnerable - safe input


# TN6: Safe config template (should NOT be flagged)
def safe_template_usage():
    """Should NOT be flagged: Safe config template"""
    template = get_config_template()  # Safe source
    exec(template)  # Not vulnerable - safe input


# TN7: Safe app config (should NOT be flagged)
def safe_app_config():
    """Should NOT be flagged: Safe app configuration"""
    config = get_app_config()  # Safe source
    eval(config)  # Not vulnerable - safe input


# TN8: Safe validated input (should NOT be flagged)
def safe_validated():
    """Should NOT be flagged: Validated safe input"""
    validated = get_validated_input()  # Safe source
    exec(validated)  # Not vulnerable - validated input


# TN9: Hard-coded literals (should NOT be flagged)
def safe_literals():
    """Should NOT be flagged: Hard-coded literals"""
    eval("1 + 1")  # Not vulnerable - literal
    exec("print('hello')")  # Not vulnerable - literal
    os.system("echo safe")  # Not vulnerable - literal


# TN10: No user input involved (should NOT be flagged)
def safe_no_input():
    """Should NOT be flagged: No user input"""
    safe_data = "application_constant"
    eval(safe_data)  # Not vulnerable - no user input


if __name__ == "__main__":
    print("True negatives - should NOT be flagged as vulnerabilities")
