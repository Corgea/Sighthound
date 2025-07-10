# Test 4.2: Real Environment Variable Vulnerability - ENV READER
# Expected: Should detect this as a real vulnerability (reading user-controlled env var)

import os


def get_user_command():
    """
    SOURCE: Reading user-controlled environment variable
    This IS a real vulnerability - user controls this env var
    """
    return os.environ.get("USER_COMMAND")  # SOURCE - user can set this


def get_user_input_path():
    """
    Another real vulnerability - user-controlled path
    """
    return os.environ.get("USER_INPUT_FILE", "/tmp/default")


def safe_config_read():
    """
    Safe configuration reading for contrast
    """
    return os.environ.get("APP_CONFIG_DIR", "/etc/myapp")
