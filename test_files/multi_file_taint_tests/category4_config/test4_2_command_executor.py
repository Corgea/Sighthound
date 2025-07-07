# Test 4.2: Real Environment Variable Vulnerability - COMMAND EXECUTOR
# Expected: Should detect flow from get_user_command() to subprocess.run()

from test4_2_env_reader import get_user_command, get_user_input_path, safe_config_read
import subprocess
import os


def execute_user_command():
    """
    VULNERABLE: Should detect taint flow from user env var to subprocess
    """
    cmd = get_user_command()  # Tainted data from user-controlled env var
    if cmd:
        subprocess.run(cmd, shell=True)  # SINK - dangerous!


def process_user_file():
    """
    Another vulnerability with file operations
    """
    user_path = get_user_input_path()  # Tainted path
    os.system(f"cat {user_path}")  # SINK - path injection


def safe_config_operation():
    """
    Safe operation using configuration
    """
    config_dir = safe_config_read()  # Safe config value
    subprocess.run(["ls", config_dir])  # Safe - config not user input
