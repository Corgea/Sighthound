# Test 5.1: Three-File Chain - COMMAND RUNNER (File 3 of 3)
# Expected: Should detect complete flow from file 1 -> file 2 -> file 3

from test5_1_data_processor import process_input, process_safe_input
import os
import subprocess


def run_command():
    """
    SINK: Final destination of tainted data through 3-file chain
    Should detect: test5_1_user_input.get_input() -> test5_1_data_processor.process_input() -> os.system()
    """
    processed = process_input()  # Receives processed but still tainted data
    os.system(processed)  # SINK - should trace back through all 3 files


def run_safe_command():
    """
    Safe operation using non-tainted data
    """
    safe_processed = process_safe_input()  # Non-tainted data path
    subprocess.run(["echo", safe_processed])  # Safe operation


def run_direct_command():
    """
    Direct safe command for contrast
    """
    os.system("echo 'Hello World'")  # Safe - hardcoded command
