# Test 1.1: Direct Function Import Flow - SINK MODULE
# Expected: Should detect flow from test1_1_source_module.get_user_data() to os.system()

from test1_1_source_module import get_user_data
import os


def process_data():
    """
    SINK: Should detect taint flow from imported function to os.system
    """
    user_input = get_user_data()  # Import usage - tainted data
    os.system(user_input)  # SINK - should detect flow


def safe_process():
    """
    Safe function using non-tainted data
    """
    safe_data = "echo 'safe'"
    os.system(safe_data)
