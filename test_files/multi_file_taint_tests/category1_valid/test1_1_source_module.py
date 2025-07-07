# Test 1.1: Direct Function Import Flow - SOURCE MODULE
# Expected: This should be detected as a valid cross-file taint flow


def get_user_data():
    """
    SOURCE: Direct user input - should be flagged as taint source
    """
    return input("Enter data: ")


def safe_function():
    """
    Non-source function for negative testing
    """
    return "safe_constant_data"
