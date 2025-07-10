# Test 5.1: Three-File Chain - USER INPUT (File 1 of 3)
# Expected: Should trace through all 3 files to detect complete flow


def get_input():
    """
    SOURCE: User input that will flow through 3 files
    This tests multi-hop flow detection capability
    """
    return input("Enter command: ")


def get_safe_data():
    """
    Safe function for contrast testing
    """
    return "safe_default_command"
