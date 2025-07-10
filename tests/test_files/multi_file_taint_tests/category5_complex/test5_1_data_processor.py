# Test 5.1: Three-File Chain - DATA PROCESSOR (File 2 of 3)
# Expected: Middle file that processes and forwards tainted data

from test5_1_user_input import get_input, get_safe_data


def process_input():
    """
    PROPAGATION: Takes user input and processes it
    Should maintain taint status through processing
    """
    raw_data = get_input()  # Receives tainted data from file 1
    return f"processed_{raw_data}"  # Processes but keeps taint


def process_safe_input():
    """
    Safe processing for contrast
    """
    safe_data = get_safe_data()  # Non-tainted data
    return f"processed_{safe_data}"


def sanitize_input():
    """
    Example of potential sanitization (though our current system doesn't detect this)
    """
    raw_data = get_input()
    # In a real system, this might sanitize the input
    return raw_data.replace(";", "").replace("&", "")
