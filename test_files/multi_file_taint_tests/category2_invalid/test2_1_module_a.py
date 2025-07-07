# Test 2.1: Phantom Flow - No Import Relationship - MODULE A
# Expected: Should NOT create cross-file flow to module_b (no imports)


def safe_function():
    """
    SOURCE: User input in isolated module
    This should NOT connect to module_b because there's no import relationship
    """
    user_data = input("Enter: ")  # SOURCE
    return user_data


def another_function():
    """
    Additional function to make the module realistic
    """
    return "module_a_data"
