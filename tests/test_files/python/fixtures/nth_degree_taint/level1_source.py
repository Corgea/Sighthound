# Level 1: Initial Taint Source
# This is the starting point of our nth degree taint flow


def get_user_input():
    """
    LEVEL 1 SOURCE: Initial user input - this is where taint begins
    """
    user_input = input("Enter command: ")  # PRIMARY SOURCE
    return user_input


def get_user_data():
    """
    LEVEL 1 SOURCE: Another user input source
    """
    user_data = input("Enter data: ")  # SECONDARY SOURCE
    return user_data


def get_config_from_user():
    """
    LEVEL 1 SOURCE: Configuration from user
    """
    user_config = input("Enter config: ")  # TERTIARY SOURCE
    return f"config_{user_config}"


def safe_constant():
    """
    LEVEL 1 SAFE: Non-tainted constant
    """
    return "safe_constant_value"


if __name__ == "__main__":
    print("Level 1: Taint sources initialized")
