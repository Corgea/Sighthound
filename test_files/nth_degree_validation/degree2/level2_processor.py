# Level 2: First Degree Taint Propagation
# This file receives taint from level1 and propagates it further

from level1_source import (
    get_user_input,
    get_user_data,
    get_config_from_user,
    safe_constant,
)


def process_user_command():
    """
    LEVEL 2 PROPAGATION: Processes tainted user input from level 1
    """
    raw_command = get_user_input()  # Receives taint from level 1
    processed = f"processed_{raw_command}"
    return processed  # Propagates taint to level 3


def transform_user_data():
    """
    LEVEL 2 PROPAGATION: Transforms tainted data from level 1
    """
    raw_data = get_user_data()  # Receives taint from level 1
    transformed = raw_data.upper()
    return f"transformed_{transformed}"  # Propagates taint to level 3


def combine_tainted_inputs():
    """
    LEVEL 2 PROPAGATION: Combines multiple tainted inputs
    """
    cmd = get_user_input()  # Tainted
    data = get_user_data()  # Tainted
    config = get_config_from_user()  # Tainted
    combined = f"{cmd}|{data}|{config}"
    return combined  # Propagates combined taint to level 3


def mix_safe_and_tainted():
    """
    LEVEL 2 PROPAGATION: Mixes safe and tainted data
    """
    safe = safe_constant()  # Safe
    tainted = get_user_input()  # Tainted
    mixed = f"{safe}_{tainted}"
    return mixed  # Should still be considered tainted


def process_with_validation():
    """
    LEVEL 2 PROPAGATION: Processes with some validation (still tainted)
    """
    user_input = get_user_input()  # Tainted
    if len(user_input) > 0:
        validated = f"validated_{user_input}"
        return validated  # Still tainted despite validation
    return "empty"


if __name__ == "__main__":
    print("Level 2: Taint propagation layer initialized")
