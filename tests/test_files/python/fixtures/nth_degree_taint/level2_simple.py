# Level 2: Simple cross-file test
import os
from level1_source import get_user_input


def execute_user_command():
    """
    LEVEL 2 SINK: Simple cross-file taint test
    Flow: Level1 input() -> Level2 os.system()
    """
    user_cmd = get_user_input()  # Should receive taint from level1
    os.system(user_cmd)  # SINK - Should detect cross-file taint


if __name__ == "__main__":
    print("Level 2: Simple cross-file taint test")
    execute_user_command()
