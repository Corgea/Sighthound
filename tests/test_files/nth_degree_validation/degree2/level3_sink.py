# Level 3: 2nd Degree Sink
# This file receives 2nd degree taint: Level1 -> Level2 -> Level3

import os
from level2_processor import process_user_command


def execute_processed_command():
    """
    LEVEL 3 SINK: 2nd degree taint reception
    Flow: Level1 input() -> Level2 process -> Level3 execute
    """
    processed_cmd = process_user_command()  # 2nd degree taint
    os.system(processed_cmd)  # SINK - Should detect 2nd degree taint


if __name__ == "__main__":
    print("Level 3: 2nd degree taint sink")
    execute_processed_command()
