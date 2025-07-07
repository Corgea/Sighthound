# Level 4: 3rd Degree Sink
import os
from level3_transformer import advanced_command_processing


def execute_advanced_command():
    """3rd degree taint: Level1 -> Level2 -> Level3 -> Level4"""
    advanced_cmd = advanced_command_processing()  # 3rd degree taint
    os.system(advanced_cmd)  # SINK - Should detect 3rd degree taint


if __name__ == "__main__":
    execute_advanced_command()
