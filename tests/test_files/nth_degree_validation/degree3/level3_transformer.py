# Level 3: Second Degree Taint Propagation
# This file receives taint from level2 and propagates it further

from level2_processor import (
    process_user_command,
    transform_user_data,
    combine_tainted_inputs,
    mix_safe_and_tainted,
    process_with_validation,
)


def advanced_command_processing():
    """
    LEVEL 3 PROPAGATION: Advanced processing of tainted command
    """
    processed_cmd = process_user_command()  # Receives taint from level 2
    advanced = f"advanced_{processed_cmd}"
    return advanced  # Propagates taint to level 4


def data_transformation_pipeline():
    """
    LEVEL 3 PROPAGATION: Data transformation pipeline
    """
    transformed = transform_user_data()  # Receives taint from level 2
    pipelined = f"pipeline_{transformed}"
    return pipelined  # Propagates taint to level 4


def complex_data_merger():
    """
    LEVEL 3 PROPAGATION: Complex merger of multiple tainted sources
    """
    combined = combine_tainted_inputs()  # Receives taint from level 2
    mixed = mix_safe_and_tainted()  # Receives taint from level 2
    validated = process_with_validation()  # Receives taint from level 2

    merged = f"merged_{combined}_{mixed}_{validated}"
    return merged  # Propagates complex taint to level 4


def conditional_processing():
    """
    LEVEL 3 PROPAGATION: Conditional processing with tainted data
    """
    cmd = process_user_command()  # Tainted from level 2
    if "processed_" in cmd:
        conditional = f"conditional_{cmd}"
        return conditional  # Propagates taint to level 4
    return "no_processing"


def class_based_processing():
    """
    LEVEL 3 PROPAGATION: Class-based taint propagation
    """

    class TaintProcessor:
        def __init__(self):
            self.data = transform_user_data()  # Receives taint from level 2

        def process(self):
            return f"class_processed_{self.data}"  # Propagates taint

    processor = TaintProcessor()
    return processor.process()  # Propagates taint to level 4


if __name__ == "__main__":
    print("Level 3: Advanced taint transformation layer initialized")
