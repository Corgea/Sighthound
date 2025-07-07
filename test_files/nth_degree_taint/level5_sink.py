# Level 5: Final Sink - Fourth Degree Taint Reception
# This file contains the final sinks that should detect nth degree taint

import os
import subprocess
from level4_aggregator import (
    enterprise_data_aggregation,
    multi_source_consolidation,
    workflow_orchestration,
    distributed_processing,
    caching_layer,
)


def execute_enterprise_command():
    """
    LEVEL 5 SINK: Executes command with 4th degree taint
    Flow: Level1 -> Level2 -> Level3 -> Level4 -> Level5
    """
    enterprise_data = enterprise_data_aggregation()  # 4th degree taint
    os.system(enterprise_data)  # SINK - Should detect 4th degree taint


def process_consolidated_data():
    """
    LEVEL 5 SINK: Processes consolidated tainted data
    Flow: Level1(multiple) -> Level2 -> Level3 -> Level4 -> Level5
    """
    consolidated = multi_source_consolidation()  # 4th degree taint
    eval(consolidated)  # SINK - Should detect 4th degree taint


def execute_orchestrated_workflow():
    """
    LEVEL 5 SINK: Executes orchestrated workflow
    Flow: Level1 -> Level2 -> Level3 -> Level4 -> Level5
    """
    orchestrated = workflow_orchestration()  # 4th degree taint
    exec(orchestrated)  # SINK - Should detect 4th degree taint


def run_distributed_command():
    """
    LEVEL 5 SINK: Runs distributed command
    Flow: Level1 -> Level2 -> Level3 -> Level4 -> Level5
    """
    distributed = distributed_processing()  # 4th degree taint
    subprocess.run(distributed, shell=True)  # SINK - Should detect 4th degree taint


def execute_cached_operation():
    """
    LEVEL 5 SINK: Executes cached operation
    Flow: Level1 -> Level2 -> Level3 -> Level4 -> Level4 -> Level5
    """
    cached = caching_layer()  # 4th degree taint (with internal recursion)
    os.system(cached)  # SINK - Should detect 4th degree taint


def complex_multi_sink():
    """
    LEVEL 5 SINK: Complex sink using multiple 4th degree sources
    """
    enterprise = enterprise_data_aggregation()  # 4th degree taint
    consolidated = multi_source_consolidation()  # 4th degree taint
    orchestrated = workflow_orchestration()  # 4th degree taint

    # Multiple sinks with 4th degree taint
    os.system(enterprise)  # SINK 1
    eval(consolidated)  # SINK 2
    exec(orchestrated)  # SINK 3


def safe_operation():
    """
    LEVEL 5 SAFE: Safe operation that should not be flagged
    """
    safe_data = "safe_constant"
    os.system(f"echo {safe_data}")  # Should NOT be flagged


if __name__ == "__main__":
    print("Level 5: Final sink layer - 4th degree taint reception ready")
    print("Testing nth degree taint propagation...")

    # These should all be detected as tainted
    print("1. Enterprise command execution")
    print("2. Consolidated data processing")
    print("3. Orchestrated workflow execution")
    print("4. Distributed command execution")
    print("5. Cached operation execution")
    print("6. Complex multi-sink operations")
