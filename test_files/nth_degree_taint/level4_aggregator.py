# Level 4: Third Degree Taint Propagation
# This file receives taint from level3 and propagates it further

from level3_transformer import (
    advanced_command_processing,
    data_transformation_pipeline,
    complex_data_merger,
    conditional_processing,
    class_based_processing,
)


def enterprise_data_aggregation():
    """
    LEVEL 4 PROPAGATION: Enterprise-level data aggregation
    """
    advanced = advanced_command_processing()  # Receives taint from level 3
    pipeline = data_transformation_pipeline()  # Receives taint from level 3

    aggregated = f"enterprise_{advanced}_{pipeline}"
    return aggregated  # Propagates taint to level 5


def multi_source_consolidation():
    """
    LEVEL 4 PROPAGATION: Consolidates multiple tainted sources
    """
    merged = complex_data_merger()  # Receives taint from level 3
    conditional = conditional_processing()  # Receives taint from level 3
    class_based = class_based_processing()  # Receives taint from level 3

    consolidated = f"consolidated_{merged}_{conditional}_{class_based}"
    return consolidated  # Propagates taint to level 5


def workflow_orchestration():
    """
    LEVEL 4 PROPAGATION: Orchestrates workflow with tainted data
    """
    all_sources = [
        advanced_command_processing(),  # Tainted
        data_transformation_pipeline(),  # Tainted
        complex_data_merger(),  # Tainted
        conditional_processing(),  # Tainted
        class_based_processing(),  # Tainted
    ]

    orchestrated = "orchestrated_" + "_".join(all_sources)
    return orchestrated  # Propagates complex taint to level 5


def distributed_processing():
    """
    LEVEL 4 PROPAGATION: Simulates distributed processing
    """
    # Simulate distributed nodes processing tainted data
    node1_data = advanced_command_processing()  # Tainted from level 3
    node2_data = data_transformation_pipeline()  # Tainted from level 3
    node3_data = complex_data_merger()  # Tainted from level 3

    distributed = (
        f"distributed_node1_{node1_data}_node2_{node2_data}_node3_{node3_data}"
    )
    return distributed  # Propagates distributed taint to level 5


def caching_layer():
    """
    LEVEL 4 PROPAGATION: Caching layer that maintains taint
    """
    cached_data = enterprise_data_aggregation()  # Receives taint from level 4
    cache_key = f"cache_{hash(cached_data) % 10000}"
    return f"{cache_key}_{cached_data}"  # Propagates cached taint to level 5


if __name__ == "__main__":
    print("Level 4: Enterprise aggregation layer initialized")
