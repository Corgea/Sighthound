#!/usr/bin/env python3
"""
CROSS-FILE TEST MODULE B: Intermediate module that imports from A and propagates taint
"""

import os
from module_a import (
    get_database_config,
    get_user_args,
    process_env_data,
    get_class_env,
    get_safe_module_data,
    get_version,
    TaintedDataProvider,
)


# CF-B1: Direct propagation of tainted data
def propagate_db_config():
    """Tainted: Propagates database config from module A"""
    config = get_database_config()  # Tainted from module_a
    return f"propagated_{config}"  # Still tainted


def propagate_user_args():
    """Tainted: Propagates user args from module A"""
    args = get_user_args()  # Tainted from module_a
    return args.upper()  # Still tainted


# CF-B2: Combining multiple tainted sources
def combine_tainted_sources():
    """Tainted: Combines multiple tainted sources"""
    db_config = get_database_config()  # Tainted
    user_args = get_user_args()  # Tainted
    processed = process_env_data()  # Tainted

    combined = f"{db_config}_{user_args}_{processed}"
    return combined  # Tainted (combination of tainted sources)


# CF-B3: Class-based taint propagation
def propagate_class_taint():
    """Tainted: Propagates class-based taint"""
    class_data = get_class_env()  # Tainted from module_a class
    return f"class_processed_{class_data}"


# CF-B4: Safe data propagation (should NOT be flagged)
def propagate_safe_data():
    """Safe: Propagates safe data from module A"""
    safe_data = get_safe_module_data()  # Safe from module_a
    version = get_version()  # Safe from module_a
    return f"{safe_data}_v{version}"  # Should remain safe


# CF-B5: Mixed safe and tainted (should be flagged)
def mix_safe_and_tainted():
    """Tainted: Mixes safe and tainted data"""
    safe_part = get_safe_module_data()  # Safe
    tainted_part = get_database_config()  # Tainted
    return f"{safe_part}_{tainted_part}"  # Should be considered tainted


# CF-B6: Local taint source for comparison
def get_local_taint():
    """Tainted: Local taint source in module B"""
    return os.environ.get("MODULE_B_LOCAL", "")


# CF-B7: Complex processing chain
def complex_processing_chain():
    """Tainted: Complex multi-step processing"""
    # Step 1: Get tainted data from module A
    raw_tainted = get_database_config()

    # Step 2: Process it locally
    step1 = f"step1_{raw_tainted}"

    # Step 3: Further processing
    step2 = step1.replace("_", "-")

    # Step 4: Final processing
    final = f"final_{step2}"

    return final  # Should still be tainted


# CF-B8: Instance creation and usage
provider_instance = TaintedDataProvider()


def use_class_instance():
    """Tainted: Uses class instance from module A"""
    return provider_instance.get_env_data()  # Tainted via class


__all__ = [
    "propagate_db_config",
    "propagate_user_args",
    "combine_tainted_sources",
    "propagate_class_taint",
    "propagate_safe_data",
    "mix_safe_and_tainted",
    "get_local_taint",
    "complex_processing_chain",
    "use_class_instance",
]
