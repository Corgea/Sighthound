#!/usr/bin/env python3
"""
CROSS-FILE TEST MODULE C: Final sink module that tests complex multi-file taint flows
"""

import os
import subprocess
from module_a import get_database_config, get_safe_module_data, get_version
from module_b import (
    propagate_db_config,
    propagate_user_args,
    combine_tainted_sources,
    propagate_class_taint,
    propagate_safe_data,
    mix_safe_and_tainted,
    get_local_taint,
    complex_processing_chain,
    use_class_instance,
)


# CF-C1: Direct A->C taint flow (SHOULD detect)
def test_direct_a_to_c():
    """SHOULD detect: Direct taint flow from module A"""
    db_config = get_database_config()  # Tainted from module_a
    eval(db_config)  # Vulnerable sink - SHOULD detect


# CF-C2: A->B->C taint flow (SHOULD detect)
def test_a_to_b_to_c():
    """SHOULD detect: Taint flow A->B->C"""
    propagated = propagate_db_config()  # Tainted from module_a via module_b
    exec(propagated)  # Vulnerable sink - SHOULD detect


# CF-C3: Multiple source combination (SHOULD detect)
def test_combined_sources():
    """SHOULD detect: Combined tainted sources"""
    combined = combine_tainted_sources()  # Multiple tainted sources via module_b
    os.system(combined)  # Vulnerable sink - SHOULD detect


# CF-C4: Class-based taint flow (SHOULD detect)
def test_class_taint():
    """SHOULD detect: Class-based taint flow"""
    class_data = propagate_class_taint()  # Tainted class data via module_b
    compile(class_data, "<string>", "exec")  # Vulnerable sink - SHOULD detect


# CF-C5: Safe data flow (should NOT detect)
def test_safe_flow():
    """Should NOT detect: Safe data flow"""
    safe_data = propagate_safe_data()  # Safe data via module_b
    eval(safe_data)  # Should NOT be flagged - safe data


# CF-C6: Mixed safe/tainted (SHOULD detect conservatively)
def test_mixed_flow():
    """SHOULD detect: Mixed safe/tainted data"""
    mixed = mix_safe_and_tainted()  # Mixed data via module_b
    exec(mixed)  # Should detect - conservative approach


# CF-C7: Local B taint (SHOULD detect)
def test_local_b_taint():
    """SHOULD detect: Local taint from module B"""
    local_taint = get_local_taint()  # Tainted locally in module_b
    eval(local_taint)  # SHOULD detect


# CF-C8: Complex processing chain (SHOULD detect)
def test_complex_chain():
    """SHOULD detect: Complex processing chain"""
    chain_result = complex_processing_chain()  # Complex tainted chain via module_b
    os.system(chain_result)  # SHOULD detect


# CF-C9: Class instance usage (SHOULD detect)
def test_class_instance():
    """SHOULD detect: Class instance taint"""
    instance_data = use_class_instance()  # Tainted via class instance
    exec(instance_data)  # SHOULD detect


# CF-C10: Multiple hops from A (SHOULD detect)
def test_multiple_hops():
    """SHOULD detect: Multiple hop taint flow"""
    user_args = propagate_user_args()  # A->B propagation
    local_processed = f"final_{user_args}"  # Local processing
    eval(local_processed)  # SHOULD detect original taint


# CF-C11: Safe direct from A (should NOT detect)
def test_safe_direct():
    """Should NOT detect: Safe data direct from A"""
    safe_from_a = get_safe_module_data()  # Safe from module_a
    version = get_version()  # Safe from module_a
    eval(f"{safe_from_a}_{version}")  # Should NOT detect


# CF-C12: False positive test (should NOT detect)
def test_false_positive():
    """Should NOT detect: No actual taint connection"""
    # Local variable with similar name but no connection
    local_db_config = "safe_local_config"
    eval(local_db_config)  # Should NOT detect


# CF-C13: String literal test (should NOT detect)
def test_string_literals():
    """Should NOT detect: String literals containing patterns"""
    eval("get_database_config()")  # Should NOT detect - literal string
    exec("os.environ")  # Should NOT detect - literal string


# CF-C14: Subprocess with tainted data (SHOULD detect)
def test_subprocess_taint():
    """SHOULD detect: Subprocess with tainted data"""
    tainted_cmd = propagate_db_config()  # Tainted via module_b
    subprocess.call(tainted_cmd, shell=True)  # SHOULD detect


# CF-C15: Complex multi-import scenario (SHOULD detect)
def test_multi_import():
    """SHOULD detect: Complex multi-import taint"""
    # Import from A
    direct_a = get_database_config()

    # Import from B (which imports from A)
    via_b = propagate_db_config()

    # Combine both
    combined = f"{direct_a}_{via_b}"
    eval(combined)  # SHOULD detect both flows


if __name__ == "__main__":
    print("Cross-file accuracy tests - testing complex multi-file taint flows")
