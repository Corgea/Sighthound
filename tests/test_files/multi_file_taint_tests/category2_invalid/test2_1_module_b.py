# Test 2.1: Phantom Flow - No Import Relationship - MODULE B
# Expected: Should NOT detect flow from module_a (NO IMPORT relationship exists)
# CRITICAL: This tests the core phantom flow bug that was fixed

import os
# NOTE: NO IMPORT from test2_1_module_a - this is intentional!


def dangerous_function():
    """
    SINK: This function has same variable name as module_a but NO connection
    The old broken system would incorrectly create a phantom flow here
    """
    # This variable has same name but NO connection to module_a
    user_data = "safe_constant"  # This is NOT the same variable from module_a
    os.system(user_data)  # Should NOT detect flow - different variable entirely


def legitimate_function():
    """
    A realistic function that could exist in this module
    """
    return "module_b_functionality"
