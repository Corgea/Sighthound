#!/usr/bin/env python3
"""
EDGE CASES: Complex cross-file scenarios testing analysis accuracy
"""

import os
from tricky_source import (
    get_user_data,
    get_safe_data,
    get_conditional_data,
    get_nested_data,
    get_multi_return,
    get_reassigned_data,
    get_mixed_data,
    get_comment_test,
    get_aliased_data,
)


# EC1: Should detect tainted, NOT detect safe (same variable name)
def test_variable_scope():
    """Should detect tainted user_data, NOT safe user_data"""
    tainted_data = get_user_data()  # Tainted - SHOULD detect
    eval(tainted_data)

    safe_data = get_safe_data()  # Safe - should NOT detect
    eval(safe_data)


# EC2: Conditional flows - should detect potential taint
def test_conditional():
    """Should detect conditional taint"""
    cond_data = get_conditional_data(True)  # Could be tainted - SHOULD detect
    exec(cond_data)


# EC3: Nested function taint - should detect
def test_nested():
    """Should detect nested taint"""
    nested_data = get_nested_data()  # Tainted - SHOULD detect
    eval(nested_data)


# EC4: Multiple return paths - should detect tainted paths
def test_multi_return():
    """Should detect multiple tainted paths"""
    data1 = get_multi_return(1)  # Tainted - SHOULD detect
    eval(data1)

    data2 = get_multi_return(2)  # Safe - should NOT detect
    eval(data2)

    data3 = get_multi_return(3)  # Tainted - SHOULD detect
    eval(data3)


# EC5: Variable reassignment - should detect final tainted state
def test_reassignment():
    """Should detect reassigned tainted variable"""
    reassigned = get_reassigned_data()  # Tainted - SHOULD detect
    exec(reassigned)


# EC6: Mixed data - should detect (conservatively tainted)
def test_mixed():
    """Should detect mixed safe/tainted data"""
    mixed = get_mixed_data()  # Tainted - SHOULD detect
    eval(mixed)


# EC7: Comments should NOT confuse parser
def test_comments():
    """Should NOT detect (safe data despite comments)"""
    comment_data = get_comment_test()  # Safe - should NOT detect
    # This eval() call should not be flagged
    eval(comment_data)


# EC8: Aliased variables - should detect
def test_aliasing():
    """Should detect aliased tainted data"""
    aliased = get_aliased_data()  # Tainted via alias - SHOULD detect
    exec(aliased)


# EC9: False positive test - similar names but no connection
def test_false_positive():
    """Should NOT detect - no actual connection"""
    # These have similar variable names but no taint connection
    local_user_data = "safe_local_data"  # No connection to get_user_data()
    eval(local_user_data)  # Should NOT be flagged


# EC10: String literals containing taint patterns (should NOT detect)
def test_string_literals():
    """Should NOT detect - string literals"""
    # These are just string literals, not actual taint
    eval("os.environ")  # Should NOT detect - literal string
    exec("sys.argv")  # Should NOT detect - literal string


# EC11: Variable name confusion (should be precise)
def test_name_confusion():
    """Should be precise about variable identity"""
    user_data = "safe_local"  # Local safe variable
    safe_data = get_safe_data()  # Safe function result

    eval(user_data)  # Should NOT detect - local safe
    eval(safe_data)  # Should NOT detect - safe function


# EC12: Complex assignment chains
def test_assignment_chain():
    """Should track through assignment chains"""
    step1 = get_user_data()  # Tainted
    step2 = step1  # Still tainted
    step3 = step2  # Still tainted
    eval(step3)  # SHOULD detect - tainted through chain


if __name__ == "__main__":
    print("Edge case tests for analysis accuracy")
