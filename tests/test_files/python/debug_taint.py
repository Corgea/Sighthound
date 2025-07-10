#!/usr/bin/env python3
"""
Debug test file for taint analysis pattern matching
"""

import os
import sys


def test_simple_taint():
    # Simple taint source
    user_input = os.environ.get("USER_DATA")

    # Simple taint sink
    eval(user_input)


def test_complex_taint():
    # Complex taint source
    db_config = os.environ.get("DATABASE_CONFIG", "")

    # Complex taint sink
    os.system(f"echo {db_config}")


if __name__ == "__main__":
    test_simple_taint()
    test_complex_taint()
