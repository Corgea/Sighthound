#!/usr/bin/env python3
"""
Debug string matching test
"""

import os

# Test 1: Simple eval
user_input = os.environ.get("USER_DATA")
eval(user_input)

# Test 2: Simple exec
exec(user_input)

# Test 3: Simple os.system
os.system(user_input)
