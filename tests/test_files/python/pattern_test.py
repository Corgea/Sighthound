#!/usr/bin/env python3
"""
Test file to debug pattern matching
"""

import os

# Test 1: Direct eval with tainted variable
user_input = os.environ.get("USER_DATA")
eval(user_input)

# Test 2: Direct eval with literal
eval("print('hello')")

# Test 3: Direct exec with tainted variable
exec(user_input)

# Test 4: Direct exec with literal
exec("print('hello')")
