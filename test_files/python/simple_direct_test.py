#!/usr/bin/env python3
"""
Minimal test for direct variable taint analysis
"""

import os

# Simple taint source
user_input = os.environ.get("USER_DATA")

# Simple taint sink - direct usage
eval(user_input)
