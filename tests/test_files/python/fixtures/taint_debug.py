#!/usr/bin/env python3

import os


def simple_taint_flow():
    user_input = os.environ.get("USER_DATA")
    eval(user_input)


def complex_taint_flow():
    db_config = os.environ.get("DATABASE_CONFIG", "")
    os.system(f"echo {db_config}")
