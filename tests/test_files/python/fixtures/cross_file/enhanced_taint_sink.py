#!/usr/bin/env python3

import os
from enhanced_taint_source import (
    get_user_input,
    get_environment_config,
    get_network_data,
    process_user_data,
)


def vulnerable_eval_cross_file():
    config = get_environment_config()
    eval(config)


def vulnerable_exec_cross_file():
    user_data = get_user_input()
    exec(user_data)


def vulnerable_system_cross_file():
    network_data = get_network_data()
    os.system(network_data)


def complex_cross_file_flow():
    raw_data = get_user_input()
    processed = process_user_data(raw_data)
    eval(processed)


def local_vulnerable_function():
    local_input = os.environ.get("LOCAL_VAR", "")
    eval(local_input)
