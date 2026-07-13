#!/usr/bin/env python3

import os
import subprocess
from taint_source import get_user_input, get_config, UserInputProvider


def vulnerable_command():
    user_input = get_user_input()
    os.system(user_input)


def vulnerable_config():
    config = get_config()
    eval(config)


def vulnerable_class_usage():
    provider = UserInputProvider()
    data = provider.get_data()
    subprocess.call(data, shell=True)


def complex_flow():
    raw_input = get_user_input()
    processed_input = raw_input.upper()
    command = f"echo {processed_input}"
    os.system(command)
