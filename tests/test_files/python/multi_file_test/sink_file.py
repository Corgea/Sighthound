#!/usr/bin/env python3
"""
Sink file that uses tainted data from source_file.py
"""

import os
import subprocess
from source_file import get_user_input, get_config, UserInputProvider


def vulnerable_command():
    """Uses tainted data from another file in a vulnerable way"""
    user_input = get_user_input()  # Tainted data from source_file.py
    os.system(user_input)  # Vulnerable sink


def vulnerable_config():
    """Uses tainted config from another file"""
    config = get_config()  # Tainted data from source_file.py
    eval(config)  # Vulnerable sink


def vulnerable_class_usage():
    """Uses tainted data from a class in another file"""
    provider = UserInputProvider()  # Contains tainted data
    data = provider.get_data()  # Tainted data
    subprocess.call(data, shell=True)  # Vulnerable sink


def complex_flow():
    """Complex flow through multiple variables"""
    raw_input = get_user_input()  # Tainted source from other file
    processed_input = raw_input.upper()  # Local propagation
    command = f"echo {processed_input}"  # String formatting
    os.system(command)  # Vulnerable sink
