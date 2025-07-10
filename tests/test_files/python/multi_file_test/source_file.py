#!/usr/bin/env python3
"""
Source file that provides tainted data to other files
"""

from flask import request


def get_user_input():
    """Function that returns tainted user input"""
    user_data = request.args.get("input", "")
    return user_data


def get_config():
    """Function that returns tainted config data"""
    import os

    config = os.environ.get("CONFIG", "")
    return config


class UserInputProvider:
    def __init__(self):
        self.data = request.form.get("data", "")

    def get_data(self):
        return self.data
