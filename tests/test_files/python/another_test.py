import subprocess
import os


def execute_user_command(cmd):
    # Command injection vulnerability
    result = os.system(f"bash -c '{cmd}'")
    return result


def unsafe_eval(user_input):
    # Code injection vulnerability
    return eval(user_input)


def process_file(filename):
    # Path traversal vulnerability
    path = f"../data/{filename}"
    with open(path) as f:
        return f.read()
