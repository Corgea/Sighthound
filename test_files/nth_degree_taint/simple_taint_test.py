# Simple taint test to validate pattern matching
import os
import subprocess


def test_direct_taint():
    """Direct taint flow - should be detected"""
    user_input = input("Enter command: ")  # SOURCE
    os.system(user_input)  # SINK - Should detect taint flow


def test_eval_taint():
    """Eval taint flow - should be detected"""
    user_data = input("Enter code: ")  # SOURCE
    eval(user_data)  # SINK - Should detect taint flow


def test_subprocess_taint():
    """Subprocess taint flow - should be detected"""
    user_cmd = input("Enter subprocess command: ")  # SOURCE
    subprocess.run(user_cmd, shell=True)  # SINK - Should detect taint flow


if __name__ == "__main__":
    print("Simple taint test - validating pattern matching")
    test_direct_taint()
    test_eval_taint()
    test_subprocess_taint()
