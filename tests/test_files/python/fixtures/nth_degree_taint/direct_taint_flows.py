import os
import subprocess


def direct_taint_flow():
    user_input = input("Enter command: ")
    os.system(user_input)


def eval_taint_flow():
    user_data = input("Enter code: ")
    eval(user_data)


def subprocess_taint_flow():
    user_cmd = input("Enter subprocess command: ")
    subprocess.run(user_cmd, shell=True)
