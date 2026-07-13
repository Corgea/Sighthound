import os


def execute_user_command(cmd):
    result = os.system(f"bash -c '{cmd}'")
    return result


def unsafe_eval(user_input):
    return eval(user_input)


def process_file(filename):
    path = f"../data/{filename}"
    with open(path) as f:
        return f.read()


user_input = input("Enter command: ")
os.system(user_input)
