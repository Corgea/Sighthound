import os


def vulnerable_function(user_input):
    # This should trigger command injection
    os.system(user_input)

    # This should trigger code injection
    eval(user_input)
