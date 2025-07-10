import os

# This should trigger a vulnerability
user_input = input("Enter command: ")
os.system(user_input)
