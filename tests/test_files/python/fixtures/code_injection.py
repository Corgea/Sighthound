#!/usr/bin/env python3

import os

user_input = os.environ.get("USER_DATA")

eval(user_input)
eval("print('hello')")

exec(user_input)
exec("print('hello')")

os.system(user_input)
