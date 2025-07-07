import sqlite3

cursor = sqlite3.connect("test.db").cursor()
cursor.execute("SELECT * FROM users WHERE username = '%s'" % "test")
