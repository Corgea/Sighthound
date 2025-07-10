#!/usr/bin/env python3

import os
import subprocess
import sqlite3


# SQL Injection vulnerability
def get_user(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"  # Vulnerable to SQL injection
    cursor.execute(query)
    return cursor.fetchone()


# Command injection vulnerability
def run_command(user_input):
    cmd = f"ls -la {user_input}"  # Vulnerable to command injection
    return subprocess.call(cmd, shell=True)


# Path traversal vulnerability
def read_file(filename):
    filepath = f"/var/www/uploads/{filename}"  # Vulnerable to path traversal
    with open(filepath, "r") as f:
        return f.read()


# Weak random generation
import random


def generate_password():
    return str(random.randint(100000, 999999))  # Weak random generation


# Hardcoded secret
API_KEY = "sk-1234567890abcdef"  # Hardcoded secret


# Safe patterns (should not trigger)
def safe_query(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    )  # Safe parameterized query
    return cursor.fetchone()


if __name__ == "__main__":
    print("Test file with vulnerabilities")
