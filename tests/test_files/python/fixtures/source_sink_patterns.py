#!/usr/bin/env python3
"""
Test file for source and sink detection in search-based findings
"""

import os
import sqlite3
import hashlib
from flask import Flask, request

app = Flask(__name__)


def scenario_sources_with_crypto():
    """Test cases where sources feed into crypto sinks"""

    # Source: user input via request
    user_password = request.args.get("password")

    # Sink: weak crypto
    weak_hash = hashlib.md5(user_password.encode())

    return weak_hash.hexdigest()


def scenario_sources_with_sql():
    """Test cases where sources feed into SQL sinks"""

    # Source: user input via request
    user_id = request.args.get("id")

    # Sink: SQL execution
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

    return cursor.fetchall()


def scenario_environment_source():
    """Test environment variable as source"""

    # Source: environment variable
    config_value = os.environ.get("CONFIG")

    # Sink: weak crypto
    hash_result = hashlib.sha1(config_value.encode())

    return hash_result


def scenario_input_source():
    """Test direct input as source"""

    # Source: user input
    user_data = input("Enter data: ")

    # Sink: weak crypto
    result = hashlib.md5(user_data.encode())

    return result


def scenario_multiple_sources():
    """Test multiple sources in same function"""

    # Source 1: request parameter
    param1 = request.form.get("param1")

    # Source 2: environment
    param2 = os.environ.get("PARAM2")

    # Combine sources
    combined = param1 + param2

    # Sink: weak crypto
    final_hash = hashlib.sha1(combined.encode())

    return final_hash


def scenario_no_source():
    """Test sink without obvious source (should only show sink)"""

    # No source - just literal data
    literal_data = "static_string"

    # Sink: weak crypto
    hash_result = hashlib.md5(literal_data.encode())

    return hash_result


if __name__ == "__main__":
    print("Source and sink detection test")
