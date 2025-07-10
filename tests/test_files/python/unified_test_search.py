#!/usr/bin/env python3
"""
Test file for unified rule search mode patterns
"""

import sqlite3
import hashlib
from Crypto.Hash import MD5, SHA1
from Crypto.Cipher import DES, ARC4


def sql_injection_tests():
    """Test SQL injection patterns"""
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()

    # These should match the "execute" pattern
    cursor.execute("SELECT * FROM users WHERE id = 1")
    cursor.executemany("INSERT INTO users VALUES (?, ?)", [(1, "test")])

    # Direct connection execute
    conn.execute("DELETE FROM users WHERE id = 1")

    return "SQL tests done"


def weak_crypto_tests():
    """Test weak cryptography patterns"""

    # These should match weak hash patterns
    md5_hash = hashlib.md5(b"test data")
    sha1_hash = hashlib.sha1(b"test data")

    # Crypto library weak hashes
    md5_crypto = MD5.new()
    sha1_crypto = SHA1.new()

    # Weak ciphers
    des_cipher = DES.new(b"12345678", DES.MODE_ECB)
    arc4_cipher = ARC4.new(b"secret_key")

    return "Crypto tests done"


def complex_sql_injection():
    """More complex SQL injection scenarios"""
    database = sqlite3.connect(":memory:")
    db_cursor = database.cursor()

    # Should match cursor.execute pattern
    db_cursor.execute("CREATE TABLE test (id INTEGER, name TEXT)")

    # Should match executemany
    db_cursor.executemany("INSERT INTO test VALUES (?, ?)", [(1, "Alice"), (2, "Bob")])

    return "Complex SQL done"


if __name__ == "__main__":
    sql_injection_tests()
    weak_crypto_tests()
    complex_sql_injection()
    print("All search pattern tests completed")
