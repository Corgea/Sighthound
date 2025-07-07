import unittest
import pytest
from django.test import TestCase


class MyTestCase(unittest.TestCase):
    def test_something(self):
        # This should be filtered out in general scanning
        # but included in malicious scanning
        user_input = "malicious'; DROP TABLE users; --"
        query = f"SELECT * FROM users WHERE name = '{user_input}'"
        self.assertEqual(query, "test")
