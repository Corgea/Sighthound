from flask import Flask, request, render_template_string, jsonify
import subprocess
import os
import sqlite3
import requests
from lxml import etree

# Example hardcoded AWS credentials (sensitive data leakage)
aws_access_key_id = "AKIAFAKEKEY00000000"
aws_secret = "fake-secret-not-real-do-not-use-in-production"

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    output = ""
    # 1 - SQL Injection
    db = sqlite3.connect("tutorial.db")
    cursor = db.cursor()
    username = ""
    password = ""
    try:
        cursor.execute(
            "SELECT * FROM users WHERE username = '%s' AND password = '%s'"
            % (username, password)
        )
    except:
        pass

    return "test"
