from django.http import HttpResponse
from django.shortcuts import render
import pickle


# XSS vulnerability - should be detected by xss_prevention.ron
def unsafe_response(request):
    user_input = request.GET.get("data", "")
    return HttpResponse(user_input)  # Direct user input to response - XSS risk


# SQL injection vulnerability - should be detected by sql_injection.ron
def unsafe_query(request):
    from django.db import connection

    user_id = request.GET.get("id", "")
    cursor = connection.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"  # String formatting - SQL injection risk
    cursor.execute(query)
    return cursor.fetchall()


# Unsafe deserialization - should be detected by deserialization.ron
def unsafe_unpickle(request):
    data = request.POST.get("data", "")
    return pickle.loads(data)  # Pickle with user input - deserialization attack


# Code injection - should be detected by test rule
def unsafe_eval(request):
    user_code = request.POST.get("code", "")
    return eval(user_code)  # Code injection via eval


# Hardcoded secret - should be detected by security_settings.ron
SECRET_KEY = "django-insecure-hardcoded-secret-key-123456789"  # Hardcoded secret
