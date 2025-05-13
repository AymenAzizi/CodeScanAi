# This file contains intentional security vulnerabilities for testing SAST scanning

import os
import subprocess
import pickle
import yaml

# Command Injection vulnerability
def run_command(user_input):
    os.system("echo " + user_input)  # Vulnerable to command injection

# Unsafe deserialization
def load_pickle_data(filename):
    with open(filename, 'rb') as f:
        return pickle.load(f)  # Vulnerable to unsafe deserialization

# Unsafe YAML loading
def load_yaml_data(filename):
    with open(filename, 'r') as f:
        return yaml.load(f)  # Vulnerable to YAML deserialization attacks

# SQL Injection vulnerability
def get_user(user_id):
    import sqlite3
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)  # Vulnerable to SQL injection
    return cursor.fetchone()

# Hardcoded credentials
def connect_to_database():
    password = "super_secret_password"  # Hardcoded credentials
    username = "admin"
    return {"username": username, "password": password}

# Path traversal vulnerability
def read_file(filename):
    with open(filename, 'r') as f:  # Vulnerable to path traversal
        return f.read()

if __name__ == "__main__":
    print("This file contains intentional security vulnerabilities for testing SAST scanning")
