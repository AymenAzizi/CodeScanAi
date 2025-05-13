#!/usr/bin/env python
# Sample Python file with vulnerabilities

import os
import subprocess
import pickle
import yaml
import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Hardcoded credentials vulnerability
PASSWORD = "hardcoded_password"

@app.route('/user/<user_id>')
def get_user(user_id):
    # SQL Injection vulnerability
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id  # SQL Injection
    cursor.execute(query)
    user = cursor.fetchone()
    return str(user)

@app.route('/search')
def search():
    # Command injection vulnerability
    query = request.args.get('q')
    result = subprocess.check_output("grep " + query + " /var/log/app.log", shell=True)  # Command injection
    return result

@app.route('/template')
def template():
    # Server-side template injection vulnerability
    name = request.args.get('name')
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)  # Template injection

@app.route('/file')
def read_file():
    # Path traversal vulnerability
    filename = request.args.get('filename')
    with open(os.path.join('data', filename), 'r') as f:  # Path traversal
        content = f.read()
    return content

@app.route('/pickle')
def pickle_data():
    # Insecure deserialization vulnerability
    data = request.args.get('data')
    obj = pickle.loads(data.encode('utf-8'))  # Insecure deserialization
    return str(obj)

@app.route('/yaml')
def yaml_load():
    # YAML deserialization vulnerability
    data = request.args.get('data')
    obj = yaml.load(data)  # YAML deserialization vulnerability
    return str(obj)

if __name__ == '__main__':
    app.run(debug=True)  # Debug mode enabled in production
