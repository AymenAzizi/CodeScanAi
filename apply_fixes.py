#!/usr/bin/env python3
"""
Script to apply security fixes to JavaScript files.
"""

import os
import sys
import re

def fix_sql_injection(file_path):
    """
    Fix SQL injection vulnerabilities in JavaScript files.
    
    Args:
        file_path (str): Path to the JavaScript file.
    
    Returns:
        bool: True if fixes were applied, False otherwise.
    """
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} does not exist.")
        return False
    
    # Read the file
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    
    # Fix SQL injection vulnerabilities
    # Pattern 1: String concatenation in queries
    pattern1 = r'connection\.query\(\s*[\'"]SELECT\s+\*\s+FROM\s+users\s+WHERE\s+id\s*=\s*[\'"]\s*\+\s*userId\s*\+\s*[\'"]'
    replacement1 = r'connection.query(\'SELECT * FROM users WHERE id = ?\', [userId]'
    
    # Pattern 2: String concatenation in queries with backticks
    pattern2 = r'connection\.query\(\s*`SELECT\s+\*\s+FROM\s+users\s+WHERE\s+username\s*=\s*\$\{username\}`'
    replacement2 = r'connection.query(\'SELECT * FROM users WHERE username = ?\', [username]'
    
    # Apply fixes
    new_content = re.sub(pattern1, replacement1, content)
    new_content = re.sub(pattern2, replacement2, new_content)
    
    # Check if any changes were made
    if new_content == content:
        print(f"No SQL injection vulnerabilities found in {file_path}.")
        return False
    
    # Write the fixed content back to the file
    with open(file_path, 'w', encoding='utf-8', errors='replace') as f:
        f.write(new_content)
    
    print(f"Fixed SQL injection vulnerabilities in {file_path}.")
    return True

def main():
    """
    Main function.
    """
    if len(sys.argv) < 2:
        print("Usage: python apply_fixes.py <file_path>")
        return
    
    file_path = sys.argv[1]
    fix_sql_injection(file_path)

if __name__ == "__main__":
    main()
