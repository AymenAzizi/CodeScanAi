"""
A test file with a SQL injection vulnerability.
"""

import sqlite3

def get_user(user_id):
    """
    Get a user from the database.
    
    This function has a SQL injection vulnerability.
    """
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Vulnerable SQL query - using string concatenation
    query = "SELECT * FROM users WHERE id = " + user_id
    
    cursor.execute(query)
    result = cursor.fetchone()
    
    conn.close()
    return result

def main():
    """Main function."""
    user_id = input("Enter user ID: ")
    user = get_user(user_id)
    print(f"User: {user}")

if __name__ == "__main__":
    main()
