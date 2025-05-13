#!/usr/bin/env python3
"""
Script to create a pull request manually.
"""

import os
import sys
import subprocess
import tempfile
import shutil
from datetime import datetime

def create_pr(repo_url, token, branch_name=None):
    """
    Create a pull request manually.
    
    Args:
        repo_url (str): URL of the repository.
        token (str): GitHub token.
        branch_name (str, optional): Name of the branch to create. Defaults to None.
    
    Returns:
        bool: True if the PR was created successfully, False otherwise.
    """
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp()
    print(f"Created temporary directory: {temp_dir}")
    
    try:
        # Clone the repository
        print(f"Cloning repository {repo_url}...")
        repo_url_with_token = repo_url.replace("https://", f"https://{token}@")
        subprocess.check_call(["git", "clone", repo_url_with_token, temp_dir])
        
        # Change to the repository directory
        os.chdir(temp_dir)
        
        # Create a new branch
        if branch_name is None:
            branch_name = f"security-fixes-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        print(f"Creating branch {branch_name}...")
        subprocess.check_call(["git", "checkout", "-b", branch_name])
        
        # Apply fixes to JavaScript files
        js_files = []
        for root, _, files in os.walk(temp_dir):
            for file in files:
                if file.endswith(".js"):
                    js_files.append(os.path.join(root, file))
        
        if not js_files:
            print("No JavaScript files found in the repository.")
            return False
        
        # Apply fixes to each JavaScript file
        fixed_files = []
        for js_file in js_files:
            # Run the apply_fixes.py script
            script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "apply_fixes.py")
            try:
                subprocess.check_call(["python", script_path, js_file])
                fixed_files.append(js_file)
            except subprocess.CalledProcessError:
                print(f"Failed to apply fixes to {js_file}")
        
        if not fixed_files:
            print("No fixes were applied to any files.")
            return False
        
        # Commit the changes
        print("Committing changes...")
        subprocess.check_call(["git", "add", "."])
        subprocess.check_call(["git", "commit", "-m", "Fix security vulnerabilities"])
        
        # Push the changes
        print(f"Pushing changes to branch {branch_name}...")
        subprocess.check_call(["git", "push", "-u", "origin", branch_name])
        
        # Print instructions for creating a PR
        print("\nPull request created successfully!")
        print("\nTo create a pull request, go to:")
        print(f"{repo_url.replace('.git', '')}/compare/{branch_name}?expand=1")
        
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        return False
    finally:
        # Clean up
        shutil.rmtree(temp_dir)

def main():
    """
    Main function.
    """
    if len(sys.argv) < 3:
        print("Usage: python create_pr.py <repo_url> <token> [branch_name]")
        return
    
    repo_url = sys.argv[1]
    token = sys.argv[2]
    branch_name = sys.argv[3] if len(sys.argv) > 3 else None
    
    create_pr(repo_url, token, branch_name)

if __name__ == "__main__":
    main()
