import os
import subprocess
import sys

def run_command(command):
    """Run a command and return its output."""
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {command}")
        print(f"Error message: {e.stderr}")
        return None

def push_to_github():
    """Push the current project to GitHub."""
    # Check if we're in a Git repository
    if not os.path.exists('.git'):
        print("Initializing Git repository...")
        run_command('git init')
    
    # Configure Git if needed
    print("Configuring Git...")
    username = input("Enter your GitHub username: ")
    email = input("Enter your GitHub email: ")
    
    run_command(f'git config user.name "{username}"')
    run_command(f'git config user.email "{email}"')
    
    # Add the remote repository
    print("Adding remote repository...")
    run_command('git remote remove origin')  # Remove if exists
    run_command('git remote add origin https://github.com/AymenAzizi/AI-security-fix.git')
    
    # Add all files
    print("Adding files to Git...")
    run_command('git add .')
    
    # Commit changes
    print("Committing changes...")
    commit_message = input("Enter commit message: ")
    run_command(f'git commit -m "{commit_message}"')
    
    # Push to GitHub
    print("Pushing to GitHub...")
    run_command('git push -u origin main --force')
    
    print("Done! Your code has been pushed to GitHub.")

if __name__ == "__main__":
    push_to_github()
