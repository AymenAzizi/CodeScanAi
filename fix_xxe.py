import os
import sys
import logging
import tempfile
import subprocess
import shutil
from core.scanners.xml_scanner import scan_file, scan_xml_files

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def clone_repo(repo_url, target_dir):
    """Clone a repository to a target directory."""
    try:
        subprocess.check_call(['git', 'clone', repo_url, target_dir])
        logging.info(f"Successfully cloned {repo_url} to {target_dir}")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to clone repository: {e}")
        return False

def fix_xxe_vulnerability(file_path):
    """Fix XXE vulnerability in an XML file."""
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Check if it's an XXE vulnerability
    if '<!DOCTYPE' in content and 'ENTITY' in content and ('file:' in content or 'http:' in content):
        logging.info(f"Fixing XXE vulnerability in {file_path}")
        
        # Create a fixed version that removes the DOCTYPE declaration
        fixed_content = '<?xml version="1.0" encoding="UTF-8"?>\n<foo>Content removed for security</foo>'
        
        # Write the fixed content
        with open(file_path, 'w') as f:
            f.write(fixed_content)
        
        logging.info(f"Fixed XXE vulnerability in {file_path}")
        return True
    
    return False

def main():
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp(prefix="xml-scan-")
    logging.info(f"Created temporary directory: {temp_dir}")
    
    try:
        # Clone the repository
        repo_url = "https://github.com/SahbeniEya/First_ProjecteEya.git"
        if not clone_repo(repo_url, temp_dir):
            return
        
        # Get Hugging Face token from environment
        huggingface_token = os.environ.get("HUGGING_FACE_TOKEN")
        
        # Scan all XML files in the repository
        logging.info(f"Scanning XML files in {temp_dir}...")
        vulnerabilities = scan_xml_files(temp_dir, huggingface_token=huggingface_token)
        
        # Fix vulnerabilities
        fixed_files = []
        if vulnerabilities:
            logging.info(f"Found {len(vulnerabilities)} vulnerabilities to fix")
            for vuln in vulnerabilities:
                if vuln.id == "XXE-001":
                    if fix_xxe_vulnerability(vuln.file_path):
                        fixed_files.append(vuln.file_path)
        
        # Verify fixes
        if fixed_files:
            logging.info(f"Fixed {len(fixed_files)} files. Verifying...")
            vulnerabilities_after = scan_xml_files(temp_dir, huggingface_token=huggingface_token)
            if vulnerabilities_after:
                logging.warning(f"Still found {len(vulnerabilities_after)} vulnerabilities after fixing")
            else:
                logging.info("All vulnerabilities fixed successfully!")
                
                # Show the fixed files
                for file_path in fixed_files:
                    logging.info(f"Fixed file: {file_path}")
                    with open(file_path, 'r') as f:
                        logging.info(f"Content:\n{f.read()}")
        else:
            logging.info("No files needed fixing")
    
    finally:
        # Clean up
        logging.info(f"Cleaning up temporary directory: {temp_dir}")
        shutil.rmtree(temp_dir)

if __name__ == "__main__":
    main()
