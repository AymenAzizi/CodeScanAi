import logging
import sys
from core.scanners.dast_scanner import scan_url

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def main():
    # URL to scan
    url = "http://testphp.vulnweb.com/"
    
    # Run DAST scan with basic scanner
    logging.info(f"Running DAST scan on {url}")
    vulnerabilities = scan_url(url, use_basic_scanner=True)
    
    # Print results
    logging.info(f"Found {len(vulnerabilities)} vulnerabilities")
    
    # Print each vulnerability
    for i, vuln in enumerate(vulnerabilities, 1):
        print(f"\n--- Vulnerability {i} ---")
        print(f"ID: {vuln.id}")
        print(f"Severity: {vuln.severity}")
        print(f"Confidence: {vuln.confidence}")
        print(f"Description: {vuln.description}")
        print(f"URL: {vuln.file_path}")
        print(f"Code: {vuln.code}")
        print(f"Fix: {vuln.fix_suggestion}")
        print("-" * 50)

if __name__ == "__main__":
    main()
