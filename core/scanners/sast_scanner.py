"""
This module provides SAST (Static Application Security Testing) scanning capabilities.
It integrates with Bandit for Python code scanning.
"""

import json
import logging
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

@dataclass
class Vulnerability:
    """
    Represents a security vulnerability found in code.
    """
    id: str
    severity: str
    confidence: str
    file_path: str
    line_number: int
    description: str
    code: str
    cwe: Optional[str] = None
    fix_suggestion: Optional[str] = None


class SASTScanner:
    """
    Base class for SAST scanners.
    """

    def scan_directory(self, directory: str) -> List[Vulnerability]:
        """
        Scan a directory for security vulnerabilities.

        Args:
            directory (str): Path to the directory to scan.

        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        raise NotImplementedError("Subclasses must implement this method")


class BanditScanner(SASTScanner):
    """
    SAST scanner that uses Bandit for Python code.
    """

    def __init__(self):
        """
        Initialize the Bandit scanner.
        """
        self._check_bandit_installed()

    def _check_bandit_installed(self):
        """
        Check if Bandit is installed, and install it if not.
        """
        try:
            import bandit
            logging.info("Bandit is already installed")
        except ImportError:
            logging.info("Installing Bandit...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "bandit"])
                logging.info("Bandit installed successfully")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to install Bandit: {e}")
                raise RuntimeError("Failed to install Bandit. Please install it manually with 'pip install bandit'.")

    def scan_directory(self, directory: str) -> List[Vulnerability]:
        """
        Scan a directory for security vulnerabilities using Bandit.

        Args:
            directory (str): Path to the directory to scan.

        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        logging.info(f"Scanning directory {directory} with Bandit...")

        # Create a temporary file to store the JSON output
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_file:
            temp_path = temp_file.name

        try:
            # Use bandit as a Python module instead of command line
            import bandit.cli.main as bandit_main
            import sys

            # Save the original sys.argv
            original_argv = sys.argv.copy()

            # Set up the arguments for bandit
            sys.argv = [
                'bandit',
                '-r',  # Recursive
                '-f', 'json',  # JSON output format
                '-o', temp_path,  # Output file
                directory  # Directory to scan
            ]

            try:
                # Run bandit
                bandit_main.main()
            except SystemExit:
                # Bandit calls sys.exit(), which we need to catch
                pass
            finally:
                # Restore the original sys.argv
                sys.argv = original_argv

            # Parse the JSON output
            with open(temp_path, 'r') as f:
                results = json.load(f)

            # Convert Bandit results to Vulnerability objects
            vulnerabilities = self._parse_bandit_results(results, directory)

            logging.info(f"Found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities

        except Exception as e:
            logging.error(f"Error running Bandit: {e}")
            # Try to parse any output that might have been produced
            try:
                with open(temp_path, 'r') as f:
                    results = json.load(f)
                vulnerabilities = self._parse_bandit_results(results, directory)
                logging.info(f"Found {len(vulnerabilities)} vulnerabilities despite error")
                return vulnerabilities
            except (json.JSONDecodeError, FileNotFoundError):
                logging.error("No valid output from Bandit")
                return []
        finally:
            # Clean up the temporary file
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def _parse_bandit_results(self, results: Dict[str, Any], base_dir: str) -> List[Vulnerability]:
        """
        Parse Bandit JSON results into Vulnerability objects.

        Args:
            results (Dict[str, Any]): Bandit JSON results.
            base_dir (str): Base directory of the scan.

        Returns:
            List[Vulnerability]: List of parsed vulnerabilities.
        """
        vulnerabilities = []

        for result in results.get('results', []):
            # Make file path relative to base directory
            file_path = result.get('filename', '')
            if file_path.startswith(base_dir):
                file_path = os.path.relpath(file_path, base_dir)

            vuln = Vulnerability(
                id=f"BANDIT-{result.get('test_id', 'UNKNOWN')}",
                severity=result.get('issue_severity', 'UNKNOWN').upper(),
                confidence=result.get('issue_confidence', 'UNKNOWN').upper(),
                file_path=file_path,
                line_number=result.get('line_number', 0),
                description=result.get('issue_text', 'No description available'),
                code=result.get('code', 'No code available'),
                cwe=result.get('cwe', None)
            )
            vulnerabilities.append(vuln)

        return vulnerabilities


# Factory function to get the appropriate scanner based on file type
def get_scanner_for_file_type(file_type: str) -> SASTScanner:
    """
    Get the appropriate scanner for a given file type.

    Args:
        file_type (str): File extension (e.g., 'py', 'js').

    Returns:
        SASTScanner: Appropriate scanner for the file type.
    """
    if file_type.lower() == 'py':
        return BanditScanner()
    # Add more scanners for other file types here
    else:
        logging.warning(f"No specific scanner available for file type '{file_type}'. Using Bandit as fallback.")
        return BanditScanner()


# Function to scan a directory with the appropriate scanner based on file types
def scan_directory(directory: str) -> List[Vulnerability]:
    """
    Scan a directory with the appropriate scanner based on file types.

    Args:
        directory (str): Path to the directory to scan.

    Returns:
        List[Vulnerability]: List of found vulnerabilities.
    """
    # For now, we'll just use Bandit for all files
    scanner = BanditScanner()
    return scanner.scan_directory(directory)
