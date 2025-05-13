#!/usr/bin/env python3

import argparse
import logging
import re
import os
import sys
from pygments import highlight
from pygments.lexers import get_lexer_for_filename, guess_lexer
from pygments.formatters import Terminal256Formatter

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define regular expressions for common secrets
PATTERNS = {
    "API Key": r"[a-zA-Z0-9]{32,45}",  # Example: Long alphanumeric string
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Access Key": r"AKIA[0-9A-Z]{16}.*?[\r\n].*?[a-zA-Z0-9/+=]{40}",
    "Secret Key": r"sk-[a-zA-Z0-9]{48}",
    "Password": r"(password|pwd|pass)\s*[:=]\s*['\"]?[\w\d@#$%^&*()_+{}\[\]:;<>,.?\/~\\-]{6,}['\"]?",
}


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="Scans code for accidentally committed secrets.")
    parser.add_argument("path", help="Path to the file or directory to scan.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    parser.add_argument("-e", "--exclude", help="Comma-separated list of file extensions to exclude (e.g., .txt,.log).", default="")
    return parser


def scan_file(file_path, exclude_extensions):
    """
    Scans a single file for secrets using predefined patterns.

    Args:
        file_path (str): The path to the file to scan.
        exclude_extensions (list): A list of file extensions to exclude.

    Returns:
        list: A list of dictionaries, each representing a detected secret.
    """
    if any(file_path.endswith(ext) for ext in exclude_extensions):
        logging.debug(f"Skipping file due to extension: {file_path}")
        return []

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except UnicodeDecodeError as e:
        logging.warning(f"Could not decode file {file_path}: {e}")
        return []
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
        return []

    secrets = []
    for name, pattern in PATTERNS.items():
        try:
            matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
            for match in matches:
                secret = {
                    "file": file_path,
                    "name": name,
                    "match": match.group(0),
                    "start": match.start(),
                    "end": match.end(),
                }
                secrets.append(secret)
        except re.error as e:
            logging.error(f"Regex error for pattern '{name}': {e}")

    return secrets


def scan_directory(dir_path, exclude_extensions):
    """
    Recursively scans a directory for secrets.

    Args:
        dir_path (str): The path to the directory to scan.
        exclude_extensions (list): A list of file extensions to exclude.

    Returns:
        list: A list of dictionaries, each representing a detected secret.
    """
    secrets = []
    for root, _, files in os.walk(dir_path):
        for file in files:
            file_path = os.path.join(root, file)
            secrets.extend(scan_file(file_path, exclude_extensions))
    return secrets


def highlight_code(file_path, secret):
    """
    Highlights the code snippet containing the secret using Pygments.

    Args:
        file_path (str): The path to the file containing the secret.
        secret (dict): A dictionary containing information about the secret.

    Returns:
        str: The highlighted code snippet, or an empty string if an error occurs.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        try:
            lexer = get_lexer_for_filename(file_path)
        except Exception:
            try:
                lexer = guess_lexer(content)
            except Exception:
                lexer = None

        if lexer:
            formatter = Terminal256Formatter(style='fruity')  # Choose a style
            snippet_start = max(0, secret["start"] - 100)
            snippet_end = min(len(content), secret["end"] + 100)
            snippet = content[snippet_start:snippet_end]
            highlighted_code = highlight(snippet, lexer, formatter)
            return highlighted_code
        else:
            return f"No lexer found for {file_path}.  Plain text snippet:\n{content[max(0, secret['start'] - 50):min(len(content), secret['end'] + 50)]}"
    except Exception as e:
        logging.error(f"Error highlighting code for {file_path}: {e}")
        return ""


def main():
    """
    Main function to parse arguments and initiate the scanning process.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    path = args.path
    exclude_extensions = [ext.strip() for ext in args.exclude.split(",") if ext.strip()]

    if not os.path.exists(path):
        logging.error(f"Path does not exist: {path}")
        sys.exit(1)

    if os.path.isfile(path):
        logging.info(f"Scanning file: {path}")
        secrets = scan_file(path, exclude_extensions)
    elif os.path.isdir(path):
        logging.info(f"Scanning directory: {path}")
        secrets = scan_directory(path, exclude_extensions)
    else:
        logging.error(f"Invalid path: {path}. Must be a file or directory.")
        sys.exit(1)

    if secrets:
        print("Potential secrets found:")
        for secret in secrets:
            print(f"  File: {secret['file']}")
            print(f"  Type: {secret['name']}")
            print(f"  Match: {secret['match']}")
            highlighted_code = highlight_code(secret["file"], secret)
            if highlighted_code:
                print("  Code Snippet:\n")
                print(highlighted_code)
            print("-" * 40)
    else:
        print("No secrets found.")

if __name__ == "__main__":
    main()