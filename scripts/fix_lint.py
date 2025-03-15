#!/usr/bin/env python
"""Script to fix common lint issues."""

import os
import re
import sys
from pathlib import Path

def fix_trailing_whitespace(file_path):
    """Remove trailing whitespace and ensure files end with a newline."""
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()

    # Remove trailing whitespace
    fixed_content = re.sub(r'[ \t]+$', '', content, flags=re.MULTILINE)

    # Ensure the file ends with a single newline
    if not fixed_content.endswith('\n'):
        fixed_content += '\n'
    elif fixed_content.endswith('\n\n'):
        fixed_content = fixed_content.rstrip('\n') + '\n'

    if content != fixed_content:
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(fixed_content)
        print(f"Fixed whitespace issues in {file_path}")

def fix_blank_lines(file_path):
    """Remove whitespace from blank lines."""
    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    fixed_lines = []
    modified = False

    for line in lines:
        if line.strip() == '' and line.rstrip('\n') != '':
            fixed_lines.append('\n')
            modified = True
        else:
            fixed_lines.append(line)

    if modified:
        with open(file_path, 'w', encoding='utf-8') as file:
            file.writelines(fixed_lines)
        print(f"Fixed blank lines in {file_path}")

def process_files(base_dir=None):
    """Process Python files in the specified directory."""
    if base_dir is None:
        base_dir = os.getcwd()

    python_files = []

    # Find all Python files
    for root, _, files in os.walk(base_dir):
        for file in files:
            if file.endswith('.py'):
                path = os.path.join(root, file)
                if (
                    not path.startswith('./venv') and
                    not path.startswith('./env') and
                    not path.startswith('./build')
                ):
                    python_files.append(path)

    # Apply fixes
    for file_path in python_files:
        fix_trailing_whitespace(file_path)
        fix_blank_lines(file_path)

def main():
    """Main function."""
    if len(sys.argv) > 1:
        process_files(sys.argv[1])
    else:
        process_files()
    print("Whitespace issues fixed. Run flake8 to check for remaining issues.")

if __name__ == "__main__":
    main()
