#!/usr/bin/env python
"""Script to remove unused imports detected by flake8."""

import os
import re
import subprocess
import sys


def get_unused_imports():
    """Run flake8 and extract unused import errors."""
    try:
        flake8_output = subprocess.check_output(
            ["flake8", "sentinelprobe", "tests"], text=True
        )
    except subprocess.CalledProcessError as e:
        # When flake8 finds errors, it returns a non-zero exit code
        # We still want to use its output
        flake8_output = e.output

    import_errors = []
    for line in flake8_output.split("\n"):
        if "F401" in line:
            error_parts = line.split()
            if len(error_parts) < 2:
                continue

            file_location = error_parts[0].split(":")
            if len(file_location) < 2:
                continue

            file_path = file_location[0]
            try:
                line_num = int(file_location[1])
                import_match = re.search(r"'([^']+)'", line)
                if import_match:
                    import_name = import_match.group(1)
                    import_errors.append((file_path, line_num, import_name))
            except (ValueError, IndexError):
                pass

    return import_errors


def remove_unused_imports(file_path, imports_to_remove):
    """Remove unused imports from a file."""
    with open(file_path, "r", encoding="utf-8") as file:
        lines = file.readlines()

    # Group imports by line number
    imports_by_line = {}
    for _, line_num, import_name in imports_to_remove:
        if line_num not in imports_by_line:
            imports_by_line[line_num] = []
        imports_by_line[line_num].append(import_name)

    modified = False
    for line_num, imports in imports_by_line.items():
        # Line numbers are 1-indexed
        line_idx = line_num - 1
        if line_idx >= len(lines):
            continue

        line = lines[line_idx]

        # Handle different import formats
        for import_name in imports:
            # Print what we're trying to remove for debugging
            print(
                f"Trying to remove '{import_name}' from line {line_num}: {line.strip()}"
            )

            if re.search(rf"^from\s+.+\s+import\s+.*{re.escape(import_name)}.*$", line):
                # Handle 'from module import name1, name2, name3'
                parts = line.split(" import ")
                module = parts[0]
                imports_str = parts[1]

                # Handle imports with trailing comma
                if f"{import_name}," in imports_str:
                    new_imports = re.sub(
                        rf"{re.escape(import_name)},\s*", "", imports_str
                    )
                # Handle imports without trailing comma but with preceding comma
                elif re.search(rf",\s*{re.escape(import_name)}(\s|$)", imports_str):
                    new_imports = re.sub(
                        rf",\s*{re.escape(import_name)}(\s|$)", r"\1", imports_str
                    )
                # Handle single import or last import in list
                else:
                    new_imports = re.sub(
                        rf"\b{re.escape(import_name)}\b", "", imports_str
                    )

                # Clean up any double commas or trailing/leading commas
                new_imports = re.sub(r",\s*,", ",", new_imports)
                new_imports = re.sub(r"^\s*,\s*", "", new_imports)
                new_imports = re.sub(r",\s*$", "", new_imports)

                # If there are no more imports, remove the entire line
                if not new_imports.strip() or new_imports.strip() == "":
                    lines[line_idx] = ""
                else:
                    lines[line_idx] = f"{module} import {new_imports}\n"

                modified = True
                print(f"Modified line: {lines[line_idx].strip()}")

            elif re.search(rf"^import\s+.*{re.escape(import_name)}.*$", line):
                # Handle 'import module1, module2'
                if "," in line:
                    if f"{import_name}," in line:
                        new_line = re.sub(rf"{re.escape(import_name)},\s*", "", line)
                    else:
                        new_line = re.sub(rf",\s*{re.escape(import_name)}", "", line)
                    lines[line_idx] = new_line
                # Simple import
                else:
                    lines[line_idx] = ""

                modified = True
                print(f"Modified line: {lines[line_idx].strip()}")

    # Remove empty lines (but preserve blank lines with newlines)
    fixed_lines = []
    for line in lines:
        if line.strip() or line == "\n":
            fixed_lines.append(line)

    if modified:
        with open(file_path, "w", encoding="utf-8") as file:
            file.writelines(fixed_lines)
        print(f"Removed unused imports from {file_path}")


def fix_specific_files():
    """Fix specific files with known issues."""
    # Fix core/migrations.py
    file_path = "sentinelprobe/core/migrations.py"
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()

        # Remove unused sqlalchemy.text import
        content = re.sub(
            r"from sqlalchemy import .*text.*",
            lambda m: m.group(0).replace("text", "").replace("import ,", "import "),
            content,
        )

        with open(file_path, "w", encoding="utf-8") as file:
            file.write(content)
        print(f"Fixed specific imports in {file_path}")

    # Fix orchestration/models.py
    file_path = "sentinelprobe/orchestration/models.py"
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()

        # Remove unused imports
        content = re.sub(
            r"from pydantic import .*Field.*",
            lambda m: m.group(0).replace("Field", "").replace("import ,", "import "),
            content,
        )
        content = re.sub(
            r"from sqlalchemy import .*Boolean.*",
            lambda m: m.group(0).replace("Boolean", "").replace("import ,", "import "),
            content,
        )
        content = re.sub(
            r"from sqlalchemy import .*Column.*",
            lambda m: m.group(0).replace("Column", "").replace("import ,", "import "),
            content,
        )

        with open(file_path, "w", encoding="utf-8") as file:
            file.write(content)
        print(f"Fixed specific imports in {file_path}")

    # Fix orchestration/service.py
    file_path = "sentinelprobe/orchestration/service.py"
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()

        # Remove unused imports
        content = re.sub(
            r"from typing import .*Dict.*",
            lambda m: m.group(0).replace("Dict", "").replace("import ,", "import "),
            content,
        )
        content = re.sub(
            r"from typing import .*Union.*",
            lambda m: m.group(0).replace("Union", "").replace("import ,", "import "),
            content,
        )
        content = re.sub(
            r"from sentinelprobe.orchestration.models import .*JobType.*",
            lambda m: m.group(0).replace("JobType", "").replace("import ,", "import "),
            content,
        )

        with open(file_path, "w", encoding="utf-8") as file:
            file.write(content)
        print(f"Fixed specific imports in {file_path}")


def main():
    """Main function to fix imports."""
    try:
        # Fix specific files first
        fix_specific_files()

        # Then try to fix remaining imports
        unused_imports = get_unused_imports()

        if not unused_imports:
            print("No unused imports found!")
            return

        # Group by file
        imports_by_file = {}
        for file_path, line_num, import_name in unused_imports:
            if file_path not in imports_by_file:
                imports_by_file[file_path] = []
            imports_by_file[file_path].append((file_path, line_num, import_name))

        # Process each file
        for file_path, imports in imports_by_file.items():
            remove_unused_imports(file_path, imports)

        print("Done! Run flake8 again to check for remaining issues.")
    except Exception as e:
        print(f"Error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
