#!/bin/bash
set -e

# Run all pre-commit hooks on all files
echo "Running pre-commit hooks on all files..."
pre-commit run --all-files

# If we get here, it means all checks passed
echo "✅ All checks passed!"
