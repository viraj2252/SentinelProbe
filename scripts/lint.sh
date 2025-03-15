#!/bin/bash
set -e

# Run flake8 on the entire codebase
echo "Running flake8 on the codebase..."
flake8 sentinelprobe tests

# If we get here, it means flake8 didn't find any errors
echo "✅ No lint errors found!"
