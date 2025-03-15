#!/bin/bash
set -e

# Run flake8 on the entire codebase
echo "Running flake8 on the codebase..."
flake8 sentinelprobe/ --config=setup.cfg

# Run flake8 on tests with specific ignores
echo "Running flake8 on tests with specific ignores..."
flake8 tests/ --ignore=F401,D102,D105,D107,D400,F811,E501,D202 --config=setup.cfg

# If we get here, it means flake8 didn't find any errors
echo "✅ No lint errors found!"
