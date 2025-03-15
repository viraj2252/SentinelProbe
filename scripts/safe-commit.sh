#!/bin/bash
# safe-commit.sh: A script to ensure pre-commit hooks are always run

if [[ "$*" == *"--no-verify"* ]]; then
    echo "Error: The --no-verify flag is not allowed."
    echo "This would bypass pre-commit hooks and could lead to code quality issues."
    exit 1
fi

# Run pre-commit hooks manually
echo "Running pre-commit checks..."
pre-commit run || {
    echo "Pre-commit checks failed. Please fix the issues before committing."
    exit 1
}

# If pre-commit passes, perform the commit
echo "Pre-commit checks passed. Proceeding with commit..."
git commit "$@"
