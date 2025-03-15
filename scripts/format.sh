#!/bin/bash

# Format Python code using Black
echo "Formatting Python code with Black..."
black sentinelprobe/ tests/

# Run isort to sort imports
echo "Sorting imports with isort..."
isort sentinelprobe/ tests/

echo "Formatting complete!"
