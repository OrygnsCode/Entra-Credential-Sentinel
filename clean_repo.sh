#!/bin/bash
set -u

echo "Cleaning repo of artifacts..."

# Remove Python Cache
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete

# Remove Output Folders
rm -rf out/
rm -rf out_*/

# Remove Packaging Info
rm -rf *.egg-info/
rm -rf build/
rm -rf dist/
rm -rf .pytest_cache/

# Remove ship check script (self-cleanup of dev artifacts)
rm -f ship_check.sh

echo "Cleanup complete."
