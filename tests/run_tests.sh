#!/bin/bash

# ================================================================
#  BURN SUITE — Test Runner
#  Runs the full persisted regression suite for all five tools.
#  Usage: ./tests/run_tests.sh   (from anywhere in the suite folder)
# ================================================================

SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SUITE_DIR" || exit 1

python3 -m unittest discover -s tests -p "test_*.py" -v
