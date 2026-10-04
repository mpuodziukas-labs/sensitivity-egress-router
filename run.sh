#!/bin/bash
# one command: the results table, then every test
set -euo pipefail
cd "$(dirname "$0")"
PY="${PY:-python3}"
"$PY" evaluate.py
"$PY" -m pytest -q
