#!/bin/bash
set -euo pipefail

echo "Running unittest suite..."
python3 -m unittest -v
