#!/usr/bin/env bash
set -euo pipefail
python -m pip install -e ./packages/core
python -m pip install -e ./packages/cli
agentguard version
