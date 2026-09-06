#!/usr/bin/env bash
set -euo pipefail
rm -rf dist
mkdir -p dist
python -m pip wheel --no-deps --no-build-isolation ./packages/core -w dist
python -m pip wheel --no-deps --no-build-isolation ./packages/cli -w dist
ls -lh dist
