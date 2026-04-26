#!/usr/bin/env bash
set -euo pipefail

manifest="tests/golden/manifest.json"

python -m kernel_diffguard.golden "$manifest"
