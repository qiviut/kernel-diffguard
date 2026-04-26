#!/usr/bin/env bash
set -euo pipefail

manifest="tests/golden/manifest.json"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if command -v python >/dev/null 2>&1; then
  python_bin=python
else
  python_bin=python3
fi

PYTHONPATH="$repo_root/src${PYTHONPATH:+:$PYTHONPATH}" "$python_bin" -m kernel_diffguard.golden "$manifest"
