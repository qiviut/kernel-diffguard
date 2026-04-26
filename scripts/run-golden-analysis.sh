#!/usr/bin/env bash
set -euo pipefail

manifest="tests/golden/manifest.json"

if [[ ! -f "$manifest" ]]; then
  echo "No golden analysis manifest yet; tracked by kernel-diffguard-hsz."
  exit 0
fi

echo "Golden analysis manifest found at $manifest, but the runner is not implemented yet."
echo "Implement comparison tooling as part of kernel-diffguard-hsz."
exit 1
