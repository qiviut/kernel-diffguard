#!/usr/bin/env bash
# Run the same verification suite locally and in GitHub Actions.
# Keep this script as the single source of truth for required PR/main checks.

set -Eeuo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

run_step() {
  local label="$1"
  shift
  printf '\n==> %s\n' "$label"
  "$@"
}

PYTHON_BIN="${PYTHON:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
  elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
  else
    echo "error: neither python3 nor python is available" >&2
    exit 127
  fi
fi

run_step "Check Python dev dependencies" "$PYTHON_BIN" - <<'PY'
import importlib.util
import sys

missing = [name for name in ("pytest", "ruff", "mypy") if importlib.util.find_spec(name) is None]
if missing:
    print("missing Python dev dependencies: " + ", ".join(missing), file=sys.stderr)
    print("install them with: python -m pip install -e '.[dev]'", file=sys.stderr)
    sys.exit(1)
PY

run_step "Python tests" "$PYTHON_BIN" -m pytest -q
run_step "Golden analysis regression cases" scripts/run-golden-analysis.sh
run_step "Review-signal scorecard" scripts/run-scorecard.sh
run_step "Lint" "$PYTHON_BIN" -m ruff check .
run_step "Type checks" "$PYTHON_BIN" -m mypy src
run_step "Whitespace/conflict-marker diff check" git diff --check
