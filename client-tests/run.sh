#!/usr/bin/env bash
# Run Python and TypeScript Efflux v3 client integration tests.
#
# Usage:
#   export EFFLUX_API_KEY=your-key
#   ./run.sh
#   ./run.sh --resource scans
#   ./run.sh --python-only
#   ./run.sh --typescript-only -v

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
PYTHON_ONLY=0
TS_ONLY=0
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --python-only) PYTHON_ONLY=1; shift ;;
    --typescript-only|--ts-only) TS_ONLY=1; shift ;;
    *) EXTRA_ARGS+=("$1"); shift ;;
  esac
done

if [[ -z "${EFFLUX_API_KEY:-}" ]]; then
  echo "ERROR: EFFLUX_API_KEY is not set." >&2
  echo "  export EFFLUX_API_KEY=your-api-key" >&2
  exit 2
fi

PY_EXIT=0
TS_EXIT=0

if [[ "$TS_ONLY" -eq 0 ]]; then
  echo "============================================================"
  echo " Python client"
  echo "============================================================"
  # bash 3.2 (macOS) + set -u treats empty "${arr[@]}" as unbound
  python3 "$ROOT/python/test_client.py" ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"} || PY_EXIT=$?
fi

if [[ "$PYTHON_ONLY" -eq 0 ]]; then
  echo ""
  echo "============================================================"
  echo " TypeScript client"
  echo "============================================================"
  if [[ ! -d "$ROOT/typescript/node_modules" ]]; then
    echo "Installing typescript test dependencies..."
    (cd "$ROOT/typescript" && npm install --silent)
  fi
  (cd "$ROOT/typescript" && npm test -- ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}) || TS_EXIT=$?
fi

echo ""
echo "============================================================"
echo " Summary"
echo "============================================================"
[[ "$TS_ONLY" -eq 0 ]] && echo "Python:     $([[ $PY_EXIT -eq 0 ]] && echo PASS || echo FAIL)"
[[ "$PYTHON_ONLY" -eq 0 ]] && echo "TypeScript: $([[ $TS_EXIT -eq 0 ]] && echo PASS || echo FAIL)"

if [[ $PY_EXIT -ne 0 || $TS_EXIT -ne 0 ]]; then
  exit 1
fi
exit 0
