#!/usr/bin/env bash
set -euo pipefail

report_dir="."
if [[ "${1:-}" == "--report-dir" ]]; then
  if [[ $# -lt 2 ]]; then
    echo "Usage: $0 [--report-dir DIR] [pytest arguments...]" >&2
    exit 2
  fi
  report_dir="$2"
  shift 2
fi

mkdir -p "$report_dir"

KMP_DUPLICATE_LIB_OK=TRUE UV_CACHE_DIR="$PWD/.uv-cache" \
  uv run pytest tests/ -q --tb=short "$@" \
    --cov=shyhurricane \
    --cov-branch \
    --cov-report="xml:$report_dir/coverage.xml" \
    --cov-report="html:$report_dir/htmlcov" \
    --cov-report="json:$report_dir/coverage.json"
