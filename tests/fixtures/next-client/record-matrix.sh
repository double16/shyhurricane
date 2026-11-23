#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
: "${FIXTURE_CHROME:?Set FIXTURE_CHROME to the Chromium executable}"
: "${1:?Supply an absolute directory for the capture files}"
output="$1"
mkdir -p "$output"
export NEXT_TELEMETRY_DISABLED=1

for bundler in webpack turbopack; do
  for maps in 0 1; do
    FIXTURE_BROWSER_MAPS="$maps" node node_modules/next/dist/bin/next build "--$bundler"
    FIXTURE_BROWSER_MAPS="$maps" node capture.mjs > "$output/$bundler-maps-$maps.jsonl"
  done
done
