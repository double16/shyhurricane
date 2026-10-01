#!/usr/bin/env bash
set -euo pipefail

RULES=/opt/opengrep-rules
STAMP="${RULES}/.last-refresh"

tar -xf - -C /work

if [[ ! -f "$STAMP" || $(find "$STAMP" -mtime +0) ]]; then
  timeout 20 git -C "$RULES" pull --ff-only --quiet >&2 || true
  touch "$STAMP"
fi

mkdir -p /work/scan
if [[ -s /work/source.js.map ]]; then
  timeout 60 shuji /work/source.js.map -o /work/scan -p >&2 || true
fi

if ! find /work/scan -type f \( -name '*.js' -o -name '*.jsx' -o -name '*.ts' -o -name '*.tsx' \) -print -quit | grep -q .; then
  cp /work/source.js /work/scan/source.js
fi

timeout 240 opengrep scan --json --quiet --config "$RULES/javascript" /work/scan
