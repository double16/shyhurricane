#!/usr/bin/env bash

set -euo pipefail

if [[ $# -eq 0 ]]; then
  exec webcrack
fi

if [[ $# -eq 1 ]]; then
  exec webcrack "$1"
fi

webcrack "$1" >"$2"
