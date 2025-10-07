#!/usr/bin/env bash

# TODO: try webcrack once it installs with Node 24+

SCRIPT_DIR="$(dirname $0)"
if [[ -s "${SCRIPT_DIR}/wakaru.cjs" ]]; then
  WAKARU="${SCRIPT_DIR}/wakaru.cjs"
else
  WAKARU=/usr/share/wakaru/wakaru.cjs
fi

if [ -z "$1" ]; then
  INPUT_FILE="$(mktemp)"
  cat >"${INPUT_FILE}"

  cleanup() {
    [ -f "${INPUT_FILE}" ] && rm -f "${INPUT_FILE}"
  }
  trap cleanup EXIT
else
  INPUT_FILE="$1"
  test -r "${INPUT_FILE}" || exit $?
fi

if [ -z "$2" ]; then
  OUTPUT_FILE="/dev/stdout"
else
  OUTPUT_FILE="$2"
  touch "${OUTPUT_FILE}" || exit $?
fi

for RULESET in 0 1 2 3 4 5; do
  node --max-old-space-size=4096 "${WAKARU}" ${RULESET} <"${INPUT_FILE}" >"${OUTPUT_FILE}" && exit 0
done
