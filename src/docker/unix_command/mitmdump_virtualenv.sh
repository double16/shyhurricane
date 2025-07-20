#!/usr/bin/env bash

source /usr/share/mitm_to_katana/.venv/bin/activate

exec mitmdump "$@"
