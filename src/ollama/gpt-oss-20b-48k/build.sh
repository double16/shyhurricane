#!/usr/bin/env bash

set -e

ollama create gpt-oss-20b:48k -f "$(dirname "$0")/Modelfile"
