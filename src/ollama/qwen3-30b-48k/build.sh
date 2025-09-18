#!/usr/bin/env bash

set -e

ollama create qwen3-30b:48k -f "$(dirname "$0")/Modelfile"
