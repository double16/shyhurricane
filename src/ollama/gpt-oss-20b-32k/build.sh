#!/usr/bin/env bash

set -e

ollama create gpt-oss-20b:32k -f "$(dirname "$0")/Modelfile"
