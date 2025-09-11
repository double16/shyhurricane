#!/usr/bin/env bash

set -e

ollama create gpt-oss-20b:64k -f "$(dirname "$0")/Modelfile"
