#!/usr/bin/env bash

# to maintain entropy or mitmproxy gets stuck
haveged -w 0 -d 256 -F -v 1 &

exec python3 mcp_service.py "$@"
