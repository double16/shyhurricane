#!/usr/bin/env bash
set -x
curl -s "https://www.googleapis.com/discovery/v1/apis?key=${GOOGLE_API_KEY}"
