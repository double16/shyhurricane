#!/usr/bin/env sh

#
# go
# installing from source can be fragile, so don't exit on failure
#

set -e

FAILURE_CMD="${FAILURE_CMD:-false}"
export GOPATH=/usr/local/share/go
export TARGET_DIR=/usr/local/bin
mkdir -p "${TARGET_DIR}"
if [ -z "$GOARCH" ]; then
  export GOBIN="${TARGET_DIR}"
fi
export GOCACHE=/usr/local/share/go-build-cache
export GOFLAGS="-ldflags=-s -w"
if command -v go; then
	for GOPKG in \
github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest \
github.com/projectdiscovery/katana/cmd/katana@latest \
github.com/OJ/gobuster/v3@latest \
github.com/tomnomnom/meg@latest \
github.com/tomnomnom/anew@latest \
github.com/tomnomnom/unfurl@latest \
github.com/tomnomnom/gf@latest \
github.com/lc/gau/v2/cmd/gau@latest \
github.com/trap-bytes/403jump@latest \
github.com/tomnomnom/waybackurls@latest \
github.com/projectdiscovery/httpx/cmd/httpx@latest \
github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
github.com/sensepost/gowitness@latest \
github.com/hakluke/hakrawler@latest \
		; do
		go install ${GOPKG} || ${FAILURE_CMD}
	done
  if [ -n "$GOARCH" ]; then
	  find "${GOPATH}/bin" -type f -exec cp {} "${TARGET_DIR}" \;
	fi
fi
