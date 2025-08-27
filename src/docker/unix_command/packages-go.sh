#!/usr/bin/env sh

set -xe

export GOPATH=/usr/local/share/go
export TARGET_DIR=/usr/local/bin
mkdir -p "${TARGET_DIR}"
if [ -z "$GOARCH" ]; then
  export GOBIN="${TARGET_DIR}"
fi
export GOCACHE=/usr/local/share/go-build-cache
export GOFLAGS="-ldflags=-s -w"

CC=gcc CXX=g++
if [ "$BUILDPLATFORM" = "linux/amd64" ]; then
  if [ "$TARGETARCH" = "arm64" ]; then
    export CC=aarch64-linux-gnu-gcc CXX=aarch64-linux-gnu-g++
  fi
elif [ "$BUILDPLATFORM" = "linux/arm64" ]; then
  if [ "$TARGETARCH" = "amd64" ]; then
    export CC=x86_64-linux-gnu-gcc CXX=x86_64-linux-gnu-g++
  fi
fi

if command -v go; then
	for GOPKG in \
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
		; do
		go install ${GOPKG}
	done
  if [ -n "$GOARCH" ]; then
	  find "${GOPATH}/bin" -type f -exec cp {} "${TARGET_DIR}" \;
	fi
fi

test -x ${TARGET_DIR}/katana
test -x ${TARGET_DIR}/gobuster
test -x ${TARGET_DIR}/meg
test -x ${TARGET_DIR}/anew
test -x ${TARGET_DIR}/unfurl
test -x ${TARGET_DIR}/gf
test -x ${TARGET_DIR}/gau
test -x ${TARGET_DIR}/403jump
test -x ${TARGET_DIR}/waybackurls
test -x ${TARGET_DIR}/httpx
test -x ${TARGET_DIR}/subfinder
