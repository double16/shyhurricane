#!/usr/bin/env bash

set -xe

export GOPATH=/usr/local/share/go
export TARGET_DIR=/usr/local/bin
mkdir -p "${TARGET_DIR}"
if [ "$BUILDPLATFORM" == "linux/$TARGETARCH" ]; then
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
github.com/projectdiscovery/katana/cmd/katana@v1.5.0 \
		; do
		go install -v ${GOPKG}
	done
fi

if [ -d "${GOPATH}/bin/linux_${TARGETARCH}" ]; then
  find "${GOPATH}/bin/linux_${TARGETARCH}" -type f -exec cp {} "${TARGET_DIR}" \;
fi

test -x ${TARGET_DIR}/katana
