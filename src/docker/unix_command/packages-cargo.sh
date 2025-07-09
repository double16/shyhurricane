#!/usr/bin/env bash

#
# cargo (rust)
# installs from source can be fragile, so don't exit on failure
#

set -e

ALL_CARGOS="rustscan feroxbuster"
FAILURE_CMD="${FAILURE_CMD:-true}"

# won't compile on arm64
#    https://github.com/microsoft/rusty-radamsa.git

# Get target specific vars
if [[ -f "/etc/environment" ]]; then
  . /etc/environment
fi

# Setup the cargo environment
if [[ -f "${HOME}/.cargo/env" ]]; then
  . "${HOME}/.cargo/env"
else
  export CARGO_HOME=/usr/local/share/cargo
fi

if command -v cargo; then
  echo "Building rust apps for target ${TARGET}"

  for CARGO in ${ALL_CARGOS}; do
    cargo install --root /usr/local ${TARGET:+--target ${TARGET}} "${CARGO}" || ${FAILURE_CMD}
  done
  for REPO in \
    https://gitlab.com/dee-see/graphql-path-enum \
    ; do
    cargo install --root /usr/local ${TARGET:+--target ${TARGET}} --git "${REPO}" || ${FAILURE_CMD}
  done
fi
