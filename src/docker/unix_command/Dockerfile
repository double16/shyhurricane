FROM --platform=$BUILDPLATFORM golang:1.24 AS gobuild
ARG TARGETARCH
ENV DEBIAN_FRONTEND=noninteractive
ENV FAILURE_CMD="true"
ENV GOOS=linux GOARCH=$TARGETARCH
ADD packages-go.sh /tmp
RUN /tmp/packages-go.sh

FROM --platform=$BUILDPLATFORM ghcr.io/double16/cargobuild:latest AS cargobuild
ENV FAILURE_CMD="true"
ADD packages-cargo.sh /tmp
RUN /tmp/packages-cargo.sh

FROM ubuntu:24.04 AS wordlists
RUN apt-get update &&\
    apt-get install -y git pipx
RUN git clone --depth=1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists
RUN rm -rf /usr/share/seclists/.git

FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive \
    PIPX_BIN_DIR=/usr/local/bin \
    PIPX_HOME=/usr/local/share \
    PIP_CACHE_DIR=/usr/local/share/pip-cache

RUN apt-get update &&\
    apt-get install -y --install-recommends ruby nmap curl wget dirb ffuf wfuzz netcat-openbsd git pipx iputils-ping &&\
    apt-get clean
RUN pipx install impacket
RUN gem install evil-winrm

COPY --from=gobuild /usr/local/bin/* /usr/local/bin/
COPY --from=cargobuild /usr/local/bin/* /usr/local/bin/
COPY --from=wordlists /usr/share/seclists /usr/share/seclists/

RUN useradd -u 2000 --home-dir /work --create-home --shell /bin/bash runner
USER 2000
WORKDIR /work

VOLUME /work
