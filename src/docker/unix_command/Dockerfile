FROM --platform=$BUILDPLATFORM golang:1.25 AS gobuild
ARG TARGETARCH
ARG BUILDPLATFORM
ENV DEBIAN_FRONTEND=noninteractive
ENV GOOS=linux GOARCH=$TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends build-essential pkg-config git ca-certificates &&\
    if [ "$BUILDPLATFORM" = "linux/amd64" ]; then apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross; fi &&\
    if [ "$BUILDPLATFORM" = "linux/arm64" ]; then apt-get install -y --no-install-recommends gcc-x86-64-linux-gnu g++-x86-64-linux-gnu libc6-dev-amd64-cross; fi
ENV CGO_ENABLED=1
ADD packages-go.sh /tmp
RUN /tmp/packages-go.sh

FROM --platform=$BUILDPLATFORM ghcr.io/double16/cargobuild:latest AS cargobuild
ADD packages-cargo.sh /tmp
RUN /tmp/packages-cargo.sh

FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND=noninteractive \
    PIPX_BIN_DIR=/usr/local/bin \
    PIPX_HOME=/usr/local/share \
    PIP_CACHE_DIR=/usr/local/share/pip-cache

RUN echo 'path-exclude=/usr/share/doc/*'        >  /etc/dpkg/dpkg.cfg.d/excludes &&\
    echo 'path-exclude=/usr/share/man/*'        >> /etc/dpkg/dpkg.cfg.d/excludes &&\
    echo 'path-exclude=/usr/share/groff/*'      >> /etc/dpkg/dpkg.cfg.d/excludes &&\
    echo 'path-exclude=/usr/share/info/*'       >> /etc/dpkg/dpkg.cfg.d/excludes &&\
    echo 'path-exclude=/usr/share/lintian/*'    >> /etc/dpkg/dpkg.cfg.d/excludes &&\
    echo 'path-include=/usr/share/doc/*/copyright' >> /etc/dpkg/dpkg.cfg.d/excludes

RUN apt-get update &&\
    apt-get install -y --no-install-recommends rsync ruby nmap sqlmap curl wget dirb ffuf wfuzz hydra netcat-openbsd git pipx iputils-ping nodejs npm mitmproxy python3-pip python3-virtualenv jq exploitdb nuclei ftp atftp sshpass tshark sqlite3 smbclient &&\
    apt-get clean
RUN pipx install impacket git-dumper
RUN gem install evil-winrm
RUN mkdir /usr/share/wakaru/ && chown 0:0 /usr/share/wakaru/ && chmod 0755 /usr/share/wakaru/
COPY --chown=0:0 --chmod=644 package.json package-lock.json /usr/share/wakaru/
COPY --chown=0:0 --chmod=755 wakaru.cjs /usr/share/wakaru/
COPY --chown=0:0 --chmod=755 jsdeobf.sh /usr/local/bin/
RUN cd /usr/share/wakaru/ && npm install

RUN mkdir /usr/share/mitm_to_katana/ && chown 0:0 /usr/share/mitm_to_katana/ && chmod 0755 /usr/share/mitm_to_katana/
COPY --chown=0:0 --chmod=644 requirements.txt mitm_to_katana.py /usr/share/mitm_to_katana/
RUN virtualenv /usr/share/mitm_to_katana/.venv &&\
    . /usr/share/mitm_to_katana/.venv/bin/activate &&\
    pip install --no-cache-dir --prefer-binary --compile -r /usr/share/mitm_to_katana/requirements.txt
COPY --chown=0:0 --chmod=755 mitmdump_virtualenv.sh /usr/local/bin/

COPY --from=gobuild /usr/local/bin/* /usr/local/bin/
COPY --from=cargobuild /usr/local/bin/* /usr/local/bin/

RUN useradd -u 2000 --home-dir /work --create-home --shell /bin/bash runner
USER 2000
WORKDIR /work
#RUN nuclei -update-templates
RUN mkdir -m 0700 ".ssh" && touch ".ssh/config" && chmod 0600 ".ssh/config" &&\
    echo -e "StrictHostKeyChecking no\nUserKnownHostsFile /dev/null\nBatchMode yes\n" >> ".ssh/config"
COPY --chown=0:0 --chmod=0755 entrypoint.sh /
ENTRYPOINT ["/entrypoint.sh"]

VOLUME /work
VOLUME /usr/share/seclists
