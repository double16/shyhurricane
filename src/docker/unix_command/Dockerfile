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

FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND=noninteractive \
    PIPX_BIN_DIR=/usr/local/bin \
    PIPX_HOME=/usr/local/share \
    PIP_CACHE_DIR=/usr/local/share/pip-cache

RUN apt-get update &&\
    apt-get install -y --install-recommends ruby nmap sqlmap curl wget dirb ffuf wfuzz hydra netcat-openbsd git pipx iputils-ping nodejs npm mitmproxy python3-pip python3-virtualenv jq exploitdb nuclei ftp sshpass tshark sqlite3 &&\
    apt-get clean
RUN pipx install impacket git-dumper
RUN gem install evil-winrm
RUN mkdir /usr/share/wakaru/ && chown 0:0 /usr/share/wakaru/ && chmod 0755 /usr/share/wakaru/
COPY --chown=0:0 --chmod=644 package.json package-lock.json /usr/share/wakaru/
COPY --chown=0:0 --chmod=755 wakaru.cjs /usr/share/wakaru/
RUN cd /usr/share/wakaru/ && npm install && chmod +x /usr/share/wakaru/wakaru.cjs

RUN mkdir /usr/share/mitm_to_katana/ && chown 0:0 /usr/share/mitm_to_katana/ && chmod 0755 /usr/share/mitm_to_katana/
COPY --chown=0:0 --chmod=644 requirements.txt mitm_to_katana.py /usr/share/mitm_to_katana/
RUN virtualenv /usr/share/mitm_to_katana/.venv &&\
    . /usr/share/mitm_to_katana/.venv/bin/activate &&\
    pip install -r /usr/share/mitm_to_katana/requirements.txt
COPY --chown=0:0 --chmod=755 mitmdump_virtualenv.sh /usr/local/bin/

COPY --from=gobuild /usr/local/bin/* /usr/local/bin/
COPY --from=cargobuild /usr/local/bin/* /usr/local/bin/

RUN useradd -u 2000 --home-dir /work --create-home --shell /bin/bash runner
USER 2000
RUN nuclei -update-templates
WORKDIR /work

VOLUME /work
VOLUME /usr/share/seclists
