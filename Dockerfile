FROM python:3.12-slim

# https://docs.docker.com/engine/install/debian/
RUN apt update &&\
    apt install -y --no-install-recommends ca-certificates curl &&\
    install -m 0755 -d /etc/apt/keyrings &&\
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc &&\
    chmod a+r /etc/apt/keyrings/docker.asc &&\
    . /etc/os-release &&\
    cat <<EOF > /etc/apt/sources.list.d/docker.sources
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: ${VERSION_CODENAME}
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
EOF

RUN apt update &&\
    apt install -y --no-install-recommends docker-ce-cli curl nmap haveged &&\
    apt clean

WORKDIR /app
RUN --mount=type=bind,source=requirements.txt,target=/tmp/requirements.txt \
    pip install --no-cache-dir --prefer-binary --compile --requirement /tmp/requirements.txt
COPY *.py /app/
COPY shyhurricane /app/shyhurricane/
COPY --chown=0:0 --chmod=755 src/docker/mcp_server/entrypoint.sh /

RUN useradd -u 2000 -m --shell /usr/bin/rbash runner
RUN mkdir -p /data /tool_cache /home/runner/.cache && chown 2000:2000 /data /tool_cache /home/runner/.cache
USER 2000

ENV HOME=/home/runner
VOLUME /data
VOLUME /tool_cache
VOLUME /home/runner/.cache

EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh", "--host", "0.0.0.0", "--port", "8000"]
