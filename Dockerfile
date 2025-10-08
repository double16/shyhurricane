FROM python:3.12-slim

RUN apt-get update &&\
    apt-get install -y --no-install-recommends docker.io curl nmap haveged &&\
    apt-get clean

WORKDIR /app
RUN --mount=type=bind,source=requirements.txt,target=/tmp/requirements.txt \
    pip install --requirement /tmp/requirements.txt
COPY *.py /app/
COPY shyhurricane /app/shyhurricane/
COPY --chown=0:0 --chmod=755 src/docker/mcp_server/entrypoint.sh /

RUN useradd -u 2000 -m --shell /usr/bin/rbash runner
RUN mkdir -p /data /tool_cache /home/runner/.cache && chown 2000:2000 /data /tool_cache /home/runner/.cache
USER 2000

ENV CHROMA=/data
VOLUME /data
VOLUME /tool_cache
VOLUME /home/runner/.cache

EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh", "--host", "0.0.0.0", "--port", "8000"]
