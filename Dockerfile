FROM python:3.12-slim

RUN apt-get update &&\
    apt-get install -y --install-recommends docker.io curl nmap &&\
    apt-get clean

WORKDIR /app
RUN --mount=type=bind,source=requirements.txt,target=/tmp/requirements.txt \
    pip install --requirement /tmp/requirements.txt
COPY *.py /app/
COPY shyhurricane /app/shyhurricane/

RUN useradd -u 2000 -m --shell /usr/bin/rbash runner
RUN mkdir -p /data /tool_cache /home/runner/.cache && chown 2000:2000 /data /tool_cache /home/runner/.cache
USER 2000

ENV CHROMA=/data
VOLUME /data
VOLUME /tool_cache
VOLUME /home/runner/.cache

EXPOSE 8000

ENTRYPOINT ["python3", "mcp_service.py", "--host", "0.0.0.0", "--port", "8000"]
