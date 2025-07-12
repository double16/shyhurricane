FROM python:3.12-slim

RUN apt-get update &&\
    apt-get install -y --install-recommends docker.io curl nmap &&\
    apt-get clean

COPY requirements.txt /app/
WORKDIR /app
RUN pip install -r requirements.txt
COPY *.py /app/

RUN useradd -u 2000 -m --shell /usr/bin/rbash runner
RUN mkdir -p /data /tool_cache && chown 2000:2000 /data /tool_cache
USER 2000

ENV CHROMA=/data
VOLUME /data
VOLUME /tool_cache

EXPOSE 8000

CMD ["python3", "mcp_service.py", "--host", "0.0.0.0", "--port", "8000"]
