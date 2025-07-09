FROM python:3.12

RUN apt-get update &&\
    apt-get install -y --install-recommends docker.io &&\
    apt-get clean

COPY requirements.txt /app/
WORKDIR /app
RUN pip install -r requirements.txt
COPY *.py /app/

RUN useradd -u 2000 -m --shell /usr/bin/rbash runner
USER 2000

ENV CHROMA_STORE_PATH /data
VOLUME /data
EXPOSE 8000

CMD ["python", "mcp_service.py"]
