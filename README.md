# shyhurricane

MCP server and AI assistant for penetration testing.

## TL;DR

### Dependencies

#### Docker Desktop or colima

On Mac, Apple Virtualization networking has issues. Use qemu.

```shell
brew install colima docker qemu
colima start --runtime docker --cpu 6 --disk 50 -m 12 --vm-type qemu -V ${HOME}:${HOME}:m
```

#### Python Environment

```shell
virtualenv --try-first-with $(command -v python3.12) .venv
source .venv/bin/activate
virtualenv .venv
source .venv/bin/activate
```

#### Ollama

Install Ollama and the llama3.2:3b model:

Ubuntu:

```shell
apt-get install ollama
ollama pull llama3.2:3b
```

macOS:

```shell
brew install ollama
brew services start ollama
ollama pull llama3.2:3b
```

#### Chroma Database

```shell
chroma run --path chroma_store --host 127.0.0.1 --port 8200 
```

### MCP Server

#### As a Docker Service

Configure your desired provider and model in `.env`:

```shell
OLLAMA_MODEL=llama3.2:3b
OLLAMA_HOST=192.168.100.100:11434
GEMINI_API_KEY=
GEMINI_MODEL=
OPENAI_MODEL=
OPENAI_API_KEY=
```

Run the MCP server:

```shell
docker compose up -d
```

or to build the images from source:

```shell
docker compose -f docker-compose.dev.yml up -d
```

#### Running Locally

The unix command is run in a container to prevent bad things, so you still need docker.

```shell
docker build -t ghcr.io/double16/shyhurricane_unix_command:main src/docker/unix_command
python3 mcp_service.py
```

### Run the assistant

Run the assistant as a chat:

```shell
pip install -r requirements.txt

python3 assistant.py
```

Run the assistant as an agent:

```shell
pip install -r requirements.txt

python3 assistant.py
```

### Other MCP Client

Or connect the MCP server at http://127.0.0.1:8000 in your client, such as "5ire".

## Google AI

Remove the Ollama options. Set the following environment variables before running the MCP server and assistant. The
model may be set using `--gemini-model`. The API key must be an environment variable.

- `GEMINI_MODEL=gemini-2.5-pro`
- `GEMINI_API_KEY`

# OpenAI

Remove the Ollama options. Set the following environment variables before running the MCP server and assistant. The
model may be set using `--openai-model`. The API key must be an environment variable.

- `OPENAI_MODEL=o4-mini`
- `OPENAI_API_KEY`

## Ollama

Ollama can be configured to use a remote server by setting the host and port. The host can also be set using
`--ollama-host` and the
model with `--ollama-model`.

- `OLLAMA_MODEL=llama3.2:3b`
- `OLLAMA_HOST=localhost:11434`

# misc.

Disable user elicitation:
`DISABLE_ELICITATION=True`

## Indexing Data

The ingest queue is based on the EXACT string of the Chroma database. i.e., `localhost` and `127.0.0.1` are different!

### katana

```shell
cat katana.jsonl | python3 ingest.py --db 127.0.0.1:8200 --katana

# live ingestion:
tail -f katana.jsonl | python3 ingest.py --db 127.0.0.1:8200 --katana
```

... or send to a running MCP server:

```shell
curl -X POST -H 'Transfer-Encoding: chunked' -H 'Content-Type: application/json' http://127.0.0.1:8000/index --data-binary @katana.jsonl
```

### Burp Logger++ CSV

Minimum fields to export:

- Request.AsBase64
- Request.Time
- Request.URL
- Response.AsBase64
- Response.RTT

```shell
cat LoggerPlusPlus.csv | python3 ingest.py --db 127.0.0.1:8200 --csv

# live ingestion using the auto-export feature of Logger++:
tail -f LoggerPlusPlus.csv | python3 ingest.py --db 127.0.0.1:8200 --csv
```
