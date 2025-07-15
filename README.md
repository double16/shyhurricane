# shyhurricane

MCP server and AI assistant for penetration testing.

## TL;DR

### Dependencies

```shell
virtualenv .venv
source .venv/bin/activate
```

### Ollama

Install Ollama and the qwen2.5:7b-instruct model:

Ubuntu:

```shell
apt-get install ollama
ollama pull qwen2.5:7b-instruct
```

macOS:

```shell
brew install ollama
brew services start ollama
ollama pull qwen2.5:7b-instruct
```

### Chroma Database

```shell
chroma run --path chroma_store --host 127.0.0.1 --port 8200 
```

### MCP Server

#### As a Docker Service

Configure your desired provider and model in `.env`:

```shell
OLLAMA_MODEL=qwen2.5:7b-instruct
OLLAMA_URL=http://192.168.100.100:11434
GEMINI_API_KEY=
GEMINI_MODEL=
OPENAI_MODEL=
OPENAI_API_KEY=
```

Run the MCP server:

```shell
docker-compose up -d
```

#### Running Locally

The unix command is run in a container to prevent bad things, so you still need docker.

```shell
docker build -t shyhurricane_unix_command:latest src/docker/unix_command
python3 mcp_service.py --ollama-model qwen2.5:7b-instruct
```

### Run the assistant

Run the assistant as a chat:

```shell
pip install -r requirements.txt

python3 assistant.py --ollama-model qwen2.5:7b-instruct --mode chat
```

Run the assistant as an agent:

```shell
pip install -r requirements.txt

python3 assistant.py --ollama-model qwen2.5:7b-instruct --mode agent
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

Ollama can be configured to use a remote server by setting the URL. The URL can also be set using `--ollama-url` and the
model with `--ollama-model`.

- `OLLAMA_MODEL=qwen2.5:7b-instruct`
- `OLLAMA_URL=http://localhost:11434`


# misc.

Disable user elicitation:
`DISABLE_ELICITATION=True`
