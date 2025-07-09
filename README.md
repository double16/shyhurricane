# shyhurricane

MCP server and AI assistant for penetration testing.

## TL;DR

Install Ollama and the llama3.1 model:

Ubuntu:
```shell
apt-get install ollama
ollama pull llama3.1
```

macOS:
```shell
brew install ollama
brew services start ollama
ollama pull llama3.1
```

### MCP Server

#### As a Docker Service

Change `docker-compose.yml` `OLLAMA_URL` to your host:
```yaml
    environment:
      OLLAMA_MODEL: llama3.1
      OLLAMA_URL: "http://127.0.0.1:11434"
```

Run the MCP server:
```shell
docker-compose up -d
```

#### Running Locally

The unix command is run in a container to prevent bad things, so you still need docker.
```shell
cd src/docker/unix_command
docker build -t shyhurricane_unix_command:latest
cd -
python3 mcp_service.py --ollama-model llama3.1
```

### Run the assistant

Run the assistant as a chat:
```shell
pip install -r requirements.txt

python3 assistant.py --ollama-model llama3.1 --mode chat
```

Run the assistant as an agent:
```shell
pip install -r requirements.txt

python3 assistant.py --ollama-model llama3.1 --mode agent
```

### Other MCP Client

Or connect the MCP server at http://127.0.0.1:8000 in your client, such as "5ire".
