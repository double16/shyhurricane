# shyhurricane

<img src="shyhurricane/assets/shyhurricane.png" alt="Hurricane picking padlock logo" width="150" style="float: left; margin-right:10px;" />

ShyHurricane is an MCP server to assist AI in offensive security testing. It aims to solve a few problems observed with
LLMs executing shell commands:

1. Spidering and directory busting commands can be quite noisy and long-running. LLMs will go through a few iterations to pick a suitable command and options. The server provides spidering and busting tools to consistently provide the LLM with usable results.
2. Models will also enumerate websites with many curl commands. The server saves and indexes responses to return data without contacting the website repeatedly. Large sites, common with bug bounty programs, are not efficiently enumerated with individual curl commands. 
3. Port scans may take a long time causing the LLM to assume the scan has failed and issue a repeated scan. The port_scan tool provided by the server addresses this.

An important feature of the server is the indexing of website content using embedding models. The `find_web_resources` tool uses LLM prompts to find vulnerabilities specific to content type: html, javascript, css, xml, HTTP headers. The content is indexed when found by the tools. Content may also be indexed by feeding external data into the `/index` endpoint. Formats supported are `katana jsonl`, `hal json` and Burp Suite Logger++ CSV. Extensions exist for Burp Suite, ZAP, Firefox and Chrome to send requests to the server as the site is browsed.

## Tools

The following tools are provided:

| Tool                        | Description                                                                                         | Open World? |
|-----------------------------|-----------------------------------------------------------------------------------------------------|-------------|
| run_unix_command            | Run a Linux or macOS command and return its output.                                                 | No          |
| port_scan                   | Performs a port scan and service identification on the target(s), similar to the functions of nmap. | Yes         |
| spider_website              | Spider the website at the url and index the results for further analysis                            | Yes         |
| directory_buster            | Search a website for hidden directories and files.                                                  | Yes         |
| index_http_url              | Index an HTTP URL to allow for further analysis. (aka curl)                                         | Yes         |
| find_wordlists              | Find available word lists for spidering and `run_unix_command`                                      | No          |
| find_web_resources          | Query indexed resources about a website using natural language .                                    | No          |
| fetch_web_resource_content  | Fetch the content of a web resource that has already been indexed.                                  | No          |
| find_domains                | Query indexed resources for a list of domains.                                                      | No          |
| find_hosts                  | Query indexed resources for a list of hosts for the given domain.                                   | No          |
| find_netloc                 | Query indexed resources for a list of network locations, i.e. host:port, for a given domain.        | No          |
| find_urls                   | Query indexed resources for a list of URLs for the given host or domain.                            | No          |
| register_hostname_address   | Registers a hostname with an IP address.                                                            | No          |
| register_http_headers       | Register HTTP headers that should be sent on every request.                                         | No          |
| save_finding                | Save findings as a markdown.                                                                        | No          |
| query_findings              | Query for previous findings for a target.                                                           | No          |
| web_search                  | Searches the web with the provided query.                                                           | Yes         |
| deobfuscate_javascript      | De-obfuscate JavaScript content (automatically done during indexing)                                | No          |
| deobfuscate_javascript_file | De-obfuscate a JavaScript file (automatically done during indexing)                                 | No          |
| prompt_chooser              | Chooses the best prompt for an offensive security operation.                                        | No          |
| prompt_list                 | Provides a list of available prompt titles for offensive security operations.                       | No          |
| encoder_decoder             | Transforms the input by applying common operations.                                                 | No          |
| channel_create_forward      | Create a forward channel backed by a local subprocess.                                              | Yes         |
| channel_create_reverse      | Create a reverse channel for one duplex client                                                      | Yes         |
| channel_poll                | Long-poll for events from a channel                                                                 | Yes         |
| channel_send                | Write bytes to a channel's stdin                                                                    | Yes         |
| channel_status              | Check whether a channel is established and ready for send/receive.                                  | Yes         |
| channel_close               | Close a specific channel                                                                            | Yes         |
| channel_close_all           | Close all channels                                                                                  | Yes         |
| oast_health                 | Check the health/reachability of the currently configured OAST provider.                            | Yes         |
| oast_endpoints              | Get the endpoints that can be used to test out-of-band interactions from the target.                | Yes         |
| oast_poll                   | Retrieve new interactions with the OAST service since the last poll.                                | Yes         |


## GPU

The MCP server requires GPUs that pytorch supports, such as nvidia or Apple Silicon. Even if non-local LLMs are used,
the index embeddings require GPU.

Features that use embeddings can be disabled by enabling "low power" mode.

Configure `.env`:

```shell
echo LOW_POWER=true >> .env
docker compose up -d
```

OR

```shell
python3 mcp_service.py --low-power true
```

## Install

The MCP server itself uses an LLM for light tasks such that the `llama3.2:3b` model is sufficient. Ollama is recommended but not required. OpenAI and Google AI models are also supported. Docker is required for tool specific commands and the generic unix commands.

### Docker Desktop or colima

Docker is required and the quality of the networking stack is important. Docker Desktop is accepted. On macOS, Apple Virtualization networking has issues. Use `colima` with `qemu` virtualization for better results.

If you use Homebrew, `brew bundle` may be used for installation. Otherwise, use your operating system to install `colima`, `qemu`, `docker`, and `docker-compose`.

Start `colima` with a command such as the following:
```shell
colima start --runtime docker --cpu 6 --disk 50 -m 12 --vm-type qemu
```

### nmap

It is best to run `nmap` on the host. If not installed on the host, the docker container will be used.

### Docker Compose

#### As a Docker Service

Configure your desired provider and model in `.env`:

```shell
OLLAMA_MODEL=llama3.2:3b
OLLAMA_HOST=192.168.100.100:11434

GEMINI_API_KEY=
GEMINI_MODEL=

OPENAI_MODEL=
OPENAI_API_KEY=

BEDROCK_MODEL=
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
```

Run the MCP server:

```shell
docker compose up -d
```

or to build the images from source:

```shell
docker compose -f docker-compose.dev.yml up -d
```

Add the MCP server to your client of choice at http://127.0.0.1:8000/mcp, or use the `assistant.py` in this repo (see below).

### Run From Source

#### Python Environment

```shell
$(command -v python3.12) -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

#### Ollama

Install Ollama and the `llama3.2:3b` model:

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

#### Command Container Image

```shell
docker build -t ghcr.io/double16/shyhurricane_unix_command:main src/docker/unix_command
```

#### MCP Server

Ollama with `llama3.2:3b`:
```shell
python3 mcp_service.py
```

OpenAI:
```shell
export OPENAI_API_KEY=xxxx
python3 mcp_service.py --openai-model gpt-4-turbo
```

Google AI:
```shell
export GOOGLE_API_KEY=xxxx
python3 mcp_service.py --gemini-model gemini-2.0-flash
```

AWS Bedrock:
```shell
python3 mcp_service.py --bedrock-model us.meta.llama3-2-3b-instruct-v1:0
```

## Disabling Open World Tools

Open-world tools allow the LLM to reach out to the Internet for spidering, directory busting, etc. There are use cases where this is undesired and only indexed content should be used.

Configure `.env`:
```shell
OPEN_WORLD=false
```

Restart Docker:
```shell
docker compose up -d
```

OR

Start the MCP server with `--open-world false`:
```shell
python3 mcp_service.py --open-world false
```

## Disabling "Assistant" Tools

Some tools are intended to augment a simple assistant, such as choosing a prompt or saving and querying findings. Sophisticated
frameworks have their own prompts and memory. The assistant tools in this MCP should be disabled when used with these
frameworks.

Configure `.env`:
```shell
ASSISTANT_TOOLS=false
```

Restart Docker:
```shell
docker compose up -d
```

OR

Start the MCP server with `--assistant-tools false`:
```shell
python3 mcp_service.py --assistant-tools false
```

## Run the assistant

The assistant provides a command line chat prompt. It isn't elaborate but provides an easy way to use the MCP server. The server queries MCP prompts for offensive security and the assistant will chose an appropriate system prompt using the first user prompt.

The assistant should use a larger reasoning model than the MCP server. This model performs the real work of finding vulnerabilities and exploits.

Local models must have a context size of at least 16k tokens. The MCP tools + system prompt currently use around 10k. The Ollama models may advertise
a large context size but the default pull is usually 4k or so. It is easy to "build" a derived model, only increasing the context size. See
`src/ollama` for example build scripts.

```shell
$(command -v python3.12) -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 assistant.py --ollama-model gpt-oss-20b:32k
```

Give the assistant instructions like:
- Solve the CTF challenge at 10.129.10.10
- Solve the HTB CTF challenge at 10.129.10.10  (Hack-the-Box specific agent)
- Help me find vulns at https://example.com  (chat)
- Find all the vulns at https://example.com  (agent)

The prompts are exposed via the MCP protocol. Clients like [5ire](https://5ire.app/) can use them and the result is the same as using the assistant script.

### Ollama Remote Server

A remote Ollama server may be used:

```shell
python3 assistant.py --ollama-model gpt-oss-20b:32k --ollama-host 192.168.100.100:11434
```

### Google AI

```shell
export GOOGLE_API_KEY=xxxx
python3 assistant.py --gemini-model gemini-flash-latest
```

### OpenAI

Remove the Ollama options. Set the following environment variables before running the MCP server and assistant. The
model may be set using `--openai-model`. The API key must be an environment variable.

```shell
export OPENAI_API_KEY=xxxx
python3 assistant.py --openai-model o3
```

### AWS Bedrock

```shell
python3 assistant.py --bedrock-model global.anthropic.claude-sonnet-4-5-20250929-v1:0
```

## Indexing Data

The MCP tools will index data if appropriate. For example, spidering and directory busting. Data can be indexed by external means using the `/index` endpoint. The endpoint is not part of an MCP tool or protocol.

The `ingest.py` script makes using this endpoint more convenient. It isn't complicated to use directly. The supported data formats are inferred. Katana JSON is the preferred format.

```shell
curl -X POST -H "Content-Type: application/json" http://127.0.0.1:8000/index @katana.json
```

### katana

```shell
cat katana.jsonl | python3 ingest.py --mcp-url http://127.0.0.1:8000/ --katana

# live ingestion:
tail -f katana.jsonl | python3 ingest.py --mcp-url http://127.0.0.1:8000/ --katana
```

### Burp Logger++ CSV

Minimum fields to export:

- Request.AsBase64
- Request.Time
- Request.URL
- Response.AsBase64
- Response.RTT

```shell
cat LoggerPlusPlus.csv | python3 ingest.py --mcp-url http://127.0.0.1:8000/ --csv

# live ingestion using the auto-export feature of Logger++:
tail -f LoggerPlusPlus.csv | python3 ingest.py --mcp-url http://127.0.0.1:8000/ --csv
```

### Extensions

Browser and intercepting proxy extensions are available at the following GitHub repos:
- https://github.com/double16/shyhurricane-chrome
- https://github.com/double16/shyhurricane-firefox
- https://github.com/double16/shyhurricane-burpsuite
- https://github.com/double16/shyhurricane-zap

The browser extensions will forward requests and responses made in Chrome and Firefox to the MCP server for indexing. There
are controls for setting in-scope domains.

The Burp Suite and ZAP extensions will forward both requests/responses and alerts/findings. The alerts are used by the LLM
to improve effectiveness.

## OAST

Out-of-band Application Security Testing allows for callbacks from various payloads, such as XSS.

### webhook_site

The default OAST provider is webhook.site without authentication. There is a limit of 100 requests sent to a single
webhook.site URL. Authentication is also supported.

```shell
# webhook.site (unauthenticated)
OAST_PROVIDER=webhook_site

# webhook.site (with API key)
OAST_PROVIDER=webhook_site
WEBHOOK_API_KEY=xxxxxxxx-xxxx-...
```

### interact.sh

interactsh is supported, but doesn't work so well. Interactions seem to get lost. YMMV.

```shell
OAST_PROVIDER=interactsh
# optional, randomly chosen if not specified
INTERACT_SERVER=oast.pro
# optional
INTERACT_TOKEN=
```

## Status Endpoint

The `/status` endpoint is an HTTP POST endpoint and is not part of the MCP server protocol.

```shell
curl -X POST http://127.0.0.1:8000/status
```

## Proxy Serving Indexed Content

The MCP server exposes a proxy port, `8010` by default, that serves the indexed content. The intent is to use tools on
the indexed content after the fact. For example, to run `nuclei` and feed the findings into the MCP server.

The proxy supports HTTP and HTTPS with self-signed certs. Look for a log line like the following to find the CA cert or
POST an empty body to `/status`. Either your tools can be configured to ignore certificate validation or trust this cert.

```
replay proxy listening on ('127.0.0.1', 8010), CA cert is at /home/user/.local/state/shyhurricane/shyhurricane.db/certs/ca.pem (CONNECT→TLS ALPN: h2/http1.1)
```

An example `curl` call:
```shell
curl -x 127.0.0.1:8010 -k https://example.com
```

Here is an example of using Nuclei on indexed content to submit findings passively:
```shell
nuclei -proxy http://127.0.0.1:8010 -target https://example.com -j | curl http://127.0.0.1:8000/findings -H "Content-Type: text/json" --data-binary @-
```

If a URL or domain isn't indexed, the 404 page will include links to URLs that have been indexed. A tool that spiders
links may use this to find the indexed content.

## MCP Servers

The assistant is intended to exercise the shyhurricane MCP server. However, additional MCP servers may be used by configuring them in a JSON file and passing as an argument to `--mcp-url`. Multiple files may be specified.

See the example below. Environment variables are interpolated in `${}`. The `token` field specifies an `Authorization: Bearer` token to include with requests.

```json
[
  {
    "transport": "stdio",
    "command": "python",
    "args": ["-m", "othermcp.server"],
    "env": {"WORKSPACE_PATH": "/home/user/workspace", "API_KEY": "${API_KEY}"},
    "max_retries": 3
  },
  {
    "transport": "streamable_http",
    "url": "https://mcp.example.com/mcp",
    "token": "Bearer ${TOKEN}",
    "timeout": 60
  },
  {
    "transport": "sse",
    "url": "https://legacy.example.com/sse",
    "token": "${SSE_TOKEN}"
  }
]
```
