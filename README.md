# shyhurricane

<img src="shyhurricane/assets/shyhurricane.png" alt="Hurricane picking padlock logo" width="150" style="float: left; margin-right:10px;" />

ShyHurricane is an MCP server to assist AI in offensive security testing of web applications. It aims to solve a few problems observed with
LLMs:

1. Spidering and directory busting commands can be quite noisy and long-running. LLMs will go through a few iterations to pick a suitable command and options. The server provides spidering and busting tools to consistently provide the LLM with usable results.
2. Models will also enumerate websites with many curl commands. The server saves and indexes responses to return data without contacting the website repeatedly. Large sites, common with bug bounty programs, are not efficiently enumerated with individual curl commands. 
3. Port scans may take a long time causing the LLM to assume the scan has failed and issue a repeated scan. The port_scan tool provided by the server addresses this.

An important feature of the server is the indexing of website content using embedding models. The `find_web_resources` tool uses LLM prompts to find vulnerabilities specific to content type: html, javascript, css, xml, HTTP headers. The content is indexed when found by the tools. Content may also be indexed by feeding external data into the `/index` endpoint. Formats supported are `katana jsonl`, `hal json` and Burp Suite Logger++ CSV. Extensions exist for Burp Suite, ZAP, Firefox and Chrome to send requests to the server as the site is browsed.

## Tools

The following tools are provided:

| Tool                        | Description                                                                                         | Open World? |
|-----------------------------|-----------------------------------------------------------------------------------------------------|-------------|
| port_scan                   | Performs a port scan and service identification on the target(s), similar to the functions of nmap. | Yes         |
| spider_website              | Spider the website at the url and index the results for further analysis                            | Yes         |
| directory_buster            | Search a website for hidden directories and files.                                                  | Yes         |
| index_http_url              | Index an HTTP URL to allow for further analysis. (aka curl)                                         | Yes         |
| find_wordlists              | Find available word lists for spidering and directory_buster                                        | No          |
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
| deobfuscate_javascript      | De-obfuscate JavaScript content (automatically done during indexing)                                | No          |

## Install

The MCP server itself uses an LLM for light tasks such that the `llama3.2:3b` model is sufficient. Ollama is recommended but not required. OpenAI, Google AI, AWS Bedrock, and LiteLLM models are supported. Docker is required for tool specific commands such as spidering and directory busting.

### Docker Desktop or colima

Docker is required and the quality of the networking stack is important. Docker Desktop is acceptable. On macOS, Apple Virtualization networking has issues. Use `colima` with `qemu` virtualization for better results.

If you use Homebrew, `brew bundle` may be used for installation. Otherwise, use your operating system to install `colima`, `qemu`, `docker`, and `docker-compose`.

Start `colima` with a command such as the following:
```shell
colima start --runtime docker --cpu 4 --disk 50 -m 4 --vm-type qemu
```

### nmap

It is best to run `nmap` on the host. If not installed on the host, the docker container will be used.

### Docker Compose

#### As a Docker Service

Configure one desired provider and model in `.env`:

| Provider | Model variable | Credential and connection variables |
| --- | --- | --- |
| Ollama | `OLLAMA_MODEL=llama3.2:3b` | `OLLAMA_HOST=192.168.253.100:11434` |
| Google AI | `GEMINI_MODEL=gemini-2.5-pro` | `GEMINI_API_KEY` or `GOOGLE_API_KEY` |
| OpenAI | `OPENAI_MODEL=gpt-5-nano` | `OPENAI_API_KEY` |
| AWS Bedrock | `BEDROCK_MODEL=us.meta.llama3-2-3b-instruct-v1:0` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` |
| LiteLLM | `LITELLM_MODEL=anthropic/claude-sonnet-4-6` | `LITELLM_API_KEY`; optionally `LITELLM_API_BASE` for a LiteLLM proxy |

For a direct LiteLLM provider connection, omit `LITELLM_API_KEY` and supply the selected provider's
standard credential environment variable, such as `ANTHROPIC_API_KEY`. When using Docker Compose, use
`LITELLM_API_KEY` and `LITELLM_API_BASE` to connect to a LiteLLM proxy.

Run the MCP server:

```shell
docker compose up -d
```

or to build the images from source:

```shell
docker compose -f docker-compose.dev.yml up -d
```

Add the MCP server to your client of choice at http://127.0.0.1:8000/mcp.

### MCP transports and elicitation

The server uses MCP Python SDK 2.2. Choose the transport with `--transport` or `MCP_TRANSPORT`.
An explicit command-line argument overrides the environment setting.

| Setting | Default | Description |
| --- | --- | --- |
| `MCP_TRANSPORT` | `streamable-http` | `streamable-http`, `sse`, or `streamable-http-modern` |
| `DISABLE_ELICITATION` | `True` in Compose; enabled when unset in source runs | Set `False` to allow the client to ask for a target or scan confirmation |

| Transport | Endpoint | Client state |
| --- | --- | --- |
| `streamable-http` | `/mcp` | Legacy client sessions retain registered headers, hostname mappings, and working directories |
| `sse` | `/sse` | Legacy SSE connections retain client state |
| `streamable-http-modern` | `/mcp` | Stateless preset; every tool call starts with fresh client state |

Both HTTP presets accept legacy and modern protocol requests; the client's protocol version selects the workflow.
Modern clients use the 2026-07-28 protocol and have request-local state under either HTTP preset. Persistent
registration tools are unavailable to those clients. Supply `request_headers` and `additional_hosts` to each operation
that needs them. Working files are removed when the modern call finishes; legacy files last until the session closes.

Start the stateless preset from source:

```shell
UV_CACHE_DIR="$PWD/.uv-cache" uv run python mcp_service.py --transport streamable-http-modern
```

For Docker Compose, set `MCP_TRANSPORT=streamable-http-modern` in `.env` and restart the service. Use `.env.example`
as an example of transport and model settings.

Clients that support elicitation can supply missing target information and confirm scans. Legacy clients use a
callback; modern clients answer the SDK's multi-round input requests. If elicitation is disabled, unsupported,
declined, or cancelled, retrieval returns guidance without automatically starting a scan. Explicit scan tools
remain available when open-world access is enabled.

Modern continuation tokens expire after ten minutes between rounds and are protected with a process-local key.
An interaction interrupted by a server restart must start again. Run one server process; legacy sessions require
requests to reach the process that created them. Streamable HTTP MCP request bodies have the SDK's 4 MiB limit;
the separate `/index` ingestion endpoint is unaffected.

### Run From Source

#### Python Environment

```shell
$(command -v python3.14) -m venv .venv
source .venv/bin/activate
uv sync
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

When started from an interactive terminal, the server displays a `shyhurricane` monitoring dashboard with
configuration, queue, database, indexing, and running MCP tool information. Press `q` to stop the
dashboard and shut down the server. Non-interactive starts, including Docker Compose, continue to use normal logging output.

Ollama with `llama3.2:3b`:
```shell
python3 mcp_service.py
```

OpenAI:
```shell
export OPENAI_API_KEY=xxxx
python3 mcp_service.py --openai-model gpt-4-turbo
```

LiteLLM:
```shell
export ANTHROPIC_API_KEY=xxxx
python3 mcp_service.py --litellm-model anthropic/claude-sonnet-4-6
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

## Indexing Data

The MCP tools will index data if appropriate. For example, spidering and directory busting. Data can be indexed by external means using the `/index` endpoint. The endpoint is not part of an MCP tool or protocol.

JavaScript responses are deobfuscated with webcrack and scanned with Opengrep during ingestion, including in low power
mode. If a source map is indexed, shuji recovers its source files for scanning. When `OPEN_WORLD=true`, indexing a
`.js` URL also attempts to fetch its `.js.map` URL. When `OPEN_WORLD=false`, only maps already supplied through
indexing are used; Opengrep rule updates are still allowed. Scan matches are saved as findings and can be retrieved
with `query_findings`. The command image includes a snapshot of the
[Opengrep rules repository](https://github.com/amplify-security/opengrep-rules); it checks for updates at runtime and
uses the cached snapshot if an update fails.

Indexing workers monitor Qdrant and LLM readiness. If either dependency is unhealthy, `/index` requests continue to be accepted into the persistent queue, but ingest and type-specific indexing pause before consuming new items. Workers resume automatically after both health checks recover; MCP tools retain their existing request and error behavior.

At server startup, ingest, document-type, and scan-finding queues discard all successfully acknowledged records
and vacuum reclaimed space. Runtime cleanup retains the latest 200 successful acknowledgements by queue insertion
order and removes the entire older history without a fixed deletion limit. Cleanup runs after 1,000 processed
items (100 for document-type indexing) or on a 60-second maintenance interval while consumers are running.
Failed acknowledgements, pending items, and items being processed are retained.

```shell
curl -X POST -H "Content-Type: application/json" http://127.0.0.1:8000/index @katana.json
```

The `ingest.py` script makes using this endpoint more convenient. It isn't complicated to use directly. The supported data formats are inferred. Katana JSON is the preferred format.

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
