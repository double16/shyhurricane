# shyhurricane

ShyHurricane is an MCP server to assist AI in offensive security testing. It aims to solve a few problems observed with
AI using a single tool to execute commands:

1. Spidering and directory busting commands can be quite noisy and long-running. AI models will go through a few iterations to pick a suitable command and options. The server provides spidering and busting tools to consistently provide the AI with usable results.
2. Models will also enumerate websites with many curl commands. The server saves and indexes responses to return data without contacting the website repeatedly. Large sites, common with bug bounty programs, are not efficiently enumerated with individual curl commands. 
3. Port scans may take a long time causing the AI to assume the scan has failed and issue a repeated scan. The port_scan tool provided by the server addresses this.

An important feature of the server is the indexing of website content using LLM embedding models. The find_web_resources tool uses LLM prompts to find vulnerabilities specific to content type: html, javascript, css, xml, HTTP headers. The content is indexed when found by the tools. Content may also be indexed by feeding external data into the `/index` endpoint. Formats supported are `katana jsonl`, `hal json` and Burp Suite Logger++ CSV. Extensions exist for Burp Suite, ZAP, Firefox and Chrome to send requests to the server as the site is browsed.

## Tools

The following tools are provided:

| Tool                       | Description                                                                                         | Open World? |
|----------------------------|-----------------------------------------------------------------------------------------------------|-------------|
| run_unix_command           | Run a Linux or macOS command and return its output.                                                 | Yes         |
| port_scan                  | Performs a port scan and service identification on the target(s), similar to the functions of nmap. | Yes         |
| spider_website             | Spider the website at the url and index the results for further analysis                            | Yes         |
| directory_buster           | Search a website for hidden directories and files.                                                  | Yes         |
| index_http_url             | Index an HTTP URL to allow for further analysis. (aka curl)                                         | Yes         |
| find_wordlists             | Find available word lists for spidering and `run_unix_command`                                      | No          |
| find_web_resources         | Query indexed resources about a website using natural language .                                    | No          |
| fetch_web_resource_content | Fetch the content of a web resource that has already been indexed.                                  | No          |
| find_domains               | Query indexed resources for a list of domains.                                                      | No          |
| find_hosts                 | Query indexed resources for a list of hosts for the given domain.                                   | No          |
| find_netloc                | Query indexed resources for a list of network locations, i.e. host:port, for a given domain.        | No          |
| find_urls                  | Query indexed resources for a list of URLs for the given host or domain.                            | No          |
| register_hostname_address  | Registers a hostname with an IP address.                                                            | No          |
| save_finding               | Save findings as a markdown.                                                                        | No          |
| query_findings             | Query for previous findings for a target.                                                           | No          |
| web_search                 | Searches the web with the provided query.                                                           | Yes         |
| deobfuscate_javascript     | De-obfuscate a JavaScript file (automatically done during indexing)                                 | No          |
| prompt_chooser             | Chooses the best prompt for an offensive security operation.                                        | No          |
| prompt_list                | Provides a list of available prompt titles for offensive security operations.                       | No          |
| encoder_decoder            | Transforms the input by applying common operations.                                                 | No          |
| channel_create_forward     | Create a forward channel backed by a local subprocess.                                              | Yes         |
| channel_create_reverse     | Create a reverse channel for one duplex client                                                      | Yes         |
| channel_poll               | Long-poll for events from a channel                                                                 | Yes         |
| channel_send               | Write bytes to a channel's stdin                                                                    | Yes         |
| channel_status             | Check whether a channel is established and ready for send/receive.                                  | Yes         |
| channel_close              | Close a specific channel                                                                            | Yes         |
| channel_close_all          | Close all channels                                                                                  | Yes         |
| oast_health                | Check the health/reachability of the currently configured OAST provider.                            | Yes         |
| oast_endpoints             | Get the endpoints that can be used to test out-of-band interactions from the target.                | Yes         |
| oast_poll                  | Retrieve new interactions with the OAST service since the last poll.                                | Yes         |


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

The MCP server itself uses an LLM for light tasks such that the `llama3.2:3b` model is sufficient. Ollama is recommended but not required. OpenAI and Google AI models are also supported. Docker is required to run the generic unix commands.

### Docker Desktop or colima

Docker is required and the quality of the networking stack is important. Docker Desktop is accepted.  On macOS, Apple Virtualization networking has issues. Use `colima` with `qemu` virtualization.

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

#### Chroma Database

Chroma is part of the python environment.

```shell
chroma run --path chroma_store --host 127.0.0.1 --port 8200 
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
python3 mcp_service.py --openai-model=gpt-4-turbo
```

Google AI:
```shell
export GOOGLE_API_KEY=xxxx
python3 mcp_service.py --gemini-model=gemini-2.0-flash
```

## Disabling Open World Tools

Open-world tools allow the AI to reach out to the Internet for spidering, directory busting, etc. There are use cases where this is undesired and only indexed content should be used.

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

## Run the assistant

The assistant provides a command line chat prompt. It isn't elaborate but provides an easy way to use the MCP server. The server prompts MCP prompts for offensive security and the assistant will chose an appropriate system prompt for the first user prompt.

The assistant should use a larger reasoning model than the MCP server. This model performs the real work of find vulnerabilities and exploits.

```shell
$(command -v python3.12) -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 assistant.py --ollama-model qwen3:30b
```

Give the assistant instructions like:
- Solve the CTF challenge at 10.129.10.10
- Solve the HTB CTF challenge at 10.129.10.10  (Hack-the-Box specific agent)
- Help me find vulns at https://example.com  (chat)
- Find all the vulns at https://example.com  (agent)

### Ollama Remote Server

A remote Ollama server may be used:

```shell
python3 assistant.py --ollama-model qwen3:30b --ollama-host 192.168.100.100:11434
```

### Google AI

```shell
export GOOGLE_API_KEY=xxxx
python3 assistant.py --gemini-model gemini-2.5-flash
```

### OpenAI

Remove the Ollama options. Set the following environment variables before running the MCP server and assistant. The
model may be set using `--openai-model`. The API key must be an environment variable.

```shell
export OPENAI_API_KEY=xxxx
python3 assistant.py --openai-model o3
```

## Indexing Data

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

Extensions are available at the following GitHub repos:
- https://github.com/double16/shyhurricane-burpsuite
- https://github.com/double16/shyhurricane-zap
- https://github.com/double16/shyhurricane-chrome
- https://github.com/double16/shyhurricane-firefox

## OAST

Out-of-band Application Security Testing allows for callbacks from various payloads, such as XSS.

### webhook_site

This is the default.

```shell
# webhook.site (unauthenticated)
OAST_PROVIDER=webhook_site

# webhook.site (with API key)
OAST_PROVIDER=webhook_site
WEBHOOK_API_KEY=xxxxxxxx-xxxx-...
```

### interact.sh

```shell
OAST_PROVIDER=interactsh
# optional, randomly chosen if not specified
INTERACT_SERVER=oast.pro
# optional
INTERACT_TOKEN=
```

## Proxy Serving Indexed Content

The MCP server exposes a proxy port, `8010` by default, that serves the indexed content. The intent is use tools on
the indexed content after the fact. For example, to run `nuclei` and feed the findings into the MCP server.

The proxy supports HTTP and HTTPS with self-signed certs. Look for a log line like the following to find the CA cert. Either
your tools can be configured to ignore certificate validation or trust this cert.

```
replay proxy listening on ('127.0.0.1', 8010), CA cert is at /home/user/.local/state/shyhurricane/127.0.0.1_8200/certs/ca.pem (CONNECT→TLS ALPN: h2/http1.1)
```

An example `curl` call:
```shell
curl -x 127.0.0.1:8010 -k https://example.com
```

Here is an example of using Nuclei on indexed content to submit findings passively:
```shell
nuclei -proxy http://127.0.0.1:8010 -target https://example.com -j | curl http://127.0.0.1:8000/findings -H "Content-Type: text/json" --data-binary @-
```
