# shyhurricane

<img src="shyhurricane/assets/shyhurricane.png" alt="Hurricane picking padlock logo" width="150" style="float: left; margin-right:10px;" />

ShyHurricane is an MCP server to assist AI in offensive security testing of web applications.

Web application resources are stored in a vector database. Raw content may be retrieved by filters or embeddings. Relationships
are mapped in a graph database for flow analysis. JavaScript is deobfuscated, reversed from source maps, graphed and
SAST is run (opengrep). There is a simple finding database where SAST results are kept, and results from other tools
such as Burp Suite and ZAP. LLMs are provided with several querying tools to help reason about the security of the
application semantically.

Resources are ingested using provided spider and busting tools, Burp Suite, ZAP, Chrome or Firefox extensions. REST
`/index` and `/finding` endpoints are available for ingesting data too. Formats supported are `katana jsonl`, `hal json` and Burp Suite Logger++ CSV.
The `ingest.py` script converts Burp Suite request/response XML exports for indexing.

## Documentation

See the [documentation index](docs/README.md) for detailed guides and architecture, and
[CONTRIBUTING.md](CONTRIBUTING.md) for development setup.

## Assessment prompts

MCP clients can discover these reusable workflows with `prompts/list` and render them with
`prompts/get`. Rendering produces assessment instructions without running tools or contacting targets.

| Prompt | Purpose |
|--------|---------|
| `map_attack_surface` | Inventory captured endpoints, forms, scripts, services, and assessment opportunities |
| `hunt_vulnerability` | Investigate the supplied `vulnerability_type` using captured content and graph evidence |
| `hunt_xss` | Review reflected, stored, and DOM XSS candidates and source-to-sink paths |
| `hunt_access_control` | Investigate IDOR/BOLA, privileged operations, and authorization boundaries |
| `hunt_injection` | Review SQL, NoSQL, command, and template injection indicators |
| `hunt_ssrf` | Investigate URL-consuming features and possible server-side request boundaries |
| `review_authentication_sessions` | Review login, recovery, OAuth, JWTs, cookies, and session lifecycle |
| `review_configuration_exposure` | Review secrets, sensitive resources, debug interfaces, CORS, and headers |
| `trace_input_to_sink` | Trace graph sources and sinks and inspect supporting evidence |
| `find_vulnerability_chains` | Correlate findings, graph flows, and possible journeys into evidence-supported chains |

| Argument | Required | Meaning |
|----------|----------|---------|
| `target` | Yes, all prompts | Host, domain, IP, netloc such as `app.example.com:8443`, or HTTP(S) URL prefix |
| `mode` | No | `analysis` (default) uses captured evidence; `active` also guides scoped live reconnaissance and validation |
| `vulnerability_type` | Yes, `hunt_vulnerability` only | Free-text vulnerability class or classes to investigate |

Use bracketed IPv6 targets, such as `[2001:db8::1]:8443`. Hostname scopes include subdomains;
explicit ports are retained, and URL prefixes restrict scheme, host, and path. User-supplied narrower
scope still applies. Query strings, fragments, credentials in target URLs, and malformed targets
are rejected.

For example, send `prompts/get` with these parameters:

```json
{"name":"hunt_vulnerability","arguments":{"target":"app.example.com:8443","vulnerability_type":"IDOR"}}
```

For graph-assisted chain analysis with scoped live testing guidance:

```json
{"name":"find_vulnerability_chains","arguments":{"target":"example.com","mode":"active"}}
```

Workflows begin with existing findings and indexed evidence. Analysis mode declines scan confirmations
and makes no target requests. Active mode respects existing confirmations and authorization, uses
available open-world tools, and describes manual checks where those tools cannot perform validation.
Prompts remain available with `OPEN_WORLD=false`; active workflows then continue indexed analysis
and report the limitation. Low-power workflows use predicate-only retrieval and captured content.

All assessment prompts use an endpoint-first graph workflow: overview, focused candidates,
traces, then step evidence. They request full graph details only when needed, distinguish bounded
examples from complete results, and keep navigation hypotheses separate from data-flow evidence.

Prompt workflows name the tool arguments explicitly: continuation results map to `token`, deferred
`analysis_unit_id` values map to `unit_id`, and saved-page tokens map to `page_token`.
Graph discovery and traversal calls retain the assessment `scope`, including when using opaque IDs.
`score_threshold` applies only to finding searches; resource searches use `retrieval_limit`.

Graph paths are investigation candidates, not proof of exploitation. Reports distinguish verified
steps, inferred links, missing prerequisites, and analysis gaps. Workflows direct the client to save
new evidence-backed findings with verification status, avoid duplicates, and keep unsupported
hypotheses in the report. Rendering a prompt alone never saves findings.

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
| find_investigation_targets  | Read ranked finding/graph targets, hotspots, and possible chains.                                    | No          |
| deobfuscate_javascript      | De-obfuscate JavaScript content (automatically done during indexing)                                | No          |
| get_result_page             | Retrieve a saved page using an opaque navigation token.                                             | No          |

### Scan rate limits

`spider_website` and `directory_buster` accept `rate_limit_requests_per_second` as a
non-negative integer. A positive value limits requests/second for that scan; `0` disables
the explicit limit. For spidering, `0` uses a high ceiling of 3000 requests/second because
Katana 1.5.0 crashes with a literal zero. For directory busting, `0` means unlimited.
If omitted or `null`, public targets default to 5 requests/second and non-public targets
retain scanner defaults, including Katana's built-in default with no rate flag supplied.
Concurrent scans have separate budgets. Public-target detection uses the URL hostname or IP,
without DNS lookups or registered address overrides.

For example, use `spider_website(url="https://example.com/", rate_limit_requests_per_second=2)`
to crawl at 2 requests/second, or supply `rate_limit_requests_per_second=0` to use the high ceiling.
See the [tool reference](docs/tool-reference.md#scan-rate-limits) for backend behavior.

### Search and results

Use natural-language queries with `find_web_resources`, or narrow captured content with filters such as
`site:example.com filetype:js -inurl:vendor`. Predicate-only queries also work in low-power mode.

`query_findings` accepts scoped predicates too: `site:example.com inurl:admin -ext:js`.
Start with `site:example.com` to include host-level findings before narrowing by URL.
Plain root URLs search hostname scope, retaining explicit ports; explicit `site:` URLs retain
scheme and path restrictions. Finding searches support `site:`, `inurl:`, and `filetype:`/`ext:`;
the required `query` combines scope predicates and optional natural-language search text, like
`find_web_resources`. For example, use
`query_findings(query="site:example.com session fixation")` for semantic matches.
The former `target` argument has been removed; update clients to use `query`.
Semantic search ranks existing embeddings and saves at most 1,000 matches, with an optional
minimum cosine `score_threshold`. `limit` remains the page size. Results that reach the cap
instruct the caller to narrow the search.
Without semantic text (for example, `query="site:example.com"`), `score_threshold` is ignored
and all scoped findings remain available, including in low-power mode. Semantic search requires normal power mode.
Searches report progress and idle updates; semantic scores indicate similarity, not confidence.
Follow saved pages and check `pagination.retrieval_truncated`: semantic results are bounded,
so page exhaustion does not mean every finding was reviewed.
The finding collection must be rebuilt and findings replayed through the updated saver for this
metadata version; existing records are not migrated. See the tool reference for details.

HTTP `/findings` and MCP `save_finding` submissions are committed to the persistent
`scan_finding_queue` before success is returned. Pending submissions survive restarts; processing
failures remain available for retry using the dashboard. Searchability follows asynchronously.
The `/findings` endpoint accepts `application/json`, `text/json`, and
`application/x-www-form-urlencoded`, including parameters such as `charset=utf-8`.

Finding submissions are deduplicated asynchronously before saving, across MCP, HTTP, and JavaScript
scanner inputs. Repeated Markdown for the same target keeps the first saved finding, including its
title and timestamp. Titles do not affect matching. Line endings, surrounding Markdown whitespace,
hostname case, and HTTP(S) default ports are normalized; URL paths, queries, fragments, and changed
evidence remain distinct. Host-level findings remain distinct from URL findings. This applies to
newly processed submissions; older records are not backfilled or cleaned up.

List tools return saved pages. Follow `pagination.next_page_token` with `get_result_page` to continue
without repeating a scan or query. Keep page tokens private. Retrieval waits briefly for relevant
indexing and reports when results may still be incomplete; avoid starting duplicate scans.

See the [tool reference](docs/tool-reference.md) for search predicates, result limits, pagination,
content retrieval, and indexing-status fields.

## Ranked investigation targets

`find_investigation_targets(scope="example.com")` reads background-ranked finding/graph correlations,
shared hotspots, and possible vulnerability chains. Results include supporting paths, evidence IDs,
priority contributions, missing prerequisites, and freshness/coverage limits. Scores rank investigation
work, not exploit probability. The tool works without model calls or target requests, including in
low-power mode. Pending results fall back to the existing scoped finding and graph tools.

Ranked investigation responses include a contributor `findings` dictionary with original titles,
submitted targets, structured metadata, and category provenance. `category_coverage` reports scoped
categorized, unknown, and metadata-free findings independently of category filters. Contextual hotspots
are capped at priority 20; inspect association basis before inferring composition. Processing completion
does not establish complete evidence. Correlation storage format 4 requires rebuilding assessment storage.
Page-level `follow_up` calls are deduplicated and reference their recommending result IDs.
`binding_status` explains operation matches, and `unknown_categories` groups remaining classification gaps.
Normalized JavaScript and recovered sources retain analyzed-source hashes for coordinate binding;
these graph changes require fresh assessment storage.
Assessment prompts and evidence tools explain that readable JavaScript may differ from deployed
bundles. Source coordinates and hashes identify the analyzed artifact; correlate artifact identity
when validating behavior rather than transferring its line numbers directly to deployed code.


HTTP `/findings` and MCP `save_finding` accept optional structured `metadata`, including scanner rule,
severity, confidence, verification status, affected request method, parameter, CWE, and code location.
Sources can omit unavailable fields. `query_findings` exposes stable finding IDs and this metadata.
Resubmissions fill missing metadata and record conflicts while preserving the original finding.
Use fresh assessment storage for finding version 3; existing payloads remain valid.

See [finding correlation and operations](docs/investigation-targets.md), including the exact contract,
scoring rules, and ready-to-send Codex prompts for [Burp](docs/codex-burp-findings.md) and
[ZAP](docs/codex-zap-findings.md) extension updates.

## Application Relationship Graph

Explore captured resources, forms, fields, scripts, routes, and possible data flows using the
read-only application graph tools. Start with `find_application_endpoints`, inspect focused elements
and relationships, then trace data flow or possible user journeys and review the supporting evidence.
Standalone and inline SVG analysis extracts links, resource dependencies, scripts, and event handlers.
The tools work in low-power mode and do not contact targets. Graph production runs in finite,
restartable epochs: captured inputs are frozen, structural analysis finishes, then inferred links
are published without replacing structural entities. New captures wait for the next epoch;
duplicate deliveries do not restart completed work. Inspect `graph.epoch` in `/status` for progress
and failures. Reference discovery and current-job fields show work before publication;
unchanged Neo4j counts during discovery do not indicate a stall. Upgrading unfinished legacy graph work requires a fresh data directory.
All graph tools share a 120-second request budget after the separately configured indexing wait.
The final five seconds are reserved for continuation checkpoints and saved result pages.
Interrupted queries preserve completed records and report analysis gaps and `time_limit`.
Continuations retain unfinished work; failed checkpoints require restarting and publish no unusable token.
Graph tools continue sending client progress at the established five-second interval.
Blank optional URL, context URL, and method filters behave like omitted filters. Coverage describes
retained analysis units, independently of queued work; proven stale capture-unit statuses are
reconciled automatically in bounded background maintenance.
Graph discovery and traversal tools infer omitted, null, or blank `scope` from a supplied HTTP(S)
URL's hostname and explicit port. Endpoints use `url`; elements use `context_url` before `url`;
relationships use URL-valued `element_id`; flow traces and journeys use URL-valued `start`.
Explicit scope takes precedence. Opaque IDs require explicit scope, and `end` never supplies scope.
For example, `find_application_endpoints(url="https://app.example.com:8443/api/items")` uses
`app.example.com:8443` scope while retaining the exact URL filter.
Discovery inventories and full IR are retained separately from bounded Neo4j summaries. Results report
discovery/flow coverage and deferred analysis units. Use `continue_application_graph_query` for
exploration continuations and `expand_application_graph_analysis` for offline detail expansion.
Graph state uses immutable, compressed SQLite artifacts, normalized discovery indexes, and
incremental storage accounting. Cleanup commits bounded batches and resumes unfinished work.
Recomputable analysis caches have a 256 MiB default budget; captured evidence and offline expansion
artifacts are retained independently. This storage version requires a fresh assessment directory;
existing layouts are rejected without migration. Preserve existing assessment directories.
Graph paths are investigation candidates;
inspect their evidence before treating them as confirmed vulnerabilities.

See the [application graph guide](docs/application-graph.md) for tool arguments and examples,
analysis coverage, architecture, Neo4j configuration, and backfill/rebuild procedures.

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

| Provider    | Model variable                                    | Credential and connection variables                                  |
|-------------|---------------------------------------------------|----------------------------------------------------------------------|
| Ollama      | `OLLAMA_MODEL=llama3.2:3b`                        | `OLLAMA_HOST=192.168.253.100:11434`                                  |
| Google AI   | `GEMINI_MODEL=gemini-2.5-pro`                     | `GEMINI_API_KEY` or `GOOGLE_API_KEY`                                 |
| OpenAI      | `OPENAI_MODEL=gpt-5-nano`                         | `OPENAI_API_KEY`                                                     |
| AWS Bedrock | `BEDROCK_MODEL=us.meta.llama3-2-3b-instruct-v1:0` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`                         |
| LiteLLM     | `LITELLM_MODEL=anthropic/claude-sonnet-4-6`       | `LITELLM_API_KEY`; optionally `LITELLM_API_BASE` for a LiteLLM proxy |

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

The default MCP endpoint is `/mcp`; legacy SSE clients can use `/sse` with `--transport sse`.
Set `MCP_TRANSPORT` or `--transport` to choose a transport. Clients supporting elicitation can
ask for missing targets and scan confirmations when enabled.

See [MCP transports and elicitation](docs/mcp-transports.md) for settings, client compatibility,
request-local state, progress notifications, and deployment limits.

### Run From Source

#### Python Environment

```shell
$(command -v python3.14) -m venv .venv
source .venv/bin/activate
uv sync
```

#### Storage and logging

Use `--data-dir` or `DATA_DIR` to select application storage. Relative names, such as `assessment`,
create separate assessment directories beneath the platform default. Docker Compose retains its
named volumes. Existing data is not migrated automatically.

Use Qdrant 1.17 or newer and fresh collections for the tuned payload index settings. New indexes,
including missing indexes repaired at startup, use the same tuning policy.

Diagnostic logs default to `<data-dir>/logs/shyhurricane.log`. Override the destination with
`--log-file` or `LOG_FILE`. Logs rotate at 10 MiB and retain five numbered backups by default.
Use `--log-max-bytes`/`LOG_MAX_BYTES` and `--log-backup-count`/`LOG_BACKUP_COUNT` to configure
rotation; a byte limit of `0` disables it.

See [storage, database tuning, and logging](docs/configuration.md) for platform defaults,
environment variables, Qdrant requirements, and migration guidance.

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
configuration, queue, database, indexing, and MCP tool information. It refreshes immediately
on startup and every 30 seconds afterward. Press `r` to refresh immediately. Press `q` to stop the
dashboard and shut down the server. Press `f` to mark failed items pending across the ingest,
type-specific indexing, scan-finding, and graph queues, plus failed investigation correlations. The notification reports counts and any
per-queue errors; successful queues are committed even if another queue fails. Retrying preserves
payloads and leaves processing items untouched. Workers pick up pending work asynchronously and
may fail again if the original problem remains. Repeated key presses do not overlap retry operations.

The **MCP tools** panel lists running tools followed by the last five completed calls, newest first.
Yellow dots indicate running tools, green dots indicate completed calls, and red dots indicate
failures (including cancelled calls). History is kept in memory until the server restarts.

Queue status counts include pending and processing items. Each persistent queue row appends
`, N failed` only when its failed count is greater than zero. Scan findings have their own row.
Missing queue databases count as empty; read failures display unavailable. Database statistics always
shows `Findings: <count>` first,
using the primary Qdrant `finding` collection count, followed by the top five other collections.
The finding count is read directly even when retrieval stores have not been initialized.
After the dashboard closes, a log message reports that shutdown
is waiting up to five minutes for current operations to finish. Shutdown stops claiming new work and
allows current operations up to five minutes to finish before terminating remaining workers. Pending
persistent queue items remain available for the next startup. SIGINT and SIGTERM use the same shutdown behavior.
Non-interactive starts, including Docker Compose, continue to use normal logging output.

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

Indexing runs asynchronously and pauses when dependencies are unhealthy or disk space is low.
Incoming submissions remain queued, and indexing resumes when readiness recovers. JavaScript is
transformed and scanned during ingestion; findings are available through `query_findings`.
On macOS, reported free space and disk readiness include capacity macOS expects to reclaim from
purgeable resources, falling back to ordinary free space if that estimate is unavailable.

See [ingestion architecture and operations](docs/ingestion.md) for dependency readiness, disk-space
configuration, JavaScript scanning, queue durability, storage formats, and maintenance.

```shell
curl -X POST -H "Content-Type: application/json" http://127.0.0.1:8000/index @katana.json
```

The `ingest.py` script makes using this endpoint more convenient. Select its input format with `--katana`, `--csv`, or
`--burp-xml`. The `/index` endpoint infers its supported data formats. Katana JSON is the preferred format.

### katana

```shell
cat katana.jsonl | python3 ingest.py --mcp-url http://127.0.0.1:8000/ --katana

# live ingestion:
tail -f katana.jsonl | python3 ingest.py --mcp-url http://127.0.0.1:8000/ --katana
```

### Recover deleted ingestion files

Use the read-only recovery exporter to reconstruct replayable HTTP exchanges and findings from
surviving graph captures and Qdrant. See [ingestion recovery](docs/ingestion-recovery.md) for commands,
prerequisites, recovery limitations, and reingestion instructions.

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

### Burp Suite request/response and issues XML

Export requests and responses as XML from Burp Suite, then ingest the complete export:

```shell
python3 ingest.py --mcp-url http://127.0.0.1:8000/ --burp-xml < export.xml
```

Both base64 and plain-text HTTP messages are supported. Each valid exchange is converted to Katana JSON and sent
to `/index`. Invalid or incomplete items are reported to stderr and skipped. Malformed XML stops ingestion with a
nonzero exit status; exchanges already queued remain queued. XML ingestion requires a complete export rather than
a continuously appended stream. XML exports must be converted through `ingest.py` before submission to `/index`.

Burp `--burp-xml` also detects `<issues>` exports. Findings go to `/findings`, one per evidence request,
with extension-compatible summaries (1,024 characters per body). Complete exchanges also go to `/index`
with full bodies. Both plain-text and base64 exports are accepted.

Incomplete or invalid exchanges are skipped independently of findings. Export time is used for indexed
exchange timestamps, falling back to ingestion time. Finding submission failures are reported and
remaining records continue; malformed XML returns a nonzero exit status.

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

Use `/status` to inspect queue counts, indexing readiness, graph details, and proxy configuration.
See the [status response reference](docs/ingestion.md#status-endpoint) for fields and an example.

## Proxy Serving Indexed Content

The MCP server exposes a proxy port, `8010` by default, that serves the indexed content. The intent is to use tools on
the indexed content after the fact. For example, to run `nuclei` and feed the findings into the MCP server.

The proxy supports HTTP and HTTPS with self-signed certs. Look for a log line like the following to find the CA cert or
POST an empty body to `/status`. Either your tools can be configured to ignore certificate validation or trust this cert.

```
replay proxy listening on ('127.0.0.1', 8010), CA cert is at /home/user/.local/state/shyhurricane/certs/ca.pem (CONNECT→TLS ALPN: h2/http1.1)
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
