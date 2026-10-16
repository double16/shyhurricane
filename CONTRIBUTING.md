# dev mode

python3 virtualenv:

```shell
$(command -v python3.14) -m venv .venv
source .venv/bin/activate
uv sync --all-extras
```

Start mcp_server:

```shell
python3 mcp_service.py
```

Start MCP Inspector:

```shell
npx @modelcontextprotocol/inspector
```

The default transport retains legacy HTTP sessions. To exercise modern request-local workflows:

```shell
UV_CACHE_DIR="$PWD/.uv-cache" uv run python mcp_service.py --transport streamable-http-modern
```

Connect a client supporting protocol 2026-07-28 to `/mcp`. With MCP SDK 2.2, `Client(url)` discovers modern
support and `Client(url, mode="legacy")` uses the legacy initialization handshake. Set
`DISABLE_ELICITATION=False` and provide an elicitation callback to test target selection and scan confirmation.
Persistent registration tools are available only to clients with legacy sessions. Use `--transport sse` and
`/sse` to test legacy SSE clients.

The transport tests bind localhost sockets. Run them in an environment that permits loopback listening.
Include `--cov=mcp_service` when collecting coverage to measure the service entry point alongside the package.

## colima docker build cache

The `shyhurricane_unix_command` image can be large (~6GB) and the build cache size may need to be increased. For `colima`, use the following
command and config.

```shell
colima start --edit

docker:
  builder:
    gc:
      enabled: true
      defaultKeepStorage: 10G
```

# Dev Notes

## Quality checks

Install and test the JavaScript graph analyzer before running Python tests that exercise its real AST output:

```shell
npm --prefix src/docker/unix_command/graph-analysis ci --ignore-scripts
npm --prefix src/docker/unix_command/graph-analysis test
```

The Node tests enforce 80% line and branch coverage per analyzer file. Python graph unit tests use
mocked database clients; optional Neo4j integration tests exercise real transactions and temporal queries.

| Environment variable | Default | Description |
|----------------------|---------|-------------|
| `NEO4J_TEST_URI` | Unset; Neo4j integration tests skipped | Bolt URI for an isolated test Neo4j; tests clean only resources under `https://graph-test.invalid/` |
| `GRAPH_ANALYZER_TEST_IMAGE` | Unset; analyzer container test skipped | Built command image containing `/opt/graph-analysis/analyze.cjs`; tests run it with networking disabled |

```shell
NEO4J_TEST_URI=bolt://127.0.0.1:17687 KMP_DUPLICATE_LIB_OK=TRUE UV_CACHE_DIR="$PWD/.uv-cache" \
  uv run pytest tests/graph/test_neo4j_integration.py -q
```

Graph publication integration tests include a 9,905-entity, 20,000-relationship, 15,140-evidence
regression case, generation activation/replay, legacy compatibility, and retained evidence.
For the memory regression, run against a dedicated Neo4j instance with a 512 MiB initial/maximum
heap, 128 MiB page cache, and a 128 MiB transaction budget. Allow at least 2 GiB of container memory
for JVM native overhead; the transaction budget is separate from the container limit. For example:

```shell
docker run -d --name graph-publication-tests --memory=2g -p 127.0.0.1:17687:7687 \
  -e NEO4J_AUTH=none -e NEO4J_server_memory_heap_initial__size=512m \
  -e NEO4J_server_memory_heap_max__size=512m -e NEO4J_server_memory_pagecache_size=128m \
  -e NEO4J_dbms_memory_transaction_total_max=128m neo4j:2026.09.0-community
```

Wait for the container's startup log to report `Started`, run the integration tests above, then
remove only this temporary test container with `docker rm -f graph-publication-tests`.

Run the test suite with the project-local UV cache:

```shell
KMP_DUPLICATE_LIB_OK=TRUE UV_CACHE_DIR="$PWD/.uv-cache" uv run pytest tests/ -q
```

Run Ruff and enforce 80% line and branch coverage for every measured Python file:

```shell
UV_CACHE_DIR="$PWD/.uv-cache" uv run ruff check .
UV_CACHE_DIR="$PWD/.uv-cache" uv run ./.github/scripts/run-python-coverage.sh
UV_CACHE_DIR="$PWD/.uv-cache" uv run python .github/scripts/check-python-coverage-floor.py coverage.json
```

Tests marked `ollama` are skipped unless `--ollama` is supplied and Ollama is reachable. Proxy integration tests skip
only when the environment prohibits loopback socket binding.

## Queries that benefit from longer context

- End-to-end data/taint flow
  “Where does user input from /signup end up being eval’ed?” (requires following variables across multiple
  functions/files.)
- Multi-stage exploit chains
  “Show how weak JWT signing + debug endpoint + S3 creds lead to RCE.” Needs many code/docs sections linked.
- Protocol / state-machine reasoning
  “How does the OAuth handshake proceed across frontend JS, backend handlers, and config?” The steps are scattered.
- Config + code coupling
  “Is CSP configured but bypassed by inline scripts elsewhere?” You need CSP headers + HTML + JS.
- Framework/template inheritance
  “Where is this Twig/React/Handlebars variable sanitised before render?” Base template and partials are far apart.
- Large log or scan result synthesis
  “What ports were open in all scans across the week and which ones changed?” Requires holistic view.
- Spec compliance checks
  “Does this payment flow meet PCI requirements?” Pulls from long policy docs + code.

## Query Expander prompts

The query expander prompts were generated using the following prompts and included the find_web_resources queries seen at runtime.

### javascript

```
Generate a system prompt that takes common vulnerability types and emits 10 javascript code patterns likely to exhibit the vulnerability. The output format must be a JSON list with each pattern as a value.
Refine to include multiple vulnerability types in a single request. In this case, there should be 10 patterns per type.
Can you improve the prompt to infer vulnerabilities from the input, such as "What javascript libraries call eval()" ?
The purpose is to query known javascript files to identify these vulnerabilities.
```

### HTML

```
Generate a system prompt that takes common vulnerability types and emits 10 HTML code patterns likely to exhibit the vulnerability.
- The purpose is to query known HTML content to identify these vulnerabilities.
- The HTML code must not be specific to a particular site, hostname or IP address.
- Infer vulnerabilities from the input, such as "What calls eval()" ?
- Handle multiple vulnerability types in a single input.
- The inputs will not be given separately. The must be inferred from the user text.
- Output the patterns as a list of strings delimitated with lines of "----". Only output the list. Do not include any other text except the list of patterns.
```

### css

```
Generate a system prompt that takes common vulnerability types and emits 10 CSS patterns likely to exhibit the vulnerability.
- The purpose is to query known CSS content to identify these vulnerabilities.
- Infer vulnerabilities from the input
- Handle multiple vulnerability types in a single input.
- The inputs will not be given separately. The must be inferred from the user text.
- Output the patterns as a list of strings delimitated with lines of "----". Only output the list. Do not include any other text except the list of patterns.
```

### network

```
Generate a system prompt that takes common vulnerability types and emits 10 HTTP header names and values likely to exhibit the vulnerability.
- The purpose is to query known network requests and responses to identify these vulnerabilities.
- Limit header names and values to those defined by RFC or seen in the wild.
- Infer vulnerabilities from the input, such as "What enables XSS" ?
- Handle multiple vulnerability types in a single input.
- The inputs will not be given separately. The must be inferred from the user text.
- Output the patterns as a list of strings delimitated with lines of "----". Only output the list. Do not include any other text except the list of patterns.
```

### queries seen from gemini-2.5-flash

```
  - example.com "IDOR" OR "access control" OR "unauthorized"
  - example.com "encryption" OR "cryptographic" OR "sensitive data" OR "weak algorithm" OR "key exposure"
  - example.com "SQL injection" OR "XSS" OR "command injection" OR "LDAP injection" OR "NoSQL injection" OR "XPath injection" OR "code injection" OR "template injection"
  - example.com "insecure design" OR "business logic flaw" OR "design flaw" OR "unhandled exception"
  - example.com "security misconfiguration" OR "default credentials" OR "unpatched" OR "unnecessary features" OR "open port" OR "misconfigured"
  - example.com "outdated component" OR "vulnerable library" OR "known vulnerability" OR "unpatched software"
  - example.com "authentication bypass" OR "session fixation" OR "broken authentication" OR "weak password" OR "credential stuffing" OR "MFA bypass"
  - example.com "insecure deserialization" OR "software integrity" OR "data integrity" OR "untrusted input" OR "supply chain" OR "auto-update"
  - example.com "logging" OR "monitoring" OR "alerting" OR "audit trail" OR "event logs" OR "detection"
  - example.com "SSRF" OR "server-side request forgery" OR "URL parsing" OR "external entity"
  - example.com error
  - example.com debug
  - example.com admin
  - example.com .env
  - example.com api
  - example.com user info
  - example.com config
  - example.com server header
```
