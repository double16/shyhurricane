# dev mode

python3 virtualenv:

```shell
$(command -v python3.12) -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r tests/requirements.txt
```

Start chroma:

```shell
chroma run --path chroma_store --host 127.0.0.1 --port 8200
```

Start mcp_server:

```shell
python3 mcp_service.py
```

Start MCP dev tool:

```shell
DANGEROUSLY_OMIT_AUTH=true mcp dev mcp_service.py:mcp_instance
```

Start assistant:

```shell
python3 assistant.py --ollama-model qwen3:30b
```

Browse the chroma collections:

```shell
chroma browse --host http://127.0.0.1:8200 content
chroma browse --host http://127.0.0.1:8200 javascript
chroma browse --host http://127.0.0.1:8200 javascript_256
```

# Debugging Model Communication

Sometimes results from the model cannot be parsed.  Use `mitmproxy` to inspect model traffic.

```shell
mitmproxy -w assistant.log
```

This works for haystack-ai components using httpx:

```shell
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
export SSL_CERT_FILE="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
```

# Dev Notes

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
- These are example inputs from the user:
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
