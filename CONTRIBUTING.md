# dev mode

python3 virtualenv:

```shell
virtualenv --try-first-with $(command -v python3.12) .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r dev_requirements.txt
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
python3 assistant.py --ollama-model qwen3:14b --ollama-host 192.168.68.1:11434
```

Browse the chroma collections:

```shell
chroma browse --host http://127.0.0.1:8200 content
chroma browse --host http://127.0.0.1:8200 javascript
chroma browse --host http://127.0.0.1:8200 javascript_256
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
