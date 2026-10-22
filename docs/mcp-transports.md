# MCP transports and elicitation

[README](../README.md) · [Documentation index](README.md)

The server uses MCP Python SDK 2.2. Choose the transport with `--transport` or `MCP_TRANSPORT`.
An explicit command-line argument overrides the environment setting.

| Setting               | Default                                              | Description                                                              |
|-----------------------|------------------------------------------------------|--------------------------------------------------------------------------|
| `MCP_TRANSPORT`       | `streamable-http`                                    | `streamable-http`, `sse`, or `streamable-http-modern`                    |
| `DISABLE_ELICITATION` | `True` in Compose; enabled when unset in source runs | Set `False` to allow the client to ask for a target or scan confirmation |

| Transport                | Endpoint | Client state                                                                                 |
|--------------------------|----------|----------------------------------------------------------------------------------------------|
| `streamable-http`        | `/mcp`   | Legacy client sessions retain registered headers, hostname mappings, and working directories |
| `sse`                    | `/sse`   | Legacy SSE connections retain client state                                                   |
| `streamable-http-modern` | `/mcp`   | Stateless preset; every tool call starts with fresh client state                             |

Both HTTP presets accept legacy and modern protocol requests; the client's protocol version selects the workflow.
Modern clients use the 2026-07-28 protocol and have request-local state under either HTTP preset. Persistent
registration tools are unavailable to those clients. Supply `request_headers` and `additional_hosts` to each operation
that needs them. Working files are removed when the modern call finishes; legacy files last until the session closes.

Start the stateless preset from source:

```shell
uv run python mcp_service.py --transport streamable-http-modern
```

For Docker Compose, set `MCP_TRANSPORT=streamable-http-modern` in `.env` and restart the service. Use `.env.example`
as an example of transport and model settings.

Clients that support elicitation can supply missing target information and confirm scans. Legacy clients use a
callback; modern clients answer the SDK's multi-round input requests. If elicitation is disabled, unsupported,
declined, or cancelled, retrieval returns guidance without automatically starting a scan. Explicit scan tools
remain available when open-world access is enabled.

Search, spidering, and directory busting send status messages through MCP progress notifications.
These tools, port scanning, JavaScript deobfuscation, and URL indexing also send a progress notification
after 20 seconds without another progress update while a call is running. Informative updates reset
the idle deadline, and nested operations share one timer. Quick tools such as `find_wordlists` do not
send idle notifications. The interval depends on event-loop scheduling and transport availability.
All six application-graph tools also send progress every five seconds while running, including
blocked database reads, with stage/read counts as batches complete. Progress counters are scoped to
the request and shared with indexing notifications. Progress delivery failures do not fail queries.
Clients must request progress updates to receive these messages; server logging remains available.
Progress can prevent a client inactivity timeout when supported, but cannot override a fixed request
deadline. Saved-page navigation reads already completed results and does not repeat graph queries.
Progress values count status events and do not estimate the total work.

Modern continuation tokens expire after ten minutes between rounds and are protected with a process-local key.
An interaction interrupted by a server restart must start again. Run one server process; legacy sessions require
requests to reach the process that created them. Streamable HTTP MCP request bodies have the SDK's 4 MiB limit;
the separate `/index` ingestion endpoint is unaffected.
