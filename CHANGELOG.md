# shyhurricane Change Log

## Unreleased

### Features

- Scan indexed JavaScript with Opengrep, recover source-map files with shuji, and save matches as findings.
- Fetch `.js.map` alongside indexed JavaScript when open-world access is enabled, and use cached Opengrep rules when updates fail.
- Replace Wakaru with webcrack for JavaScript deobfuscation.
- Add a single character command 'l' to the monitor to toggle low power mode.
- Show low power setting status in the TTY monitoring Configuration panel.
- Show the Qdrant data path and endpoint on the same line in the TTY monitoring Configuration panel.
- Show model and Qdrant health states with green and red indicators in the TTY monitoring Configuration panel.
- Pause index workers while Qdrant or the configured LLM is unhealthy, while retaining queued `/index` requests for automatic recovery.
- Add a TTY monitoring dashboard for server configuration, queues, database activity, and MCP tools.
- Migrate generator setup from deprecated `OpenAIGenerator`, `AmazonBedrockGenerator`, and `OllamaGenerator`
  to chat-based generators.
- Add LiteLLM generator support with provider-qualified models and optional proxy configuration.

### Fixes

- Remove unused OAST provider configuration options.
- Prevent the server-context unit test from creating a Docker-managed Qdrant container.
- Select available localhost ports through Python before creating the Docker-managed Qdrant database.
- Probe Qdrant using its configured endpoint after the database is restarted instead of reusing private state from a failed client.
- Allow the health monitor to report Qdrant healthy again after a temporary disconnection.
- Keep the monitoring dashboard running when Qdrant disconnects while loading document counts.
- Keep the health monitor alive when Qdrant disconnects during a health check.
- Prevent persistent queue workers from racing to create queue directories during first-time initialization.
