# shyhurricane Change Log

## Unreleased

### Features

- Add hard search predicates to `find_web_resources`: `site:`, `inurl:`, `filetype:`/`ext:`, `mime:`,
  `method:`, `status:`, and `type:`, with quoted values, exclusions, and predicate-only low-power retrieval.
- Add an `r` keyboard shortcut to refresh the monitoring dashboard immediately.
- Accept Burp Suite request/response XML exports in `ingest.py` with `--burp-xml`.
- Use a shared UTC startup timestamp for index and finding JSONL log filenames.
- Compress new and updated persistent queue payloads with zlib level 1 before base64 encoding;
  use a versioned marker and continue reading existing raw pickle and uncompressed base64 records.
- Upgrade the MCP Python SDK to 2.2.0 and support modern multi-round target selection and scan confirmation.
- Add the `streamable-http-modern` transport preset and `MCP_TRANSPORT` configuration.
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

- Distinguish queries with no matches from targets with no indexed documents in `find_web_resources`;
  recommend populating the index only for unindexed targets.
- Send idle MCP progress every 20 seconds for scans, search, JavaScript deobfuscation, and URL indexing;
  existing progress resets the deadline, and search target detection runs asynchronously.
- Upgrade Haystack to 3.3 with native document IDs and splitting behavior while retaining provider
  settings and synchronous pipelines; release provider resources after workers drain.
- Replace deprecated MCP client logging with progress notifications for search, spidering, and directory busting.
- Refresh the monitoring dashboard every 30 seconds instead of every 5 seconds to reduce polling overhead.
- Create new persistent queue indexes on `status` alone, retaining existing `(status, _id)` indexes.
- Index persistent queue status counts and move HTTP ingest writes and queue reporting off the event loop
  to keep acceptance responsive with large queues; reporting no longer resumes processing items.
- Shut down nested indexing workers without orphaned Python processes; allow current work up to five minutes
  to finish when quitting, and retain pending persistent queue items for restart.
- Increase the default runtime queue cleanup interval from 60 seconds to 10 minutes.
- Skip queue vacuuming at startup and vacuum during runtime with at least 64 MiB and 25% free database pages,
  or more than 1 GiB of free pages regardless of the ratio.
- Remove the persistent queue cleanup deletion cap, retain 200 successful acknowledgements at runtime,
  clear successful history on startup, and maintain the scan-finding queue.
- Require scan confirmation when indexed retrieval has no data; unavailable elicitation no longer starts a scan.
- Remove unused OAST provider configuration options.
- Prevent the server-context unit test from creating a Docker-managed Qdrant container.
- Select available localhost ports through Python before creating the Docker-managed Qdrant database.
- Probe Qdrant using its configured endpoint after the database is restarted instead of reusing private state from a failed client.
- Allow the health monitor to report Qdrant healthy again after a temporary disconnection.
- Keep the monitoring dashboard running when Qdrant disconnects while loading document counts.
- Keep the health monitor alive when Qdrant disconnects during a health check.
- Prevent persistent queue workers from racing to create queue directories during first-time initialization.
