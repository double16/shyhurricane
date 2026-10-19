# shyhurricane Change Log

## Unreleased

### Features

- Add a read-only ingestion recovery exporter for `index.jsonl` and `findings.jsonl`,
  preferring original `graph_state` captures and supplementing them from Qdrant, with
  deterministic output and a recovery report describing missing or partial data.
- Pause ingest, graph, and type-specific indexing on configurable low data-directory disk space,
  with automatic recovery margins. Show cached disk readiness in the terminal monitor and `/status`;
  retrieval reports disk-blocked indexing as paused. Submissions and scan/finding workers continue.
- Add opt-in `ENABLE_HEAP_PROFILING` for expensive heap summaries; disable profiling by default,
  independently of diagnostic DEBUG logging. Pass the setting through Docker Compose.
- Replace `--database` with `--data-dir`/`DATA_DIR` across the server and
  graph maintenance commands. Consolidate local application state, including database storage,
  queues, certificates, logs, tool results, and session work. Preserve automatic `/data` detection,
  otherwise use native OS state directories; resolve relative selections beneath that default.
  Keep Compose volume mappings and remote database endpoints. Existing data is not migrated.
- Accept dictionary request bodies in `index_http_url`, using URL form encoding by default and JSON
  serialization for JSON request Content-Types. Store the serialized request body during ingestion.
- Wait up to a configurable 60 seconds for query-relevant indexing before web-resource and graph
  retrieval. Send MCP progress and return explicit indexing status with available results.
  Configure `INDEXING_WAIT_TIMEOUT_SECONDS` or `--indexing-wait-timeout-seconds`; zero disables waiting.
  Persist transactional URL/document scope metadata and backfill outstanding legacy queue records.
- Add persistent Neo4j application graph built incrementally from existing HTTP ingestion,
  with versioned evidence, out-of-order reference reconciliation, shared JavaScript/source-map preparation,
  browser/framework/Vite static analysis, and resumable offline backfill.
- Add read-only graph tools for element discovery, relationships, data-flow traces, possible user journeys,
  and evidence retrieval.
- Rename the monitor tool panel to MCP tools and append the last five completed calls, with
  yellow, green, and red dots for running, complete, and failed calls.
- Add monitor `f` command to mark failed persistent queue items pending, with per-queue results.
  Show scan-finding queue counts and append positive failed counts to persistent queue rows.
- Replace `/status` fields `index_active` and `type_specific_index_active` with `queues`, containing
  pending, processing, and failed counts for ingest, type-specific indexing, scan findings, and graph.
  All queue count fields are present even when zero.
- Add ten MCP assessment prompts for attack-surface mapping, focused vulnerability hunting,
  authentication/configuration reviews, graph data-flow tracing, and vulnerability-chain analysis.
  Accept scoped targets and optional analysis/active modes; render workflows without executing tools.

### Fixes

- Close the ingestion exporter's Qdrant client explicitly; installed client versions do not
  support the context manager protocol and previously caused exports to fail before collection reads.

- Reduce monitoring load with five-minute background graph/reference statistics caches, distinct-URL
  reference lookups, five-second Neo4j statistics transactions without retries, and domain/host-only
  Qdrant payload reads. Preserve cached counts and expose reference freshness and refresh errors.
- Use batched native Qdrant document-ID lookups for ingestion duplicate checks, avoiding unindexed
  payload scans and preserving document order.
- Check pending indexing before treating search targets as absent or offering another scan.
  Preserve an explicit incomplete status when pending content or graph evidence is unavailable.
- Always show the primary Qdrant findings collection count first in dashboard database statistics,
  including when it is zero or outside the top five collections.

## 0.2.0

### Features

- Add `--log-file` and `LOG_FILE` for append-only diagnostic logs at all Python logger levels,
  including logged tracebacks, server access messages, and worker-process logs during dashboard use.
- Add filesystem-backed tool result pagination with opaque next/previous page tokens and `get_result_page`.
  Preserve snapshots across calls and restarts for 24 hours by default; configure `TOOL_RESULT_TTL_SECONDS`.
  Clean expired and corrupt results on startup, shutdown, and before new queries.
- Reduce default search and finding pages to 20 and 10 records; cap enumeration and scan response pages.
  Separate search retrieval depth from page size, and allow list limits down to one result.
- Return structured JavaScript previews and port-scan summaries with saved content/XML navigation.
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

- Handle missing `Content-Type` in `index_http_url` and binary detection. Report invalid request
  inputs, disabled network access, and ingestion failures as explicit tool errors; distinguish
  preview storage failures after queueing and retain original JavaScript on operational command failures.
- Index complete textual URL response bodies independently of preview size and `Content-Length`.
  Limit previews after JavaScript expansion without dropping indexed content.
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
