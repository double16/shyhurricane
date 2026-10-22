# Storage, database tuning, and logging

[README](../README.md) · [Documentation index](README.md)

## Application data directory

Use `--data-dir` or `DATA_DIR` to select the application storage root. The command-line option
wins over the environment variable. Absolute paths are used directly and `~` is expanded.
Relative paths are placed beneath the detected default, regardless of the working directory.
Paths that escape that default through `..` or symbolic links are rejected.

When `/data` exists as a directory, it is automatically the default. Otherwise, defaults are:

| Platform | Default data directory |
|----------|------------------------|
| Linux | `${XDG_STATE_HOME:-~/.local/state}/shyhurricane` |
| macOS | `~/Library/Application Support/shyhurricane` |
| Windows | `%LOCALAPPDATA%\shyhurricane`, falling back to `~/AppData/Local/shyhurricane` |

```shell
# Separate assessment beneath the detected default, shared by all three commands:
uv run python mcp_service.py --data-dir assessment
uv run python -m shyhurricane.graph.backfill --data-dir assessment
uv run python -m shyhurricane.graph.rebuild --data-dir assessment --dry-run

# Or choose an absolute directory:
uv run python mcp_service.py --data-dir /srv/shyhurricane
```

```text
<data-dir>/
  qdrant/                  Managed Qdrant storage
  graph/                   Managed Neo4j storage, including graph/logs/
  queues/<queue-name>/     Persistent ingest, document, finding, and graph queues
  graph_state/             Graph captures, artifacts, and maintenance checkpoints
  logs/                    Diagnostic, indexing, and finding logs
  certs/                   Replay proxy CA and certificates
  tool_cache/              Tool history, cached output, and result_pages/
  sessions/                Container working directories mounted at /work
```

| Environment variable | Default | Description |
|----------------------|---------|-------------|
| `DATA_DIR` | Detected default above | Application storage root; overridden by `--data-dir`; inherited as an absolute path by workers |
| `XDG_STATE_HOME` | `~/.local/state` | Linux state-directory base when `/data` is absent; relative values are ignored |
| `LOCALAPPDATA` | `~/AppData/Local` | Windows state-directory base when `/data` is absent |
| `QDRANT` | Unset; `db:6333` in Compose | External Qdrant `host:port`; managed local storage uses `<data-dir>/qdrant` |
| `QDRANT_ASYNC_TIMEOUT_SECONDS` | `30` | Positive integer transport timeout in seconds for raw async Qdrant clients, including MCP metadata reads; separate from the Haystack document-store timeout and 300-second predicate-query deadline |
| `QDRANT_DOCUMENT_STORE_TIMEOUT_SECONDS` | `120` | Positive integer read/write inactivity timeout in seconds for Haystack Qdrant stores, including ingestion, findings, chunk writes, and duplicate-ID lookups; REST connection establishment is capped at 5 seconds |
| `MCP_SESSION_VOLUME` | Unset; `mcp_session` in Compose | Compose compatibility override for the Docker session volume; local runs bind `<data-dir>/sessions` |

Qdrant document stores allow background operations up to 120 seconds of read/write inactivity,
while REST connection establishment remains capped at 5 seconds. The connect cap also applies
to collection setup; Qdrant's constructor compatibility probe uses its own client behavior.
This is separate from MCP raw-client timeouts and monitor/query deadlines. Successful ingestion
and chunk writes lasting at least 10 seconds produce a WARNING with collection, document ID,
elapsed time, and configured timeout, without logging captured content. Connection failures still propagate immediately;
timeouts remain finite. Both Compose configurations forward the setting. Restart the service to
apply changes; previously failed queue items are not retried automatically.

`--database` and `--graph-database` have been removed from all commands. `QDRANT` and `NEO4J`
accept remote endpoints, not local storage paths. Existing data is not moved, copied, or deleted;
relocate it manually before starting against the new layout.

Docker Compose retains its existing named volumes and storage mappings, including separate
Qdrant, Neo4j, tool-cache, and session storage. Its remaining MCP state defaults to `/data`.
Compose is an exception to physical storage consolidation. External database storage, explicitly
selected diagnostic log files, model caches, and operating-system temporary files also retain
their existing locations.

## Qdrant payload index tuning

Creating collections or repairing missing payload indexes requires Qdrant 1.17 or newer.
The server version is checked before collection creation, explicit recreation, or missing-index
repair; unsupported versions and failed version requests stop the operation before changes.

Integer payload indexes use equality-only settings (`lookup: true`, `range: false`) for
`meta.version`, `meta.port`, and `meta.status_code`. Application queries use equality or membership
for these fields. External range queries on them may be slower. Timestamp float and datetime
indexes retain range and ordering support.

Payload-specific HNSW links remain enabled for `meta.version`, `meta.netloc`, `meta.domain`,
`meta.http_method`, and `meta.status_code`, which directly filter semantic searches. All other
declared payload indexes use `enable_hnsw: false`. Their indexes still support metadata filtering,
facets, ordering, and predicate candidate selection; predicate semantic searches filter the selected
point IDs. These settings avoid unused index structures and graph links during indexing, but do
not provide filesystem compression or guarantee a particular reduction in disk usage.

New collections and missing-index repairs use the same tuned settings. Use fresh collections
and reindex data when adopting this policy; there is no legacy index policy or automatic migration
of already-present indexes. Incompatible base index types still raise an error. No collection
recreation or deletion occurs automatically.

## File logging

Python logger messages at DEBUG and higher are appended to the UTF-8 file
`<data-dir>/logs/shyhurricane.log` by default. Set `LOG_FILE` or pass `--log-file` to override the
destination. The command-line option overrides the environment variable. Parent directories are created;
an unwritable destination stops startup with an error. Each record includes its timestamp, severity,
logger name, process name, and PID. Exceptions logged with exception details include their tracebacks.
The file remains active while the interactive dashboard suppresses console output, and worker
processes inherit the destination. Uvicorn access messages also reach the file during dashboard use.
Neo4j driver logging is limited to WARNING and higher to avoid formatting full graph parameter
payloads. Application graph progress and failure logs remain available.
Missing-property notifications from a new graph database are logged once per property per process;
repeated notifications are suppressed. Other Neo4j warnings and errors remain visible.

| Environment variable | Default                      | Description                                                              |
|----------------------|------------------------------|--------------------------------------------------------------------------|
| `LOG_FILE`           | `<data-dir>/logs/shyhurricane.log` | Diagnostic log path, relative to the working directory or absolute. |
| `LOG_MAX_BYTES` | `10485760` (10 MiB) | Nonnegative byte threshold for rotation; `0` disables rotation. |
| `LOG_BACKUP_COUNT` | `5` | Number of numbered archives retained; must be at least one. |
| `ENABLE_HEAP_PROFILING` | `false` | Enable Python heap summaries and MPS memory stats at existing worker/maintenance checkpoints. Accepts `1`, `true`, `yes`, or `on`, ignoring case and surrounding whitespace. Python heap summaries also require DEBUG logging; MPS stats log at INFO. |

```shell
uv run python mcp_service.py --log-file ./logs/server.log
# Or configure the destination through the environment:
LOG_FILE=./logs/server.log uv run python mcp_service.py
```

For Docker Compose, set `LOG_FILE=/tool_cache/logs/server.log` in `.env` and restart the service.
Both Compose configurations preserve that location in the existing `tool_cache` volume. Read it with:

```shell
docker compose exec mcp tail -F -n 200 /tool_cache/logs/server.log
```

The file uses UTF-8 append mode and rotates automatically at 10 MiB, keeping five backups:
`shyhurricane.log.1` is newest and `shyhurricane.log.5` is oldest. The oldest backup is
deleted on rollover. Custom log destinations use the same numbered suffixes. Archives are
uncompressed. Total retention is approximately 60 MiB; thresholds may be exceeded by individual
records. An existing oversized file is archived intact on subsequent logging, rather than split.

Use `--log-max-bytes` and `--log-backup-count` to override the environment settings.
For example:

```shell
uv run python mcp_service.py --log-max-bytes 52428800 --log-backup-count 3
# Disable rotation while retaining coordinated append logging:
LOG_MAX_BYTES=0 uv run python mcp_service.py
```

The server and workers coordinate writes and rotation using a lock file next to the log.
The directory must permit log and lock creation; access failures stop startup. Leave the lock
file in place while processes are running. Workers inherit the resolved settings. Restart the
whole service after changing settings: every process sharing a log must use identical settings.
Both Compose configurations accept these variables from `.env`. Avoid external rotation of the
same file. Use `tail -F` to continue following the active filename across rotation.

It records Python logging output;
raw subprocess stdout/stderr and exceptions handled without logging are not redirected into it.
The cache's `history.jsonl` remains a separate record of tool calls.

Heap profiling is disabled by default even when diagnostic DEBUG logging is enabled. Set
`ENABLE_HEAP_PROFILING=true` before starting the server to enable it; workers inherit the setting.
Compose accepts the same variable from `.env`. Profiling traverses the Python heap and can slow
large ingests, especially at the type-specific worker's per-document checkpoints. MPS memory stats
also require this setting; other GPU diagnostics are independent of it.
