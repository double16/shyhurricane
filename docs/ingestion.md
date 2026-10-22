# Ingestion architecture and operations

[README](../README.md) · [Documentation index](README.md)

JavaScript responses are deobfuscated with webcrack and scanned with Opengrep during ingestion, including in low power
mode. If a source map is indexed, shuji recovers its source files for scanning. When `OPEN_WORLD=true`, indexing a
`.js` URL also attempts to fetch its `.js.map` URL. When `OPEN_WORLD=false`, only maps already supplied through
indexing are used; Opengrep rule updates are still allowed. Scan matches are saved as findings and can be retrieved
with `query_findings`. The command image includes a snapshot of the
[Opengrep rules repository](https://github.com/amplify-security/opengrep-rules); it checks for updates at runtime and
uses the cached snapshot if an update fails.

The server starts even when Qdrant is unavailable or still starting. Background health checks retry
Qdrant connectivity and collection initialization before enabling indexing workers.
Indexing workers monitor Qdrant, Neo4j, and LLM readiness. If a dependency is unhealthy, `/index`
requests continue to be accepted into the persistent queue, but ingest, graph, and type-specific indexing
pause. Workers resume automatically after dependency health recovers; MCP tools report their own query errors.

Indexing also pauses when the filesystem containing the resolved data directory has less than
3% free space **or** less than 2 GiB (2,147,483,648 bytes). Ingest, graph, and type-specific
workers finish their current item and stop starting new work. Checks run every 10 seconds;
indexing starts blocked until the first successful check. Disk measurement failures also pause
indexing. Scans and queued finding persistence continue, and incoming submissions are still
accepted into persistent queues, so disk use can continue growing during a pause.

After a disk pause, indexing resumes automatically when **both** enabled limits plus their
recovery margins are met: 4% and 2.5 GiB by default. Dependency readiness and low-power settings
still apply. The guard measures only the data-directory filesystem, not separately mounted
caches or remote database storage.

| Environment variable | Default | Description |
|----------------------|---------|-------------|
| `DISK_MIN_FREE_PERCENT` | `3` | Pause below this free percentage; `0` disables this limit |
| `DISK_MIN_FREE_BYTES` | `2147483648` | Pause below this free byte count (2 GiB); `0` disables this limit |
| `DISK_RESUME_MARGIN_PERCENT` | `1` | Additional percentage points required after a disk pause |
| `DISK_RESUME_MARGIN_BYTES` | `536870912` | Additional bytes required after a disk pause (512 MiB) |

Matching CLI flags (`--disk-min-free-percent`, `--disk-min-free-bytes`,
`--disk-resume-margin-percent`, `--disk-resume-margin-bytes`) override environment values.
All values must be finite and nonnegative; byte values must be integers and the percentage limit
plus margin must not exceed 100. Set both minimums to `0` to disable the guard. Compose accepts
these variables from `.env`; restart the server after configuration changes. For example:

```shell
python3 mcp_service.py --disk-min-free-percent 5 --disk-min-free-bytes 4294967296
```

The terminal monitor shows free capacity, pause reasons, and recovery targets. `/status` includes
an additive `disk` object with `path`, `total_bytes`, `free_bytes`, `free_percent`, `checked_at`
(Unix seconds), `state` (`checking`, `healthy`, `paused`, `disabled`), `error`, and the configured
`min_free_percent`, `min_free_bytes`, `resume_margin_percent`, and `resume_margin_bytes`.
Measurements are cached by the health monitor; before the first check or after a measurement
failure, capacity values are null. `disk` is null if no disk monitor is available.
Retrieval reports `indexing.status="paused"` promptly when relevant indexing remains blocked
by the disk guard, while still returning available results.

Duplicate-document checks use batched native Qdrant point-ID retrieval rather than filtering the
unindexed document-ID payload. Existing collections need no new payload index or reindexing.
The graph artifact store automatically adds a covering `(capture_id, url)` reference index on
first open after upgrading; logs report creation time. Allow time for this one-time index build
on large stores. Captures and queued work are preserved.

Graph link planning selects bounded candidates using the relevant equality index before loading
evidence and contexts by ID. DOM lookups filter elements before pagination, so unrelated code
nodes do not consume the candidate limit. DEBUG logs report selection/hydration timings and counts;
an INFO summary reports planning duration, selection/hydration read counts, candidates, and links. If a selected
generation becomes unavailable before hydration, the worker replans instead of publishing missing
links. No graph backfill or rebuild is required for these query changes.

Queue status counts use a covering SQLite index. Existing ingest, document-type, and scan-finding
queues gain this index automatically during startup, before workers and HTTP serving begin. The first
startup after upgrading scans each database to build the index and may take longer; logs report index
creation and elapsed time. Queue records are preserved.
New indexes include only `status`; SQLite implicitly includes the row ID, which aliases `_id`.
Existing `ack_queue_status_id` indexes on `(status, _id)` remain unchanged.

New and updated ingest, document-type, and scan-finding queue payloads use this storage format:
`object → pickle bytes → zlib compression (level 1) → marker + compressed bytes → base64`.
After base64 decoding, the versioned marker `b"SHQ\x01ZLIB\x00"` identifies compressed data;
only marked payloads are decompressed before unpickling. Existing raw pickle and uncompressed
base64 records remain readable and are compressed only when updated. Compression requires no
additional dependencies or configuration. Older application versions cannot read compressed records.

Dashboard and `/status` queue counts run in background threads using read-only connections. These reads
do not resume items already being processed. HTTP ingestion uses a dedicated writer thread and awaits
one durable commit per item, so queue reads and writes do not block the HTTP event loop. `/index`
returns HTTP 201 after all submitted items commit. If a later item fails or the request is cancelled,
items already committed remain queued; retrying the request can enqueue them again. Shutdown rejects
new writes and drains submitted writes within the existing five-minute shutdown deadline.

At server startup, ingest, document-type, and scan-finding queues discard all successfully acknowledged records
without vacuuming. Runtime cleanup retains the latest 200 successful acknowledgements by queue insertion
order and removes the entire older history without a fixed deletion limit. Cleanup runs after 1,000 processed
items (100 for document-type indexing) or on a 10-minute maintenance interval while consumers are running.
Failed acknowledgements, pending items, and items being processed are retained.
Runtime maintenance vacuums when SQLite reports at least 64 MiB of free pages and those pages represent
at least 25% of the database, or when free pages exceed 1 GiB regardless of the ratio.
These thresholds exclude WAL file size and include space freed by earlier cleanup,
including startup cleanup. Until vacuum runs, free pages remain available for new queue entries. Vacuum can run
while work is pending and may pause processing; its logs report reclaimable space and completion time.

## Status endpoint

The `/status` endpoint accepts HTTP POST requests outside the MCP protocol.

The `/status` response includes a `queues` object. Each queue always includes integer `pending`,
`processing`, and `failed` counts, including zeros. Pending means queued and available to claim;
processing means claimed but not acknowledged; failed means explicitly marked failed. Counts use
indexed, read-only queries in background threads without loading queue payloads or resuming work.
Missing databases count as empty; database read failures return an error instead of zero counts.

```json
{
  "queues": {
    "ingest": {"pending": 12, "processing": 1, "failed": 0},
    "type_specific_index": {"pending": 4, "processing": 0, "failed": 2},
    "scan_findings": {"pending": 0, "processing": 0, "failed": 3},
    "graph": {"pending": 8, "processing": 1, "failed": 0}
  }
}
```

These fields replace `index_active` and `type_specific_index_active`. Other response fields remain
available, including document/domain/host counts, graph details, and proxy configuration.
