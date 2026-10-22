# Recover deleted ingestion files

[README](../README.md) · [Documentation index](README.md)

Recover replayable HTTP exchanges and findings from surviving `graph_state` capture artifacts
and a running Qdrant instance:

```shell
uv run python -m shyhurricane.export_ingestion \
  --data-dir /srv/shyhurricane --output-dir ./recovered \
  --qdrant-url http://127.0.0.1:6333
```

The output directory must not already exist. It contains `index.jsonl` (Katana-compatible),
`findings.jsonl` (`target`, `title`, `markdown` records), and `export-report.json` with source
counts, skipped record identifiers, finding provenance, and recovery limitations. Files are private
to the current user because captures may contain credentials or sensitive response bodies.
Exit codes are `0` for a completed export, `2` for a completed export with skipped corrupt or
invalid records, and `1` for a fatal failure without a published export.

The CLI prints elapsed time, phase changes, and progress counts to stderr, including graph backup
pages, captures read, Qdrant records read, reconciliation groups, and records written. Counts update
at most once every five seconds as work advances; phase starts, phase completions, and the final
summary print immediately. Captured URLs, headers, bodies, and finding text are omitted.
Use `--quiet` to suppress progress while retaining errors. Direct Python calls to `export()` remain
silent unless a `Progress` reporter is supplied.

`--data-dir` and `DATA_DIR` follow the [application storage conventions](configuration.md#application-data-directory). Without
`--qdrant-url`, the exporter uses the existing `QDRANT` environment variable, or inspects the
already-running managed container for the selected directory. It never starts containers or
initializes application services. Use `--graph-only` to recover captures without Qdrant; this
produces an empty findings file. No target applications are contacted.

All surviving graph captures are included, including historical captures absent from Qdrant.
Original graph exchanges take precedence over matching stored representations. Backfilled graph
captures are partial representations; unmatched backfills and Qdrant records are retained.
Only unambiguous forms/content matches are combined. Ambiguous representations remain separate
and are counted in the report. Exact exchanges are deduplicated, and output order is deterministic.

Graph metadata is read through a consistent SQLite backup, including committed WAL contents.
The backup deadline defaults to 300 seconds. For large databases or slow storage, increase it
with `--graph-backup-timeout-seconds 1800`. The value must be finite and greater than zero.
Timeout errors show page-copy progress and the retry option; no partial export is published.
Pausing ingestion can also help a busy database complete its consistent backup.
Qdrant collection reads are live and are not an atomic database snapshot. Pause ingestion for a
stable dataset during export. The exporter reads only base content, network, forms, and finding
collections; derived chunks and port scans are not exported.

This is a recovery export, not an exact database backup. Original graph captures retain parsed
request bodies and response bodies; Qdrant-only recovery lacks request bodies and binary response
bodies, and text may already be normalized or JavaScript deobfuscated. Unknown bodies are `null`.
Reingestion can change finding IDs/timestamps, embeddings, generated descriptions, and graph
publications. Stored finding IDs/timestamps remain available in the report. Use database backups
when an exact copy is required.

To load both files into a fresh server:

```shell
uv run python ingest.py \
  --mcp-url http://127.0.0.1:8000/ --katana < recovered/index.jsonl
uv run python ingest.py \
  --mcp-url http://127.0.0.1:8000/ --katana < recovered/findings.jsonl
```

Ingestion is asynchronous. Check `/status` queues and the recovery report before assessing
completeness. Separate ambiguous representations can deduplicate differently during reingestion.
