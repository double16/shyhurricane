# Graph storage implementation and validation

The fresh-store graph architecture uses Neo4j for searchable discovery facts, document membership,
coverage, and publication revisions. SQLite retains scheduling, checkpoints, publication obligations,
artifact ownership, and payload locations. Producer context metadata remains in SQLite for offline
analysis and replay; public inventory queries use Neo4j.

Both SQLite and Neo4j graph stores must be fresh. Populated earlier formats and mismatched assessment
identities are rejected. There is no migration, dual-write backend, deployment, or live replay in this
change. Preserve saved inputs and existing assessments before preparing a fresh deployment.

## Payload storage and filesystem overhead

Compressed values up to 64 KiB remain inline in SQLite. Larger values share append-only segment files,
normally capped at 64 MiB. A larger single value occupies its own sealed segment. Inventory shards
contain at most 500 records or 4 MiB decoded, with bounded single-record exceptions. A shard is a
logical content address rather than a separate filesystem file.

Inventory shards contain independently compressed record frames and an authenticated offset directory.
Focused pages read selected frames rather than decompressing unrelated records. Readers check format,
size, directory digest, frame checksum, record digest, and manifest identity. At most two segment read
handles remain open per shard store; artifact-store shutdown closes them. Captured bodies share content
addresses, and detail recipes refer to retained IR ranges instead of duplicating complete IR.

Tests verify that 1,000 small values create no segment files and forty 128 KiB values share one segment.
This preserves the small-file overhead benefit of the previous SQLite payload store.

## Durability and lifecycle

- Segment bytes and directory entries are synchronized before SQLite commits payload locations.
  The SQLite writer lock serializes appends. Restart recovery trims uncommitted tails; missing
  committed bytes fail explicitly.
- Capture registration commits its inventory obligation atomically. Captured resources become
  discoverable while analysis is pending.
- Archive batches commit payload obligations and progress cursors together. Neo4j commits deterministic
  batch receipts before SQLite acknowledges delivery. Acknowledged obligations release duplicate
  delivery metadata while retaining shard pins and receipt identities.
- Generation activation validates all receipts and switches the unit pointer at one publication revision.
  Context publication advances a durable cursor in batches of at most 500 memberships.
- Continuations retain expiring revision pins. Status changes are versioned separately from immutable
  inventory facts, including publication failures and completed detail materialization.
- Expansion acceptance retains the selected generation's artifact before queue wakeup. Wakeup failure
  leaves a durable job recoverable through worker polling. Cancellation waits for reservation cleanup.
- Cleanup removes relationships before nodes and releases local pins only after a remote cleaned
  tombstone is confirmed. Segment reclamation preserves pinned shards, compacts sparse segments in
  bounded passes, and retains retired files for one hour for existing SQLite readers.

## Query indexes

Indexed scope and membership groups select generations before fact reads. Fact indexes cover generation
counts and ordered seeks within a generation, including kind, role, and URL filters. The seek order
includes the full composite index key; within the fixed generation and filter prefix this preserves the
public manifest-ID order while allowing early termination. Cleanup, capture-version selection,
read-pin expiry, status lookup, and SQLite worker polling have corresponding indexes.

A native query-plan regression adds 8,000 unrelated facts and checks that focused retrieval work stays
bounded. On the full benchmark, a 100-record page performs approximately 103 fact-index hits rather
than scanning all 52,439 matching call facts.

## Performance experiment

The experiment reads retained IR as data and never executes captured JavaScript. It uses 171,175 nodes
and 146,817 edges, fresh scratch SQLite stores, and a separately marked Neo4j test database. The database
has two CPUs, a 1.5 GiB container limit, 384 MiB heap, 128 MiB page cache, and a 64 MiB transaction budget.
The Python client runs on the host. Live stores, configuration, and ingestion queues are untouched.

Three runs per backend reverse the execution order. Timing covers the production archive path and,
for the new backend, complete inventory publication. Parsing and the common bounded traversal-summary
publication are excluded. The previous backend is the checked-in SQLite implementation; the earlier
experiment also measured a separately tuned SQLite archive at 85.59 seconds.

| Measurement | Previous SQLite backend | Native inventory with packed payloads |
|------------|--------------------------|---------------------------------------|
| Median archive plus inventory publication | 113.49 s | 34.90 s |
| Final ordered-reader run | — | 33.85 s |
| Focused 100-record page p95 | approximately 10 ms | approximately 26 ms |
| Full hydration of 52,439 call records | 2.09 s | 6.37 s |
| Local allocated files in the full verification run | 382.4 MiB, 5 files | 229.3 MiB, 7 files, including 2 packed segments |

The publication improvement is 3.25× against the checked-in backend and approximately 2.45× against
that earlier tuned archive. The complete canonical payload digest matches for all 52,439 call records;
focused page IDs and ordering match as well.

Small-page latency is an explicit tradeoff: p95 increases by approximately 16 ms. The final median
page takes 17.9 ms, split into 12.6 ms for database access, including durable revision pins and network
round trips, and 4.5 ms for selected payload reads. Query plans no longer scale with unrelated inventory
or scan every matching fact to produce a page. Do not interpret the publication speedup as a promise of
SQLite lookup-latency parity. Full hydration remains slower and should use bounded public pages.

Local allocation includes SQLite, WAL, and payload files, including reclaimable SQLite allocation. It
excludes Neo4j data and transaction files, which have their own indexes and preallocation. These numbers
do not establish a reduction in total assessment disk space. File-count tests and packed segments address
the filesystem entry constraint independently of database allocation.

## Verification

Unit and dedicated Neo4j tests cover public filtering, paging, historical and as-of selection,
revision-pinned reads, normalized contexts, oversized records, missing and corrupt payloads,
publication replay, generation activation, failed synchronization, process exit before commit,
context restart recovery, expansion acceptance, status updates, compaction, and read-pin cleanup.
Python checks enforce at least 80% statement and branch coverage per changed executable file.

Final verification on November 14, 2026: the complete Python suite passes 3,429 tests, with 165 optional
tests skipped. Coverage passes 3,422 tests with six costly size fixtures excluded from tracing; those
fixtures and the final parser-failure regression pass in the complete untraced run. The repository
coverage checker passes the 80% statement and branch floor for every measured Python file. Ruff,
isort checks for the changed graph and server files, and `git diff --check` pass.
