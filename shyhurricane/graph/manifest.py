"""Coarse execution metadata and durable shard-level discovery publication obligations."""

import json
import logging
import time
from contextlib import contextmanager
from pathlib import Path

from shyhurricane.graph.blob_store import BlobStore
from shyhurricane.graph.compact_manifest import initialize as initialize_manifest
from shyhurricane.graph.compact_manifest import term
from shyhurricane.graph.model import capture_unit_path, identity, projection_snapshot

logger = logging.getLogger(__name__)

STATUSES = {"complete", "partial", "pending", "blocked", "failed"}


class ManifestStore:
    def __init__(self, connection, root, *, initialize=True, epoch=0):
        self.connection = connection
        self.root = Path(root)
        self.build_key = "capture"
        self.epoch = epoch
        self.pending = []
        self.reader = None
        from shyhurricane.graph.inventory_outbox import InventoryOutbox
        from shyhurricane.graph.shard_store import ShardStore

        self.shards = ShardStore(root, connection)
        self.outbox = InventoryOutbox(connection, self.shards)
        self.batching = False
        self.atomic = False
        self.writes = 0
        self.term_cache = {}
        self.blobs = BlobStore(connection)
        if not initialize:
            return
        self.connection.executescript(
            "CREATE TABLE IF NOT EXISTS graph_manifest_units ("
            "id TEXT PRIMARY KEY,capture_id TEXT NOT NULL,source_path TEXT NOT NULL,"
            "discovery TEXT NOT NULL,flow TEXT NOT NULL,artifact TEXT,error TEXT NOT NULL DEFAULT '',"
            "updated_at REAL NOT NULL,materialization TEXT NOT NULL DEFAULT 'deferred');"
            "CREATE INDEX IF NOT EXISTS graph_manifest_pending ON graph_manifest_units(id) "
            "WHERE discovery='pending' OR flow='pending';"
            "CREATE INDEX IF NOT EXISTS graph_manifest_capture ON graph_manifest_units(capture_id,id);"
            "CREATE TABLE IF NOT EXISTS graph_manifest_dependencies ("
            "capture_id TEXT NOT NULL,url TEXT NOT NULL,kind TEXT NOT NULL,PRIMARY KEY(capture_id,url,kind));"
            "CREATE INDEX IF NOT EXISTS graph_dependency_url ON graph_manifest_dependencies(url,capture_id);"
        )

        initialize_manifest(self.connection)
        from shyhurricane.graph.inventory_outbox import initialize as initialize_outbox

        initialize_outbox(self.connection)
        self.connection.executescript(
            "CREATE TABLE IF NOT EXISTS graph_inventory_updates("
            "unit_id TEXT,generation TEXT,version INTEGER,delivered INTEGER,metadata TEXT,"
            "PRIMARY KEY(unit_id,generation));"
            "CREATE TABLE IF NOT EXISTS graph_inventory_catalog(id INTEGER PRIMARY KEY,after_seq INTEGER NOT NULL);"
            "INSERT OR IGNORE INTO graph_inventory_catalog VALUES (1,0);"
            "CREATE TABLE IF NOT EXISTS graph_inventory_generations("
            "id TEXT PRIMARY KEY,unit_id TEXT,capture_id TEXT,epoch INTEGER,"
            "metadata TEXT NOT NULL,artifact TEXT,state TEXT NOT NULL DEFAULT 'pending',error TEXT NOT NULL DEFAULT '',"
            "context_after INTEGER NOT NULL DEFAULT 0);"
            "CREATE INDEX IF NOT EXISTS graph_inventory_generation_unit "
            "ON graph_inventory_generations(unit_id,epoch);"
            "CREATE INDEX IF NOT EXISTS graph_inventory_generation_work "
            "ON graph_inventory_generations(state,epoch);"
            "CREATE INDEX IF NOT EXISTS graph_inventory_update_pending "
            "ON graph_inventory_updates(unit_id,generation) WHERE version>delivered;"
        )
        from shyhurricane.graph.blob_store import owner_triggers

        owner_triggers(self.connection, "graph_inventory_generations", "artifact", "id")
        for table in ("graph_archive_progress", "graph_archive_inputs"):
            owner_triggers(self.connection, table, "artifact", "id")

    @contextmanager
    def batch(self, *, atomic=False):
        """Commit discovery in finite chunks, retaining progress if a parser is killed."""
        previous_atomic = self.atomic
        self.atomic = atomic
        previous = self.batching
        if not previous:
            self.writes = 0
        previous_cache = self.term_cache
        self.term_cache = {}
        self.batching = True
        try:
            if atomic and not self.connection.in_transaction:
                self.connection.execute("BEGIN IMMEDIATE")
            yield
            self.flush()
            self.connection.commit()
        except BaseException:
            previous_cache.clear()
            self.connection.rollback()
            self.pending.clear()
            raise
        finally:
            self.atomic = previous_atomic
            self.batching = previous
            self.term_cache = previous_cache

    @contextmanager
    def transaction(self):
        if not self.batching:
            try:
                with self.connection:
                    yield
                    self.flush()
            except BaseException:
                self.pending.clear()
                raise
        else:
            yield
            self.writes += 1
            if self.writes >= 500 and not self.atomic:
                self.flush()
                self.connection.commit()
                self.writes = 0
                self.term_cache.clear()

    def _term(self, value):
        """Reuse interned identifiers within a bounded write transaction."""
        if not self.batching:
            return term(self.connection, value)
        if value not in self.term_cache:
            self.term_cache[value] = term(self.connection, value)
        return self.term_cache[value]

    def unit(self, capture_id, source_path, *, discovery="pending", flow="pending", artifact=None, error=""):
        if discovery not in STATUSES or flow not in STATUSES:
            raise ValueError("Invalid graph coverage status")
        if not self.batching:
            with self.batch(atomic=True):
                return self.unit(capture_id, source_path, discovery=discovery, flow=flow,
                                 artifact=artifact, error=error)
        from shyhurricane.graph.policy import ANALYZER_VERSION

        key = identity("analysis-unit-v2", ANALYZER_VERSION, capture_id, source_path)
        published = self.connection.execute(
            "SELECT artifact FROM graph_inventory_generations WHERE id=? AND state IN ('active','cleaned')",
            (self.generation(key),),
        ).fetchone()
        if published:
            if artifact is not None and published[0] != artifact:
                raise ValueError("Published inventory is immutable; reserve a new analysis generation")
            self.set_status(key, discovery=discovery, flow=flow, error=error)
            return key
        with self.transaction():
            self.connection.execute(
                "INSERT INTO graph_manifest_units(id,capture_id,source_path,discovery,flow,artifact,error,updated_at) "
                "VALUES (?,?,?,?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET discovery=excluded.discovery,flow=excluded.flow,"
                "artifact=coalesce(excluded.artifact,artifact),error=excluded.error,updated_at=excluded.updated_at",
                (key, capture_id, source_path, discovery, flow, artifact, error[:1000], time.time()),
            )
        row = self.connection.execute("SELECT url FROM captures WHERE id=?", (capture_id,)).fetchone()
        if row:
            self.fact(key, capture_id, "analysis_unit", {"id": key, "url": row[0], "source_path": source_path})
        self.describe_generation(key)
        return key

    def set_status(self, unit, *, discovery=None, flow=None, materialization=None, error=""):
        from shyhurricane.graph.inventory_updates import enqueue

        row = self.connection.execute(
            "SELECT discovery,flow,materialization FROM graph_manifest_units WHERE id=?", (unit,),
        ).fetchone()
        if row is None:
            raise ValueError("Analysis unit is unavailable")
        discovery, flow, materialization = discovery or row[0], flow or row[1], materialization or row[2]
        if discovery not in STATUSES or flow not in STATUSES:
            raise ValueError("Invalid graph coverage status")
        with self.transaction():
            self.connection.execute(
                "UPDATE graph_manifest_units SET discovery=?,flow=?,materialization=?,error=?,updated_at=? WHERE id=?",
                (discovery, flow, materialization, error[:1000], time.time(), unit),
            )
            generation = self.connection.execute(
                "SELECT id FROM graph_inventory_generations WHERE unit_id=? AND state<>'cleaned' "
                "ORDER BY epoch DESC,rowid DESC LIMIT 1", (unit,),
            ).fetchone()
            if generation:
                enqueue(self.connection, unit, generation[0], materialization, error, flow=flow, discovery=discovery)

    def describe_generation(self, unit):
        row = self.connection.execute(
            "SELECT u.capture_id,c.url,c.stamp,m.method,u.source_path,u.discovery,u.flow,u.artifact,"
            "u.error,u.materialization FROM graph_manifest_units u JOIN captures c ON c.id=u.capture_id "
            "JOIN graph_capture_metadata m ON m.capture_id=c.id WHERE u.id=?", (unit,),
        ).fetchone()
        if row:
            names = ("capture_id", "url", "observed_at", "method", "source_path", "discovery",
                     "flow", "artifact", "error", "materialization")
            metadata = dict(zip(names, row, strict=True))
            from shyhurricane.graph.policy import ANALYZER_VERSION

            metadata["analyzer_version"] = ANALYZER_VERSION
            with self.transaction():
                self.connection.execute(
                    "INSERT INTO graph_inventory_generations(id,unit_id,capture_id,epoch,metadata,artifact) "
                    "VALUES (?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET metadata=excluded.metadata,artifact=excluded.artifact,"
                    "state=CASE WHEN state='waiting' THEN 'pending' ELSE state END",
                    (self.generation(unit), unit, row[0], self.epoch, json.dumps(metadata), metadata["artifact"]),
                )

    def contexts(self, unit, contexts):
        from urllib.parse import urlsplit

        with self.transaction():
            unit_key = self._term(unit)
            for context in contexts:
                ref = "a:" + identity("context", context)
                ref = self.blobs.put(ref, context)
                self.connection.execute(
                    "INSERT OR IGNORE INTO graph_context_documents(context,url_key,host_key,data) VALUES (?,?,?,?)",
                    (self._term(context["id"]), self._term(context["url"]),
                     self._term(urlsplit(context["url"]).hostname or ""), ref),
                )
                document = self.connection.execute(
                    "SELECT key FROM graph_context_documents WHERE data=?", (ref,)
                ).fetchone()[0]
                self.connection.execute("INSERT OR IGNORE INTO graph_context_members(unit,document) VALUES (?,?)",
                                        (unit_key, document))

    def parent(self, unit, parent):
        with self.transaction():
            self.connection.execute("INSERT OR IGNORE INTO graph_parents(unit,parent) VALUES (?,?)",
                                    (self._term(unit), self._term(parent)))

    def dependency(self, capture, url, kind):
        if kind in {"LOADS", "IMPORTS", "SOURCE_MAP"}:
            with self.transaction():
                self.connection.execute(
                    "INSERT OR IGNORE INTO graph_manifest_dependencies VALUES (?,?,?)", (capture, url, kind)
                )

    def generation(self, unit):
        return identity("inventory-generation", unit, self.epoch, self.build_key)

    def fact(self, unit, capture, kind, data, *, contexts=()):
        payload = {"kind": kind, **data}
        context = payload.pop("context_capture_id", None)
        key = identity("manifest-fact-v1", unit, kind, payload)
        record = {**payload, "manifest_id": key, "analysis_unit_id": unit, "capture_id": capture}
        memberships = sorted({*contexts, *([context] if context else [])})
        if memberships:
            record["_context_ids"] = memberships
        with self.transaction():
            self.pending.append(record)
            if len(self.pending) >= 500:
                self.flush()
        return key

    def facts(self, unit, capture, records):
        if len(records) > 500:
            raise ValueError("Graph fact batches must contain at most 500 records")
        if not self.batching:
            with self.batch(atomic=True):
                return self.facts(unit, capture, records)
        return [self.fact(unit, capture, kind, data) for kind, data in records]

    def flush(self):
        if not self.pending:
            return
        groups = {}
        for record in self.pending:
            groups.setdefault(record["analysis_unit_id"], []).append(record)
        for unit, records in groups.items():
            generation = self.generation(unit)
            sequence = self.connection.execute(
                "SELECT coalesce(max(sequence)+1,0) FROM graph_inventory_outbox WHERE generation=?",
                (generation,),
            ).fetchone()[0]
            self.outbox.enqueue(generation, records, start=sequence)
        self.connection.execute(
            "UPDATE graph_inventory_generations SET state='pending' WHERE state='waiting' AND id IN "
            "(SELECT generation FROM graph_inventory_outbox WHERE state='pending')"
        )
        self.pending.clear()

    def inventory_reader(self):
        if self.reader is None:
            raise RuntimeError("Inventory queries require a bound graph service")
        return self.reader

    def archive(self, projection, writer):
        with self.batch():
            return self._archive(projection, writer)

    def _archive(self, projection, writer):
        path = writer(
            identity("manifest-projection-v1", projection.event["id"], projection_snapshot(projection)),
            projection_snapshot(projection),
        )
        partial = any(
            any(word in gap.lower() for word in ("budget", "unavailable", "unverified", "malformed", "parse failed"))
            for gap in projection.gaps
        )
        unit = self.unit(
            projection.event["id"],
            capture_unit_path(projection.event),
            discovery="complete",
            flow="partial" if partial else "complete",
            artifact=path,
        )
        self.contexts(unit, projection.contexts)
        for node in projection.nodes.values():
            self.fact(unit, projection.event["id"], node["kind"], node)
        for edge in projection.edges.values():
            self.fact(unit, projection.event["id"], "relationship", {**edge, "owner_url": projection.url})
        for source in projection.candidate_sources:
            self.fact(unit, projection.event["id"], "candidate_source", {**source, "owner_url": projection.url})
        return unit

    def watermark(self):
        return self.inventory_reader().watermark()

    def page(self, scope, **arguments):
        with self.blobs.snapshot():
            return self.inventory_reader().page(scope, **arguments)

    def coverage(self, capture_id=None, **arguments):
        return self.inventory_reader().coverage(capture_id, **arguments)
