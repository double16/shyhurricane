"""Durable paged discovery facts and addressable analysis units, independent of Neo4j limits."""

import json
import logging
import time
from contextlib import contextmanager
from pathlib import Path

from shyhurricane.graph.blob_store import BlobStore
from shyhurricane.graph.compact_manifest import initialize as initialize_manifest
from shyhurricane.graph.compact_manifest import term
from shyhurricane.graph.model import capture_unit_path, identity, optional_filter, projection_snapshot

logger = logging.getLogger(__name__)

STATUSES = {"complete", "partial", "pending", "blocked", "failed"}
PAGE_BYTES = 4 * 1024 * 1024


CAPTURE_SELECTION = (
    "c.rowid<=:captures AND (:as_of IS NULL OR c.stamp<=:as_of) AND (:historical OR NOT EXISTS ("
    "SELECT 1 FROM captures newer LEFT JOIN graph_capture_metadata nm ON nm.capture_id=newer.id "
    "LEFT JOIN graph_capture_metadata cm ON cm.capture_id=c.id "
    "WHERE newer.rowid<=:captures AND newer.url=c.url "
    "AND coalesce(nm.method,'GET')=coalesce(cm.method,'GET') "
    "AND (:as_of IS NULL OR newer.stamp<=:as_of) "
    "AND (newer.stamp>c.stamp OR (newer.stamp=c.stamp AND newer.id<c.id))))"
)


class ManifestStore:
    def __init__(self, connection, root, *, initialize=True):
        self.connection = connection
        self.root = Path(root)
        self.batching = False
        self.writes = 0
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

    @contextmanager
    def batch(self):
        """Commit discovery in finite chunks, retaining progress if a parser is killed."""
        previous = self.batching
        self.batching = True
        try:
            yield
            self.connection.commit()
        except BaseException:
            self.connection.rollback()
            raise
        finally:
            self.batching = previous

    @contextmanager
    def transaction(self):
        if not self.batching:
            with self.connection:
                yield
        else:
            yield
            self.writes += 1
            if self.writes >= 500:
                self.connection.commit()
                self.writes = 0

    def unit(self, capture_id, source_path, *, discovery="pending", flow="pending", artifact=None, error=""):
        if discovery not in STATUSES or flow not in STATUSES:
            raise ValueError("Invalid graph coverage status")
        from shyhurricane.graph.policy import ANALYZER_VERSION

        key = identity("analysis-unit-v2", ANALYZER_VERSION, capture_id, source_path)
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
        return key

    def contexts(self, unit, contexts):
        from urllib.parse import urlsplit

        with self.transaction():
            unit_key = term(self.connection, unit)
            for context in contexts:
                ref = "a:" + identity("context", context)
                ref = self.blobs.put(ref, context)
                self.connection.execute(
                    "INSERT OR IGNORE INTO graph_context_documents(context,url_key,host_key,data) VALUES (?,?,?,?)",
                    (term(self.connection, context["id"]), term(self.connection, context["url"]),
                     term(self.connection, urlsplit(context["url"]).hostname or ""), ref),
                )
                document = self.connection.execute(
                    "SELECT key FROM graph_context_documents WHERE data=?", (ref,)
                ).fetchone()[0]
                self.connection.execute("INSERT OR IGNORE INTO graph_context_members(unit,document) VALUES (?,?)",
                                        (unit_key, document))

    def parent(self, unit, parent):
        with self.transaction():
            self.connection.execute("INSERT OR IGNORE INTO graph_parents(unit,parent) VALUES (?,?)",
                                    (term(self.connection, unit), term(self.connection, parent)))

    def dependency(self, capture, url, kind):
        if kind in {"LOADS", "IMPORTS", "SOURCE_MAP"}:
            with self.transaction():
                self.connection.execute(
                    "INSERT OR IGNORE INTO graph_manifest_dependencies VALUES (?,?,?)", (capture, url, kind)
                )

    def fact(self, unit, capture, kind, data, *, contexts=()):
        from urllib.parse import urlsplit

        # Context membership is normalized; neither membership nor IDs depend on visitation order.
        payload = {"kind": kind, **data}
        contextual = payload.pop("context_capture_id", None)
        key = identity("manifest-fact-v1", unit, kind, payload)
        value = json.dumps(payload, sort_keys=True)
        url = data.get("url") or data.get("owner_url") or ""
        with self.transaction():
            if len(value.encode()) > PAGE_BYTES:
                oversized = "a:" + identity("manifest-blob", key)
                oversized = self.blobs.put(oversized, payload)
                payload = {"id": key, "artifact": oversized, "oversized": True}
            reference = "a:" + identity("manifest-payload", payload)
            reference = self.blobs.put(reference, payload)
            self.connection.execute(
                "INSERT OR IGNORE INTO graph_facts(id,unit,capture,kind_key,url_key,host_key,role_key,data,method,captured) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (key, term(self.connection, unit), term(self.connection, capture), term(self.connection, kind),
                 term(self.connection, url), term(self.connection, urlsplit(url).hostname or ""),
                 term(self.connection, data.get("role") or ""), reference,
                 str(data.get("method") or "GET").upper(), int(data.get("capture_status") == "captured")),
            )
            fact = self.connection.execute("SELECT seq FROM graph_facts WHERE id=?", (key,)).fetchone()[0]
            for context in {*contexts, *([contextual] if contextual else [])}:
                self.connection.execute("INSERT OR IGNORE INTO graph_fact_contexts(fact,context) VALUES (?,?)",
                                        (fact, term(self.connection, context)))
        return key

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
        return {
            name: self.connection.execute(f"SELECT coalesce(max({sequence}),0) FROM {table}").fetchone()[0]
            for name, table, sequence in (
                ("facts", "graph_facts", "seq"),
                ("captures", "captures", "seq"),
                ("memberships", "graph_fact_contexts", "seq"),
                ("units", "graph_context_members", "seq"),
                ("parents", "graph_parents", "seq"),
            )
        }

    def page(
        self,
        scope,
        *,
        kind=None,
        role=None,
        capture_id=None,
        after="",
        limit=1000,
        url=None,
        method=None,
        historical=False,
        as_of=None,
        watermark=None,
        kinds=None,
        context_url=None,
        exclude_kinds=(),
    ):
        from urllib.parse import urlsplit

        from shyhurricane.graph.query import scope_predicate

        if not 1 <= limit <= 1000:
            raise ValueError("Manifest page size must be between 1 and 1000")
        url, method, context_url = map(optional_filter, (url, method, context_url))
        matches = scope_predicate(scope)
        self.connection.create_function("graph_in_scope", 1, matches, deterministic=True)
        host = urlsplit(scope if "://" in scope else "https://" + scope).hostname
        watermark = self.watermark() if watermark is None else watermark
        # Select a finite physical batch first. Optional predicates must not hide equality
        # lookups behind ORs: SQLite otherwise prefers the global ID index even for one URL.
        parameters = {
            **watermark, "host": host, "after": after, "kind": kind, "role": role,
            "capture": capture_id, "url": url, "method": method.upper() if method else None,
            "as_of": as_of, "historical": historical, "context": context_url,
        }
        filters = ["f.id>:after", "f.rowid<=:facts"]
        candidate_filters = list(filters)
        for column, value in (("kind", kind), ("role", role), ("capture_id", capture_id), ("url", url)):
            if value is not None:
                filters.append(f"f.{column}=:{'capture' if column == 'capture_id' else column}")
        if kinds:
            filters.append("f.kind IN (SELECT value FROM json_each(:kinds))")
            parameters["kinds"] = json.dumps(kinds)
        if exclude_kinds:
            filters.append("f.kind NOT IN (SELECT value FROM json_each(:excluded))")
            parameters["excluded"] = json.dumps(exclude_kinds)
        if method is not None:
            filters.append("f.method=:method")
        # Kind predicates use the existing host/kind index when no exact URL is supplied.
        # Roles, methods, and capture IDs are checked after the finite physical batch.
        if kind is not None:
            candidate_filters.append("f.kind=:kind")
        if kinds:
            candidate_filters.append("f.kind IN (SELECT value FROM json_each(:kinds))")
        if exclude_kinds:
            candidate_filters.append("f.kind NOT IN (SELECT value FROM json_each(:excluded))")
        # Resolve interned keys before seeking compact indexes; no payload decoding here.
        candidates_where = ["f.id>:after", "f.seq<=:facts"]
        if kind is not None:
            candidates_where.append("f.kind_key=(SELECT key FROM graph_terms WHERE value=:kind)")
        if kinds:
            candidates_where.append("f.kind_key IN (SELECT key FROM graph_terms "
                                    "WHERE value IN (SELECT value FROM json_each(:kinds)))")
        if exclude_kinds:
            candidates_where.append("f.kind_key NOT IN (SELECT key FROM graph_terms "
                                    "WHERE value IN (SELECT value FROM json_each(:excluded)))")
        if url is not None:
            candidates_where.append("f.url_key=(SELECT key FROM graph_terms WHERE value=:url)")
        if kind == "resource" and url is None:
            candidates_where.append("f.host_key IN (SELECT key FROM graph_terms "
                                    "WHERE value=:host OR value LIKE :subdomains)")
            parameters["subdomains"] = "%." + host
        started = time.monotonic()
        candidates = self.connection.execute(
            "SELECT f.id FROM graph_facts f WHERE " + " AND ".join(candidates_where)
            + " ORDER BY f.id LIMIT 1001", parameters,
        ).fetchall()
        logger.debug("Graph manifest stage=candidates count=%s seconds=%.3f", len(candidates),
                     time.monotonic() - started)
        selected = [row[0] for row in candidates[:1000]]
        if not selected:
            return [], None
        parameters["selected"] = json.dumps(selected)
        # Each context lookup starts from a unit or fact key. Never construct the global
        # memberships union (which can contain millions of rows) for a small result page.
        memberships = (
            "SELECT m.url FROM graph_unit_contexts m JOIN documents d ON d.id=m.context_id "
            "WHERE m.unit_id=f.unit_id AND m.rowid<=:units "
            "UNION ALL SELECT d.url FROM graph_manifest_contexts m "
            "JOIN documents d ON d.id=m.context_id WHERE m.fact_id=f.id AND m.rowid<=:memberships "
            "UNION ALL SELECT m.url FROM graph_unit_parents parent "
            "JOIN graph_unit_contexts m ON m.unit_id=parent.parent_id "
            "JOIN documents d ON d.id=m.context_id WHERE parent.unit_id=f.unit_id "
            "AND parent.rowid<=:parents AND m.rowid<=:units"
        )
        scope_filter = "graph_in_scope(f.url)"
        if kind != "resource":
            scope_filter += " OR EXISTS (SELECT 1 FROM (" + memberships + ") WHERE graph_in_scope(url))"
        context_filter = ""
        if context_url is not None:
            context_filter = (
                " AND (c.url=:context OR EXISTS (SELECT 1 FROM (" + memberships + ") WHERE url=:context))"
            )
        started = time.monotonic()
        rows = self.connection.execute(
            "WITH documents AS MATERIALIZED (SELECT c.id,c.url FROM captures c WHERE "
            + CAPTURE_SELECTION + ") "
            "SELECT f.id,f.unit_id,f.capture_id,f.data,f.url,0 "
            "FROM graph_manifest_facts f JOIN documents c ON c.id=f.capture_id "
            "WHERE f.id IN (SELECT value FROM json_each(:selected)) AND " + " AND ".join(filters)
            + " AND (" + scope_filter + ")" + context_filter + " ORDER BY f.id", parameters,
        ).fetchall()
        logger.debug("Graph manifest stage=selection candidates=%s matched=%s seconds=%.3f",
                     len(selected), len(rows), time.monotonic() - started)
        records, used, cursor = [], 0, after
        captured_status = {}
        try:
            for key, unit, capture, data, target, captured in rows[:limit]:
                payload = self.blobs.read(data)
                size = len(json.dumps(payload).encode())
                if records and used + size > PAGE_BYTES:
                    break
                used += size
                record = {**payload, "manifest_id": key, "analysis_unit_id": unit, "capture_id": capture}
                if record.get("kind") == "analysis_unit":
                    state = self.connection.execute(
                        "SELECT discovery,flow,materialization,error,artifact IS NOT NULL "
                        "FROM graph_manifest_units WHERE id=?",
                        (unit,),
                    ).fetchone()
                    record.update(zip(("discovery", "flow", "materialization", "error", "expandable"), state))
                if "capture_status" in record:
                    resource = (target, record.get("method", "GET"))
                    if resource not in captured_status:
                        captured_status[resource] = self.connection.execute(
                            "WITH documents AS MATERIALIZED (SELECT c.id FROM captures c WHERE "
                            + CAPTURE_SELECTION + ") SELECT EXISTS (SELECT 1 FROM graph_manifest_facts f "
                            "JOIN documents d ON d.id=f.capture_id WHERE f.url=:target "
                            "AND f.rowid<=:facts AND f.kind='resource' "
                            "AND f.captured=1 "
                            "AND f.method=:resource_method)",
                            {**parameters, "target": target, "resource_method": str(resource[1]).upper()},
                        ).fetchone()[0]
                    record["capture_status"] = "captured" if captured_status[resource] else "referenced"
                    record["follow_up"] = {
                        "tool": "find_application_endpoints",
                        "arguments": {
                            "scope": scope,
                            "url": target,
                            "method": record.get("method", "GET"),
                            "detail": "summary",
                        },
                    }
                records.append(record)
                cursor = key
        except TimeoutError:
            if not records:
                raise
            return records, cursor
        if len(records) < len(rows):
            # Output/byte bounds must not consume a matching record that was not returned.
            return records, cursor
        return records, selected[-1] if len(candidates) > 1000 else None

    def coverage(self, capture_id=None, *, scope=None, historical=False, as_of=None, watermark=None):
        from shyhurricane.graph.query import scope_predicate

        matches = scope_predicate(scope) if scope else lambda value: True
        self.connection.create_function("graph_in_scope", 1, matches, deterministic=True)
        watermark = self.watermark() if watermark is None else watermark
        rows = self.connection.execute(
            "WITH documents AS (SELECT c.id,c.url FROM captures c WHERE " + CAPTURE_SELECTION + ") "
            "SELECT u.discovery,u.flow FROM graph_manifest_units u JOIN documents c ON c.id=u.capture_id "
            "WHERE (:capture IS NULL OR u.capture_id=:capture) AND "
            "(graph_in_scope(c.url) OR EXISTS (SELECT 1 FROM graph_unit_contexts member "
            "JOIN documents context ON context.id=member.context_id "
            "WHERE (member.unit_id=u.id OR member.unit_id IN (SELECT parent_id FROM graph_unit_parents "
            "WHERE unit_id=u.id AND rowid<=:parents)) "
            "AND member.rowid<=:units AND graph_in_scope(context.url)))",
            {**watermark, "as_of": as_of, "historical": historical, "capture": capture_id},
        ).fetchall()

        def status(index):
            found = {row[index] for row in rows}
            return next(
                (value for value in ("failed", "blocked", "pending", "partial") if value in found),
                "complete" if rows else "pending",
            )

        return {"discovery": status(0), "flow": status(1), "units": len(rows)}
