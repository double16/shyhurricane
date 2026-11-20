"""Bounded discovery reads over immutable Neo4j inventory generations."""

import logging
import time
from uuid import uuid4

from shyhurricane.graph.inventory_publication import visible_inventory
from shyhurricane.graph.inventory_scope import inventory_filters, scope_clause, scope_parameters
from shyhurricane.graph.performance import count, label, measured, phase, timed
from shyhurricane.graph.shard_store import SHARD_BYTES, encode

logger = logging.getLogger(__name__)

PAGE_BYTES = SHARD_BYTES

TEMPORAL = (
    "(" + visible_inventory() + ") AND ($as_of IS NULL OR g.observed_at<=$as_of) "
    "AND ($historical OR NOT EXISTS { MATCH (newer:GraphInventoryCapture) "
    "WHERE newer.url=g.url AND newer.method=g.method "
    "AND newer.registered_revision<=$revision "
    "AND ($as_of IS NULL OR newer.observed_at<=$as_of) "
    "AND (newer.observed_at>g.observed_at OR "
    "(newer.observed_at=g.observed_at AND newer.id<g.capture_id)) })"
)
CONTEXT = (
    "EXISTS { MATCH (cx:GraphInventoryContext {generation:g.id}) "
    "MATCH (document:GraphInventoryCapture {id:cx.capture_id}) "
    "WHERE document.registered_revision<=$revision "
    "AND ($as_of IS NULL OR document.observed_at<=$as_of) "
    "AND ($historical OR NOT EXISTS { MATCH (newer:GraphInventoryCapture) "
    "WHERE newer.url=document.url AND newer.method=document.method "
    "AND newer.registered_revision<=$revision AND ($as_of IS NULL OR newer.observed_at<=$as_of) "
    "AND (newer.observed_at>document.observed_at OR "
    "(newer.observed_at=document.observed_at AND newer.id<document.id)) }) "
    "AND (" + scope_clause("cx") + ") "
    "AND ($context_url IS NULL OR cx.url=$context_url) }"
)


class InventoryReader:
    def __init__(self, read, shards, *, check=lambda: None, request_id=None):
        self.read = read
        self.shards = shards
        self.check = check
        self.request_id = request_id

    @timed("read_pin_create")
    def watermark(self):
        key = uuid4().hex
        expires = time.time() + 600
        rows = self.read(
            "MATCH (s:GraphState {id:'publication_revision'}) "
            "SET s.pin_lock=coalesce(s.pin_lock,0)+1 "
            "CREATE (p:GraphInventoryReadPin {id:$pin,revision:s.value,expires:$expires}) "
            "RETURN s.value AS revision",
            pin=key, expires=expires, access_mode="WRITE",
        )
        if not rows:
            raise ValueError("Inventory revision state is unavailable")
        return {"revision": rows[0]["revision"], "pin": key, "expires": expires}

    def snapshot(self, watermark):
        if watermark is None:
            return self.watermark()
        if "pin" not in watermark:
            raise ValueError("Inventory continuation has no generation pin; restart the query")
        with phase("read_pin_validate"):
            rows = self.read(
                "MATCH (p:GraphInventoryReadPin {id:$pin}) WHERE p.expires>$now "
                "AND p.revision=$revision RETURN p.id AS id",
                pin=watermark["pin"], revision=watermark["revision"], now=time.time(),
            )
        if not rows:
            raise ValueError("Inventory continuation expired; restart the query")
        return watermark

    @measured("inventory_read", logger)
    def page(self, scope, *, kind=None, kinds=None, role=None, url=None, method=None, capture_id=None,
             context_url=None, exclude_kinds=(), unit_id=None, historical=False, as_of=None, watermark=None, after="", limit=1000):
        label(stage="page", request_id=self.request_id)
        if not 1 <= limit <= 1000:
            raise ValueError("Inventory page size must be between 1 and 1000")
        revision = self.snapshot(watermark)["revision"]
        parameters = {
            **scope_parameters(scope), **inventory_filters(kind, kinds, role, url, method, capture_id, exclude_kinds),
            "context_url": context_url, "unit_id": unit_id, "revision": revision, "historical": historical,
            "as_of": as_of, "after": after, "limit": limit + 1,
        }
        filters = ["f.manifest_id>$after"]
        for field in ("role", "url", "method", "capture_id", "unit_id"):
            if parameters[field] is not None:
                filters.append(f"f.{field}=" + chr(36) + field)
        if parameters["kinds"]:
            filters.append("f.kind=$kinds[0]" if len(parameters["kinds"]) == 1 else "f.kind IN $kinds")
        if parameters["excluded"]:
            filters.append("NOT f.kind IN $excluded")
        filtered = " AND ".join(filters)
        index = "generation,role,manifest_id" if parameters["role"] else (
            "generation,url,manifest_id" if parameters["url"] else (
                "generation,kind,manifest_id" if len(parameters["kinds"]) == 1 else "generation,manifest_id"
            )
        )
        seek = f"USING INDEX f:GraphInventoryFact({index}) WHERE "
        order = ",".join(f"f.{field}" for field in index.split(","))
        direct = (
            "MATCH (sx:GraphInventoryScope) WHERE (" + scope_clause("sx") + ")"
            + (" AND sx.kind IN $kinds" if parameters["kinds"] else "")
            + (" AND NOT sx.kind IN $excluded" if parameters["excluded"] else "")
            + (" AND sx.url=$url" if parameters["url"] else "")
            + (" AND sx.url=$context_url" if context_url else "")
            + " WITH DISTINCT sx.generation AS generation "
            "MATCH (g:GraphInventoryGeneration {id:generation}) WHERE " + TEMPORAL
            + " CALL (g) { MATCH (f:GraphInventoryFact {generation:g.id}) "
            + seek + filtered
            + " AND (" + scope_clause("f") + ")"
            + (" AND f.url=$context_url" if context_url else "")
            + " RETURN f ORDER BY " + order + " LIMIT $limit } RETURN f,g"
        )
        contextual = (
            "MATCH (cx:GraphInventoryContext) WHERE (" + scope_clause("cx") + ") "
            + ("AND cx.url=$context_url " if context_url else "")
            + "MATCH (document:GraphInventoryCapture {id:cx.capture_id}) "
            "WHERE document.registered_revision<=$revision "
            "AND ($as_of IS NULL OR document.observed_at<=$as_of) "
            "AND ($historical OR NOT EXISTS { MATCH (newer:GraphInventoryCapture) "
            "WHERE newer.url=document.url AND newer.method=document.method "
            "AND newer.registered_revision<=$revision AND ($as_of IS NULL OR newer.observed_at<=$as_of) "
            "AND (newer.observed_at>document.observed_at OR "
            "(newer.observed_at=document.observed_at AND newer.id<document.id)) }) "
            "MATCH (g:GraphInventoryGeneration {id:cx.generation}) WHERE " + TEMPORAL
            + " WITH DISTINCT g CALL (g) { MATCH (f:GraphInventoryFact {generation:g.id}) "
            + seek + filtered
            + " RETURN f ORDER BY " + order + " LIMIT $limit } RETURN f,g"
        )
        fact_context = (
            "MATCH (mx:GraphInventoryMembership) WHERE (" + scope_clause("mx") + ") "
            + ("AND mx.kind IN $kinds " if parameters["kinds"] else "")
            + ("AND mx.url=$context_url " if context_url else "")
            + "MATCH (document:GraphInventoryCapture {id:mx.capture_id}) "
            "WHERE document.registered_revision<=$revision "
            "AND ($as_of IS NULL OR document.observed_at<=$as_of) "
            "AND ($historical OR NOT EXISTS { MATCH (newer:GraphInventoryCapture) "
            "WHERE newer.url=document.url AND newer.method=document.method "
            "AND newer.registered_revision<=$revision AND ($as_of IS NULL OR newer.observed_at<=$as_of) "
            "AND (newer.observed_at>document.observed_at OR "
            "(newer.observed_at=document.observed_at AND newer.id<document.id)) }) "
            "MATCH (g:GraphInventoryGeneration {id:mx.generation}) WHERE " + TEMPORAL
            + " WITH DISTINCT g,document CALL (g,document) { "
            "MATCH (f:GraphInventoryFact {generation:g.id}) "
            + seek + filtered
            + " AND EXISTS { MATCH (f)-[:IN_DOCUMENT]->(document) } "
            "RETURN f ORDER BY " + order + " LIMIT $limit } RETURN f,g"
        )
        candidates = direct if kind == "resource" else (
            "CALL () { " + direct + " UNION " + contextual + " UNION " + fact_context + " } RETURN f,g"
        )
        with phase("inventory_query"):
            rows = self.read(
                "CALL () { " + candidates + " } "
                "WITH f,g ORDER BY f.manifest_id LIMIT $limit "
                "CALL (g) { OPTIONAL MATCH (s:GraphInventoryStatus {generation:g.id}) "
                "WHERE s.published_revision<=$revision RETURN s ORDER BY s.published_revision DESC LIMIT 1 } "
                "RETURN f.manifest_id AS manifest_id,f.generation AS generation,f.unit_id AS unit_id,f.capture_id AS capture_id,"
                "f.oversized AS oversized,f.logical_id AS logical_id,f.kind AS kind,f.url AS url,f.method AS method,"
                "f.shard AS shard,f.position AS position,properties(s) AS status,g.discovery AS discovery,g.flow AS flow,"
                "g.artifact AS artifact,g.error AS error,g.materialization AS materialization,"
                "EXISTS { MATCH (captured:GraphInventoryCapture {url:f.url,method:f.method}) "
                "WHERE captured.registered_revision<=$revision "
                "AND ($as_of IS NULL OR captured.observed_at<=$as_of) } AS captured "
                "ORDER BY f.manifest_id LIMIT $limit", **parameters,
            )
        result, used, seen_shards = [], 0, set()
        cursor = after
        for row in rows[:limit]:
            try:
                self.check()
                reference = row["shard"]
                if row["oversized"]:
                    count("oversized_records")
                    payload = {"id": row["logical_id"], "kind": row["kind"], "manifest_id": row["manifest_id"],
                               "url": row["url"], "method": row["method"], "artifact": reference, "oversized": True}
                else:
                    if reference not in seen_shards:
                        seen_shards.add(reference)
                        count("shards_read")
                    payload = self.shards.read_record(reference, row["position"], limit=SHARD_BYTES)
                    if payload.get("manifest_id") != row["manifest_id"]:
                        raise ValueError("Inventory shard identity mismatch")
                size = len(encode(payload))
                if result and used + size > PAGE_BYTES:
                    return result, cursor
                if size > PAGE_BYTES:
                    payload = {"id": payload.get("id", row["manifest_id"]), "kind": payload["kind"],
                               "manifest_id": row["manifest_id"], "artifact": reference, "oversized": True}
                used += size
                payload = {key: value for key, value in payload.items() if key != "_context_ids"}
                record = {**payload, "analysis_unit_id": row["unit_id"], "capture_id": row["capture_id"]}
                if record["kind"] == "resource":
                    record["capture_status"] = "captured" if row["captured"] else "referenced"
                    record["follow_up"] = {
                        "tool": "find_application_endpoints",
                        "arguments": {"scope": scope, "url": record["url"],
                                      "method": record.get("method", "GET"), "detail": "summary"},
                    }
                if record["kind"] == "analysis_unit":
                    status = row["status"] or {}
                    record.update(
                        discovery=status.get("discovery", row["discovery"]), flow=status.get("flow", row["flow"]),
                        expandable=bool(row["artifact"]), error=status.get("error", row["error"]) or "",
                        materialization=status.get("materialization", row["materialization"]) or "deferred",
                    )
                result.append(record)
                count("returned_records")
                cursor = row["manifest_id"]
            except TimeoutError:
                label(partial=True)
                if result:
                    return result, cursor
                raise
        return result, cursor if len(rows) > limit else None

    def lookup_unit(self, scope, unit, capture):
        snapshot = self.snapshot(None)
        rows = self.read(
            "MATCH (g:GraphInventoryGeneration {unit_id:$unit,capture_id:$capture}) WHERE " + TEMPORAL
            + " AND ((" + scope_clause("g") + ") OR " + CONTEXT + ") "
            "RETURN g.artifact AS artifact,g.id AS generation,g.source_path AS source_path LIMIT 1",
            **scope_parameters(scope), unit=unit, capture=capture, revision=snapshot["revision"],
            historical=False, as_of=None, context_url=None,
        )
        return rows[0] if rows else None

    def coverage(self, capture_id=None, *, scope=None, historical=False, as_of=None, watermark=None):
        parameters = {"capture_id": capture_id, "historical": historical, "as_of": as_of,
                      "revision": self.snapshot(watermark)["revision"], "context_url": None}
        scoped = ""
        if scope:
            parameters.update(scope_parameters(scope))
            scoped = " AND ((" + scope_clause("g") + ") OR " + CONTEXT + ")"
        rows = self.read(
            "MATCH (g:GraphInventoryGeneration) WHERE " + TEMPORAL.replace(
                "(" + visible_inventory() + ")", "((" + visible_inventory() + ") OR g.state='staging')", 1)
            + " AND ($capture_id IS NULL OR g.capture_id=$capture_id)" + scoped
            + " CALL (g) { OPTIONAL MATCH (s:GraphInventoryStatus {generation:g.id}) "
            "WHERE s.published_revision<=$revision RETURN s ORDER BY s.published_revision DESC LIMIT 1 } "
            "RETURN g.unit_id AS unit_id,coalesce(s.discovery,g.discovery) AS discovery,"
            "coalesce(s.flow,g.flow) AS flow",
            **parameters,
        )
        def status(field):
            found = {row[field] for row in rows}
            return next((value for value in ("failed", "blocked", "pending", "partial") if value in found),
                        "complete" if rows else "pending")
        return {"discovery": status("discovery"), "flow": status("flow"),
                "units": len({row["unit_id"] for row in rows})}
